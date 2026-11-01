"""Download and verify the pinned, standalone crane executable (no Docker needed)."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CRANE_VERSION = "v0.20.6"
_RELEASE_ROOT = (
    "https://github.com/google/go-containerregistry/releases/download/" + CRANE_VERSION
)
_ASSETS = {
    "Windows": (
        "go-containerregistry_Windows_x86_64.tar.gz",
        "399491efa1d88d1ee18c6642d025aa0c67a49bfe8297033fb485b1272ad70c9d",
        "crane.exe",
    ),
    "Linux": (
        "go-containerregistry_Linux_x86_64.tar.gz",
        "c1d593d01551f2c9a3df5ca0a0be4385a839bd9b86d4a76e18d7b17d16559127",
        "crane",
    ),
}
_ATTEMPTS = 3
_NETWORK_TIMEOUT = 30
_DOWNLOAD_TIMEOUT = 120
_MAX_BYTES = 128 * 1024 * 1024


def _regular(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _atomic_bytes(path: Path, content: bytes, *, executable: bool = False) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".crane-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if executable:
            os.chmod(temporary, 0o755)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _download(url: str, archive: Path, expected_hash: str) -> None:
    for attempt in range(_ATTEMPTS):
        fd, temporary = tempfile.mkstemp(prefix=".download-", dir=archive.parent)
        try:
            hasher = hashlib.sha256()
            size = 0
            deadline = time.monotonic() + _DOWNLOAD_TIMEOUT
            request = urllib.request.Request(url, headers={"User-Agent": "dentinel/1"})
            with os.fdopen(fd, "wb") as output:
                fd = -1
                with urllib.request.urlopen(request, timeout=_NETWORK_TIMEOUT) as response:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if time.monotonic() > deadline:
                            raise TimeoutError("crane download exceeded its time limit")
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > _MAX_BYTES:
                            raise RuntimeError("crane release archive exceeds size limit")
                        output.write(chunk)
                        hasher.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            if hasher.hexdigest() != expected_hash:
                raise RuntimeError("crane release archive SHA256 verification failed")
            os.replace(temporary, archive)
            return
        except (OSError, urllib.error.URLError) as error:
            if attempt + 1 == _ATTEMPTS:
                raise RuntimeError("Unable to download the verified crane release") from error
            time.sleep(0.25 * (attempt + 1))
        finally:
            if fd != -1:
                os.close(fd)
            Path(temporary).unlink(missing_ok=True)


def _executable_from_archive(archive: Path, name: str) -> bytes:
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            selected = None
            for member in bundle:
                if member.name not in (name, "./" + name):
                    continue
                if selected is not None or not member.isfile():
                    raise RuntimeError("crane archive has an unsafe or duplicate executable")
                if member.size <= 0 or member.size > _MAX_BYTES:
                    raise RuntimeError("crane executable has an invalid size")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise RuntimeError("Unable to read crane executable from release")
                with stream:
                    selected = stream.read(_MAX_BYTES + 1)
                if len(selected) != member.size:
                    raise RuntimeError("crane executable in release is truncated")
            if selected is None:
                raise RuntimeError("crane executable is missing from release archive")
            return selected
    except (tarfile.TarError, EOFError) as error:
        raise RuntimeError("Invalid crane release archive") from error


def ensure_crane(cache: Path) -> Path:
    """Return a verified v0.20.6 binary without changing PATH or executing a shell.

    Both the retained release archive and the executable are checked on every use.
    The executable hash is also checked against the verified archive, so editing the
    cache metadata cannot make an unrelated binary trusted.
    """
    system = platform.system()
    machine = platform.machine().lower()
    if system not in _ASSETS or machine not in {"amd64", "x86_64"}:
        raise RuntimeError("Pinned crane builds support only Windows/Linux x86_64")
    asset, archive_hash, name = _ASSETS[system]
    directory = Path(cache) / "crane" / CRANE_VERSION / system.lower()
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / asset
    executable = directory / name
    metadata = directory / "verified.json"

    if not _regular(archive) or _sha256(archive) != archive_hash:
        _download(f"{_RELEASE_ROOT}/{asset}", archive, archive_hash)
    # Revalidate even a just-downloaded archive before it is opened or extracted.
    if not _regular(archive) or _sha256(archive) != archive_hash:
        raise RuntimeError("Cached crane archive SHA256 verification failed")
    binary = _executable_from_archive(archive, name)
    binary_hash = hashlib.sha256(binary).hexdigest()
    expected_metadata = {
        "version": CRANE_VERSION,
        "archive_sha256": archive_hash,
        "executable_sha256": binary_hash,
    }
    try:
        recorded = (
            json.loads(metadata.read_text(encoding="utf-8"))
            if _regular(metadata)
            else None
        )
    except (OSError, ValueError):
        recorded = None
    if not _regular(executable) or _sha256(executable) != binary_hash:
        _atomic_bytes(executable, binary, executable=True)
    elif system != "Windows" and not os.access(executable, os.X_OK):
        os.chmod(executable, 0o755)
    if recorded != expected_metadata:
        _atomic_bytes(metadata, json.dumps(expected_metadata, sort_keys=True).encode("utf-8"))
    return executable
