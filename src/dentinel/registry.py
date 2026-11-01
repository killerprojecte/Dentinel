"""Pinned linux/amd64 registry operations through standalone crane."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

DEFAULT_SOURCE = "ghcr.io/altcha-org/sentinel:latest"
PLATFORM = "linux/amd64"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\Z")
_TARGET = re.compile(r"ghcr\.io/[a-z0-9]+(?:-[a-z0-9]+)*/dentinel:([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})\Z")
_IMAGE_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_ATTEMPTS = 3
_COMMAND_TIMEOUT = 120
_TRANSFER_TIMEOUT = 600
_MAX_JSON_BYTES = 16 * 1024 * 1024


def _safe_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in value)
    ):
        raise ValueError(f"Invalid {label}")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError("Expected a lowercase sha256 digest")
    return value


def _reference(value: Any) -> tuple[str, str | None]:
    """Validate a reference and return its fully qualified, tagless repository."""
    value = _safe_text(value, "image reference")
    if len(value) > 512 or value.count("@") > 1:
        raise ValueError("Invalid image reference")
    image, separator, digest = value.partition("@")
    pinned_digest = _digest(digest) if separator else None
    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    if last_colon > last_slash:
        image, tag = image[:last_colon], image[last_colon + 1 :]
        if _TAG.fullmatch(tag) is None:
            raise ValueError("Invalid image tag")
    parts = image.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host, path = parts[0], parts[1:]
    else:
        host, path = "index.docker.io", parts
    if _HOST.fullmatch(host) is None or any(not _COMPONENT.fullmatch(p) for p in path):
        raise ValueError("Invalid image repository")
    if ":" in host and not 0 < int(host.rsplit(":", 1)[1]) <= 65535:
        raise ValueError("Invalid registry port")
    if host in {"docker.io", "index.docker.io"}:
        host = "index.docker.io"
        if len(path) == 1:
            path.insert(0, "library")
    return host + "/" + "/".join(path), pinned_digest


def validate_target(target: str) -> str:
    """Only permit ghcr.io/<owner>/dentinel:<tag> destinations."""
    _safe_text(target, "publish target")
    if not _TARGET.fullmatch(target):
        raise ValueError("Publish target must be ghcr.io/<owner>/dentinel:<tag>")
    return target


def _run(
    crane: Path,
    arguments: list[str],
    *,
    input_text: str | None = None,
    timeout: int = _COMMAND_TIMEOUT,
    attempts: int = _ATTEMPTS,
) -> str:
    # Do not forward the raw token in child environments either. Crane uses its
    # normal auth configuration after an explicit password-stdin login.
    environment = {key: value for key, value in os.environ.items() if key != "GHCR_TOKEN"}
    for attempt in range(attempts):
        try:
            result = subprocess.run(
                [str(crane), *arguments],
                input=input_text,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=timeout,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            # Never propagate subprocess output, inputs, or a credential-bearing
            # TimeoutExpired / CalledProcessError through an exception chain.
            if attempt + 1 == attempts:
                raise RuntimeError(f"crane {arguments[0]} could not complete") from None
        else:
            if result.returncode == 0:
                return result.stdout
            if attempt + 1 == attempts:
                raise RuntimeError(f"crane {arguments[0]} failed (exit {result.returncode})")
        time.sleep(0.25 * (attempt + 1))
    raise RuntimeError("crane did not complete")


def _json_object(raw: str | bytes, label: str) -> dict:
    if len(raw) > _MAX_JSON_BYTES:
        raise RuntimeError(f"{label} exceeds JSON size limit")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RuntimeError(f"Invalid {label} JSON") from None
    if not isinstance(document, dict):
        raise RuntimeError(f"Invalid {label}: expected a JSON object")
    return document


def _manifest(crane: Path, pinned: str) -> dict:
    return _json_object(_run(crane, ["manifest", pinned]), "image manifest")


def _require_image(manifest: dict) -> None:
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") not in _IMAGE_TYPES
        or "manifests" in manifest
        or not isinstance(manifest.get("config"), dict)
        or not isinstance(manifest.get("layers"), list)
        or manifest.get("artifactType")
    ):
        raise RuntimeError("Expected a single container image manifest")


def resolve(crane: Path, source: str = DEFAULT_SOURCE) -> dict:
    """Lock the source first, then select exactly one linux/amd64 image.

    No platform is supplied to `digest` or the initial `manifest`: crane v0.20.6
    deliberately returns the *index* in this mode. Every subsequent request uses
    the immutable digest, never the possibly moving source tag.
    """
    repository, supplied_digest = _reference(source)
    if supplied_digest is None:
        original_digest = _digest(_run(crane, ["digest", source]).strip())
    else:
        original_digest = supplied_digest
    manifest = _manifest(crane, f"{repository}@{original_digest}")
    image_digest = original_digest
    is_index = manifest.get("mediaType") in _INDEX_TYPES
    if is_index:
        if manifest.get("schemaVersion") != 2 or not isinstance(manifest.get("manifests"), list):
            raise RuntimeError("Invalid source image index")
        candidates = []
        for descriptor in manifest["manifests"]:
            if not isinstance(descriptor, dict):
                raise RuntimeError("Invalid manifest descriptor in source index")
            annotations = descriptor.get("annotations", {})
            if isinstance(annotations, dict) and annotations.get("vnd.docker.reference.type") == "attestation-manifest":
                continue
            platform = descriptor.get("platform")
            if not isinstance(platform, dict):
                continue
            if platform.get("os") != "linux" or platform.get("architecture") != "amd64":
                continue
            if descriptor.get("mediaType") not in _IMAGE_TYPES or descriptor.get("artifactType"):
                continue
            candidates.append(descriptor)
        if len(candidates) != 1:
            raise RuntimeError("Source index must contain exactly one linux/amd64 image")
        image_digest = _digest(candidates[0].get("digest"))
        manifest = _manifest(crane, f"{repository}@{image_digest}")
    _require_image(manifest)
    pinned = f"{repository}@{image_digest}"
    config = _json_object(
        _run(crane, ["config", "--platform", PLATFORM, pinned]), "image config"
    )
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise RuntimeError("Selected image config is not linux/amd64")
    lock = {"source": source, "pinned": pinned, "digest": image_digest, "platform": PLATFORM}
    if is_index:
        lock["index_digest"] = original_digest
    return lock


def _locked_reference(lock: dict) -> tuple[str, str]:
    if not isinstance(lock, dict) or lock.get("platform") != PLATFORM:
        raise ValueError("Image lock must select linux/amd64")
    digest = _digest(lock.get("digest"))
    repository, pinned_digest = _reference(lock.get("pinned"))
    if pinned_digest != digest or lock["pinned"] != f"{repository}@{digest}":
        raise ValueError("Image lock must contain a matching immutable image reference")
    return lock["pinned"], digest


def _read_regular_json(path: Path, label: str) -> dict:
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > _MAX_JSON_BYTES:
        raise RuntimeError(f"Invalid {label} file")
    return _json_object(path.read_bytes(), label)


def _checked_blob(layout: Path, descriptor: Any) -> Path:
    if not isinstance(descriptor, dict):
        raise RuntimeError("Invalid OCI blob descriptor")
    digest = _digest(descriptor.get("digest"))
    size = descriptor.get("size")
    if type(size) is not int or size < 0:
        raise RuntimeError("Invalid OCI blob size")
    path = layout / "blobs" / "sha256" / digest.split(":", 1)[1]
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != size:
        raise RuntimeError("Missing, unsafe, or truncated OCI blob")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    if "sha256:" + hasher.hexdigest() != digest:
        raise RuntimeError("OCI blob digest verification failed")
    return path


def _validate_layout(layout: Path, expected_digest: str | None = None) -> str:
    if not layout.is_dir() or layout.is_symlink():
        raise RuntimeError("OCI layout must be a regular directory")
    for directory in (layout / "blobs", layout / "blobs" / "sha256"):
        if not directory.is_dir() or directory.is_symlink():
            raise RuntimeError("Invalid OCI blob directory")
    metadata = _read_regular_json(layout / "oci-layout", "OCI layout")
    index = _read_regular_json(layout / "index.json", "OCI index")
    manifests = index.get("manifests")
    if metadata.get("imageLayoutVersion") != "1.0.0" or index.get("schemaVersion") != 2:
        raise RuntimeError("Unsupported OCI layout version")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise RuntimeError("OCI layout must contain exactly one image")
    descriptor = manifests[0]
    if not isinstance(descriptor, dict) or descriptor.get("mediaType") not in _IMAGE_TYPES:
        raise RuntimeError("OCI layout must contain a single image manifest")
    digest = _digest(descriptor.get("digest"))
    if expected_digest is not None and digest != expected_digest:
        raise RuntimeError("Downloaded image does not match its lock")
    manifest = _read_regular_json(_checked_blob(layout, descriptor), "OCI manifest")
    _require_image(manifest)
    config = _read_regular_json(_checked_blob(layout, manifest["config"]), "OCI config")
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise RuntimeError("OCI image is not linux/amd64")
    for layer in manifest["layers"]:
        _checked_blob(layout, layer)
    return digest


def pull(crane: Path, lock: dict, layout: Path) -> None:
    """Download to an isolated directory and atomically install a complete layout."""
    pinned, digest = _locked_reference(lock)
    layout = Path(layout).absolute()
    if layout.exists() or layout.is_symlink():
        raise FileExistsError(f"Refusing to overwrite existing OCI layout: {layout}")
    layout.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(_ATTEMPTS):
        temporary = Path(tempfile.mkdtemp(prefix=".dentinel-pull-", dir=layout.parent))
        try:
            _run(
                crane,
                ["pull", "--platform", PLATFORM, "--format", "oci", pinned, str(temporary)],
                timeout=_TRANSFER_TIMEOUT,
                attempts=1,
            )
            _validate_layout(temporary, digest)
            if layout.exists() or layout.is_symlink():
                raise FileExistsError(f"Refusing to overwrite existing OCI layout: {layout}")
            # rename, not replace: no existing destination is intentionally removed.
            temporary.rename(layout)
            return
        except FileExistsError:
            raise
        except (OSError, RuntimeError, ValueError):
            if attempt + 1 == _ATTEMPTS:
                raise RuntimeError("Unable to download a complete, verified OCI image") from None
            time.sleep(0.25 * (attempt + 1))
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)


def publish(crane: Path, layout: Path, target: str) -> str:
    """Push one linux/amd64 OCI image and return its verified digest reference."""
    validate_target(target)
    layout = Path(layout).absolute()
    digest = _validate_layout(layout)
    token = os.environ.get("GHCR_TOKEN", "")
    if token:
        username = _safe_text(os.environ.get("GHCR_USERNAME", ""), "GHCR username")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", username):
            raise ValueError("Invalid GHCR username")
        if any(ord(char) < 32 or ord(char) == 127 for char in token):
            raise ValueError("Invalid GHCR token")
        _run(
            crane,
            ["auth", "login", "ghcr.io", "--username", username, "--password-stdin"],
            input_text=token + "\n",
        )
    output = _run(crane, ["push", str(layout), target], timeout=_TRANSFER_TIMEOUT).strip()
    repository, returned_digest = _reference(output)
    expected_repository = target.rsplit(":", 1)[0]
    expected = f"{expected_repository}@{digest}"
    if repository != expected_repository or returned_digest != digest or output != expected:
        raise RuntimeError("crane push returned an unexpected image digest reference")
    return expected
