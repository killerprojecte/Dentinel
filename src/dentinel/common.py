"""Small streaming/atomic filesystem primitives shared by the pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

CHUNK = 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@contextmanager
def atomic_file(path: Path, *, replace: bool = False) -> Iterator[BinaryIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not replace and path.exists():
        raise FileExistsError(f"Refusing to overwrite {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        if not replace and path.exists():
            raise FileExistsError(f"Refusing to overwrite {path}")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, value: object, *, replace: bool = False) -> None:
    with atomic_file(path, replace=replace) as stream:
        stream.write(json_bytes(value) + b"\n")


def load_json(path: Path) -> dict:
    if path.stat().st_size > 16 * CHUNK:
        raise ValueError(f"JSON metadata too large: {path}")
    with path.open("rb") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def copy_atomic(source: Path, destination: Path) -> None:
    with source.open("rb") as src, atomic_file(destination) as dst:
        shutil.copyfileobj(src, dst, CHUNK)
