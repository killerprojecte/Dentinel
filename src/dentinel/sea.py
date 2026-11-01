"""Restricted ELF64 Node SEA reader. No code execution or fixed file offsets."""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = 0x143DA20
MAX_SOURCE = 64 * 1024 * 1024


@dataclass(frozen=True)
class SeaSource:
    note_offset: int
    blob_offset: int
    blob_size: int
    source_offset: int
    source_size: int
    code_path: str
    flags: int
    code: bytes


def _span(data, offset: int, size: int, end: int | None = None) -> None:
    end = len(data) if end is None else min(len(data), end)
    if offset < 0 or size < 0 or offset > end or size > end - offset:
        raise ValueError("Truncated or out-of-bounds ELF/SEA data")


def _align4(value: int) -> int:
    return (value + 3) & ~3


def read_source(data) -> SeaSource:
    """Support the verified 9-byte SEA header, plain source, optional assets/argv.

    PT_NOTE is the runtime source of truth. Postject can leave overlapping or
    stale section headers, so SHT_NOTE is deliberately not used for discovery.
    Unknown layouts (including added header fields) fail bounds/format checks.
    """
    _span(data, 0, 64)
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[2] != 62:
        raise ValueError("Patcher requires little-endian ELF64 x86-64")
    phoff, phsize, count = header[5], header[9], header[10]
    if phsize != 56 or not 0 < count <= 4096:
        raise ValueError("Unsupported ELF program-header table")
    _span(data, phoff, phsize * count)
    notes: dict[int, tuple[int, int]] = {}
    for index in range(count):
        kind, _, offset, _, _, size, _, alignment = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        if kind != 4:
            continue
        if alignment not in (0, 1, 4, 8):
            raise ValueError("Unsupported PT_NOTE alignment")
        _span(data, offset, size)
        end, cursor = offset + size, offset
        note_count = 0
        while cursor < end:
            if end - cursor < 12:
                if any(data[cursor:end]):
                    raise ValueError("Invalid trailing ELF note bytes")
                break
            namesz, descsz, _ = struct.unpack_from("<III", data, cursor)
            if namesz == descsz == 0:
                if any(data[cursor:end]):
                    raise ValueError("Unexpected empty ELF note")
                break
            name_at = cursor + 12
            _span(data, name_at, namesz, end)
            desc_at = _align4(name_at + namesz)
            _span(data, desc_at, descsz, end)
            name = bytes(data[name_at:name_at + namesz]).rstrip(b"\0")
            if name == b"NODE_SEA_BLOB":
                notes[desc_at] = (cursor, descsz)
            following = _align4(desc_at + descsz)
            if following <= cursor or following > end:
                raise ValueError("Invalid ELF note bounds/alignment")
            cursor = following
            note_count += 1
            if note_count > 10000:
                raise ValueError("Too many ELF notes")
    if len(notes) != 1:
        raise ValueError("Expected exactly one NODE_SEA_BLOB in PT_NOTE")
    blob_at, (note_at, blob_size) = next(iter(notes.items()))
    end = blob_at + blob_size
    _span(data, blob_at, 9, end)
    magic, flags = struct.unpack_from("<II", data, blob_at)
    if magic != MAGIC or flags & ~0x1F:
        raise ValueError("Unknown SEA magic or flags")
    if flags & (2 | 4):
        raise ValueError("SEA snapshot/code-cache patching is unsupported")
    if data[blob_at + 8] not in (0, 1, 2):
        raise ValueError("Unknown SEA exec-argv extension")
    cursor = blob_at + 9

    def string(limit: int) -> tuple[int, int]:
        nonlocal cursor
        _span(data, cursor, 8, end)
        length = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        if length > limit:
            raise ValueError("SEA string exceeds supported size")
        _span(data, cursor, length, end)
        start = cursor
        cursor += length
        return start, length

    path_at, path_size = string(4096)
    path_raw = bytes(data[path_at:path_at + path_size])
    try:
        path = path_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Invalid SEA main path") from error
    if not path or "\0" in path or not path.endswith((".js", ".cjs", ".mjs")):
        raise ValueError("Unsupported SEA main path/header layout")
    source_at, source_size = string(MAX_SOURCE)
    code = bytes(data[source_at:source_at + source_size])
    if not code or b"\0" in code:
        raise ValueError("SEA main resource is not plain JavaScript")
    try:
        code.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("SEA source is not UTF-8") from error
    if flags & 8:
        _span(data, cursor, 8, end)
        assets = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        if assets > 10000:
            raise ValueError("Too many SEA assets")
        names: set[bytes] = set()
        for _ in range(assets):
            key_at, key_size = string(4096)
            key = bytes(data[key_at:key_at + key_size])
            if key in names:
                raise ValueError("Duplicate SEA asset key")
            names.add(key)
            string(256 * 1024 * 1024)
    if flags & 16:
        _span(data, cursor, 8, end)
        argc = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        if argc > 1024:
            raise ValueError("Too many SEA exec arguments")
        for _ in range(argc):
            string(65536)
    if cursor != end:
        raise ValueError("Unexpected SEA trailing bytes/header version")
    return SeaSource(note_at, blob_at, blob_size, source_at, source_size, path, flags, code)
