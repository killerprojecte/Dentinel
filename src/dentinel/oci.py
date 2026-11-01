"""Restricted, streaming OCI reader and deterministic single-file image repacker.

Linux archive metadata stays in metadata objects: no Linux rootfs is materialized
on the host. Only explicitly selected regular files can be written to host paths.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import re
import shutil
import struct
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator

from .common import CHUNK, atomic_file, json_bytes, load_json, sha256, write_json

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
BINARY_PATH = "sentinel/server/altcha-sentinel"
START_PATH = "sentinel/server/start.sh"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_LAYER_BYTES = 16 * 1024**3
MAX_FILE_BYTES = 4 * 1024**3


def archive_path(name: str) -> str:
    """Normalize ./ only; never normalize away traversal or Windows aliases."""
    if not isinstance(name, str) or not name or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError(f"Unsafe archive path: {name!r}")
    if name.startswith("/") or ".." in name.split("/"):
        raise ValueError(f"Unsafe archive path: {name!r}")
    clean = "/".join(part for part in name.split("/") if part not in ("", "."))
    return clean


def target_path(name: str) -> str:
    name = archive_path(name.lstrip("/"))
    if not name or any(part.startswith(".wh.") for part in name.split("/")):
        raise ValueError("Invalid binary path")
    return name


def descriptor(path: Path, media_type: str) -> dict:
    return {"mediaType": media_type, "digest": "sha256:" + sha256(path), "size": path.stat().st_size}


def blob_path(root: Path, digest: str) -> Path:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError(f"Unsupported or invalid digest: {digest!r}")
    path = root / "blobs" / "sha256" / digest.split(":", 1)[1]
    if any(p.is_symlink() for p in (root, root / "blobs", path.parent, path)):
        raise ValueError("Symlinks are not allowed in OCI blob paths")
    return path


def check_blob(root: Path, desc: dict, *, checksum: bool = True) -> Path:
    path = blob_path(root, desc["digest"])
    if not path.is_file() or type(desc.get("size")) is not int or path.stat().st_size != desc["size"]:
        raise ValueError(f"Missing blob or incorrect size: {desc['digest']}")
    if checksum and "sha256:" + sha256(path) != desc["digest"]:
        raise ValueError(f"Corrupt blob: {desc['digest']}")
    return path


def put_blob(root: Path, data: bytes, media_type: str) -> dict:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    path = blob_path(root, digest)
    if path.exists():
        check_blob(root, {"digest": digest, "size": len(data)})
    else:
        with atomic_file(path) as stream:
            stream.write(data)
    return {"mediaType": media_type, "digest": digest, "size": len(data)}


class _HashedReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size=-1):
        if size < 0:
            raise ValueError("Unbounded layer reads are prohibited")
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > MAX_LAYER_BYTES:
            raise ValueError("Uncompressed layer exceeds size limit")
        self.digest.update(data)
        return data


@dataclass
class FileRecord:
    layer: int
    name: str
    info: tarfile.TarInfo

    def metadata(self) -> dict:
        return {
            "path": self.name, "size": self.info.size, "uid": self.info.uid,
            "gid": self.info.gid, "mode": self.info.mode,
            "uname": self.info.uname, "gname": self.info.gname,
            "pax_headers": {k: v for k, v in self.info.pax_headers.items()
                            if k.startswith("SCHILY.xattr.")},
        }


class Image:
    def __init__(self, root: Path):
        self.root = Path(root)
        if self.root.is_symlink() or (self.root / "index.json").is_symlink():
            raise ValueError("Symlinked layouts are unsupported")
        if load_json(self.root / "oci-layout") != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("Unsupported OCI layout version")
        index = load_json(self.root / "index.json")
        if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
            raise ValueError("Expected exactly one selected image in OCI layout")
        self.desc = index["manifests"][0]
        if self.desc.get("mediaType") not in (OCI_MANIFEST, DOCKER_MANIFEST):
            raise ValueError("OCI layout must contain an image, not an index")
        self.manifest = load_json(check_blob(self.root, self.desc))
        if self.manifest.get("schemaVersion") != 2:
            raise ValueError("Unsupported image schema")
        self.config = load_json(check_blob(self.root, self.manifest["config"]))
        if self.config.get("architecture") != "amd64" or self.config.get("os") != "linux":
            raise ValueError("Only linux/amd64 images are supported")
        self.layers = self.manifest["layers"]
        rootfs = self.config.get("rootfs", {})
        if rootfs.get("type") != "layers" or len(rootfs.get("diff_ids", [])) != len(self.layers):
            raise ValueError("Invalid rootfs layer metadata")
        for diff_id in rootfs["diff_ids"]:
            if not DIGEST.fullmatch(diff_id):
                raise ValueError("Invalid uncompressed layer digest")
        self._verified: set[str] = set()

    @property
    def digest(self) -> str:
        return self.desc["digest"]

    def validate(self) -> None:
        for layer in self.layers:
            check_blob(self.root, layer)
            self._verified.add(layer["digest"])

    @contextmanager
    def layer(self, index: int, *, verify_diff: bool = True) -> Iterator[tarfile.TarFile]:
        desc = self.layers[index]
        path = check_blob(self.root, desc, checksum=desc["digest"] not in self._verified)
        self._verified.add(desc["digest"])
        media = desc.get("mediaType", "")
        if media not in (
            OCI_LAYER, "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "application/vnd.docker.image.rootfs.diff.tar",
        ):
            raise ValueError(f"Unsupported layer compression/mediaType: {media}")
        with path.open("rb") as raw:
            stream = gzip.GzipFile(fileobj=raw, mode="rb") if media.endswith(("+gzip", ".gzip")) else raw
            try:
                reader = _HashedReader(stream)
                with tarfile.open(fileobj=reader, mode="r|") as archive:
                    yield archive
                # Tar parsers stop at end markers, but diff_id covers padding too.
                while reader.read(CHUNK):
                    pass
                if verify_diff and "sha256:" + reader.digest.hexdigest() != self.config["rootfs"]["diff_ids"][index]:
                    raise ValueError(f"Incorrect diff_id for layer {index}")
            finally:
                if stream is not raw:
                    stream.close()

    def find(self, names: list[str]) -> dict[str, FileRecord]:
        """Apply relevant nodes; whiteouts precede same-layer additions."""
        targets = [target_path(name) for name in names]
        relevant = {str(p) for name in targets for p in (PurePosixPath(name), *PurePosixPath(name).parents) if str(p) != "."}
        nodes: dict[str, FileRecord] = {}
        for layer_index in range(len(self.layers)):
            entries: dict[str, tarfile.TarInfo] = {}
            removed: list[tuple[str, bool]] = []
            seen: set[str] = set()
            with self.layer(layer_index) as archive:
                for info in archive:
                    name = archive_path(info.name)
                    if not name:
                        if not info.isdir():
                            raise ValueError("Non-directory archive root")
                        continue
                    if name in seen:
                        raise ValueError(f"Duplicate layer entry: {name}")
                    seen.add(name)
                    if len(seen) > 1_000_000:
                        raise ValueError("Too many layer entries")
                    parent, _, filename = name.rpartition("/")
                    if filename.startswith(".wh."):
                        if not info.isfile() or info.size != 0 or filename == ".wh.":
                            raise ValueError(f"Invalid whiteout: {name}")
                        if filename == ".wh..wh..opq":
                            removed.append((parent, True))
                        else:
                            removed.append(((parent + "/" if parent else "") + filename[4:], False))
                    elif name in relevant:
                        entries[name] = info
            for deleted, opaque in removed:
                for name in list(nodes):
                    if not deleted or name.startswith(deleted + "/") or (not opaque and name == deleted):
                        del nodes[name]
            for name, info in sorted(entries.items(), key=lambda pair: pair[0].count("/")):
                old = nodes.get(name)
                if not info.isdir() or (old is not None and not old.info.isdir()):
                    for child in list(nodes):
                        if child.startswith(name + "/"):
                            del nodes[child]
                nodes[name] = FileRecord(layer_index, name, info)
        result: dict[str, FileRecord] = {}
        for name in targets:
            for parent in PurePosixPath(name).parents:
                node = nodes.get(str(parent))
                if node is not None and not node.info.isdir():
                    raise ValueError(f"Required path has non-directory ancestor: /{name}")
            record = nodes.get(name)
            if record is None:
                raise ValueError(f"Required file missing after applying layers: /{name}")
            if not record.info.isfile() or record.info.issparse():
                raise ValueError(f"Required path is not an ordinary file: /{name}")
            if record.info.size <= 0 or record.info.size > MAX_FILE_BYTES:
                raise ValueError(f"Invalid required file size: /{name}")
            result[name] = record
        return result

    def extract(self, record: FileRecord, destination: Path) -> dict:
        with atomic_file(destination) as output:
            found = False
            with self.layer(record.layer) as archive:
                for info in archive:
                    if archive_path(info.name) == record.name:
                        if not info.isfile() or info.size != record.info.size:
                            raise ValueError("File metadata changed during extraction")
                        source = archive.extractfile(info)
                        if source is None:
                            raise ValueError("Cannot read selected file")
                        count = 0
                        while block := source.read(CHUNK):
                            output.write(block)
                            count += len(block)
                        if count != info.size:
                            raise ValueError("Truncated file in image")
                        found = True
                        # Continue consuming through the end for diff_id checking.
            if not found:
                raise ValueError("Selected file disappeared")
        metadata = record.metadata()
        metadata["sha256"] = sha256(destination)
        return metadata


def validate_elf(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
        raise ValueError("Expected a 64-bit little-endian x86-64 ELF binary")


def _copy_blob(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Copy instead of hardlinking: outputs must not allow mutations of inputs.
    shutil.copyfile(source, destination)


def repack(base: Image, candidate: Path, metadata: dict, output: Path, *, labels: dict | None = None, mode: str = "identity") -> Image:
    if mode not in ("identity", "enterprise-state"):
        raise ValueError(f"Unsupported patch mode: {mode}")
    if output.exists():
        raise FileExistsError(f"Output layout already exists: {output}")
    validate_elf(candidate)
    path = target_path(metadata["path"])
    base.validate()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".repack-", dir=output.parent) as temporary:
        stage = Path(temporary) / "layout"
        stage.mkdir()
        for desc in [*base.layers, base.manifest["config"], base.desc]:
            _copy_blob(check_blob(base.root, desc, checksum=False), blob_path(stage, desc["digest"]))
        tar_path = Path(temporary) / "replacement.tar"
        info = tarfile.TarInfo(path)
        info.size = candidate.stat().st_size
        for field in ("uid", "gid", "mode"):
            value = metadata[field]
            if type(value) is not int or value < 0:
                raise ValueError(f"Invalid file metadata: {field}")
            setattr(info, field, value)
        info.uname = metadata.get("uname", "")
        info.gname = metadata.get("gname", "")
        info.mtime = 0
        info.pax_headers = {k: v for k, v in metadata.get("pax_headers", {}).items() if k.startswith("SCHILY.xattr.")}
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive, candidate.open("rb") as stream:
            archive.addfile(info, stream)
        diff_id = "sha256:" + sha256(tar_path)
        compressed = Path(temporary) / "replacement.tar.gz"
        with tar_path.open("rb") as src, compressed.open("wb") as dst:
            with gzip.GzipFile(filename="", mode="wb", fileobj=dst, mtime=0, compresslevel=6) as zipped:
                shutil.copyfileobj(src, zipped, CHUNK)
        layer = descriptor(compressed, OCI_LAYER)
        _copy_blob(compressed, blob_path(stage, layer["digest"]))
        config = copy.deepcopy(base.config)
        config["rootfs"]["diff_ids"].append(diff_id)
        if config.get("history") is None:
            config["history"] = []
        if mode == "identity":
            config["history"].append({"created_by": "Dentinel identity repack", "comment": "No functional binary patch applied"})
        else:
            config["history"].append({"created_by": "Dentinel enterprise-state repack", "comment": "Restricted enterprise-state binary patch applied"})
        if config.get("config") is None:
            config["config"] = {}
        if config["config"].get("Labels") is None:
            config["config"]["Labels"] = {}
        image_labels = config["config"]["Labels"]
        image_labels.update(labels or {})
        image_labels["org.dentinel.base.digest"] = base.digest
        image_labels["org.dentinel.patch.mode"] = mode
        config_desc = put_blob(stage, json_bytes(config), OCI_CONFIG)
        manifest = copy.deepcopy(base.manifest)
        manifest["mediaType"] = OCI_MANIFEST
        manifest["config"] = config_desc
        manifest["layers"].append(layer)
        # Upstream signatures/attestations are deliberately not copied as claims.
        manifest.pop("subject", None)
        manifest_desc = put_blob(stage, json_bytes(manifest), OCI_MANIFEST)
        manifest_desc["platform"] = {"os": "linux", "architecture": "amd64"}
        write_json(stage / "index.json", {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [manifest_desc]})
        write_json(stage / "oci-layout", {"imageLayoutVersion": "1.0.0"})
        Image(stage).validate()
        stage.replace(output)
    return Image(output)


def replacement_record(image: Image) -> FileRecord:
    """A Dentinel stage-one layer may contain exactly one ordinary file."""
    records = []
    index = len(image.layers) - 1
    if index < 0:
        raise ValueError("Image has no replacement layer")
    with image.layer(index) as archive:
        for info in archive:
            name = archive_path(info.name)
            if not name or not info.isfile() or info.issparse() or any(part.startswith(".wh.") for part in name.split("/")):
                raise ValueError("Replacement layer must contain only one ordinary binary file")
            records.append(FileRecord(index, name, info))
            if len(records) > 1:
                raise ValueError("Replacement layer contains unexpected extra entries")
    if len(records) != 1:
        raise ValueError("Replacement layer must contain exactly one file")
    return records[0]


def verify_publish(image: Image) -> None:
    """Validate restricted patch semantics, tar integrity and every diff_id before auth."""
    labels = (image.config.get("config") or {}).get("Labels") or {}
    mode = labels.get("org.dentinel.patch.mode")
    if mode not in ("identity", "enterprise-state"):
        raise ValueError(f"Unsupported patch mode: {mode}")
    if not DIGEST.fullmatch(labels.get("org.dentinel.base.digest", "")):
        raise ValueError("Expected a traceable Dentinel image")
    replacement = replacement_record(image)
    final = image.find([replacement.name, START_PATH])[replacement.name]
    # A read-only view of the preceding layers, not a new on-disk manifest.
    base_view = copy.copy(image)
    base_view.layers = image.layers[:-1]
    original = base_view.find([replacement.name, START_PATH])[replacement.name]
    for field in ("uid", "gid", "mode", "size", "uname", "gname", "pax_headers"):
        if original.metadata()[field] != final.metadata()[field]:
            raise ValueError(f"{mode} image changed binary metadata: {field}")
    with tempfile.TemporaryDirectory(prefix="dentinel-publish-check-") as tmp:
        old_file, new_file = Path(tmp) / "old", Path(tmp) / "new"
        base_view.extract(original, old_file)
        image.extract(final, new_file)
        validate_elf(new_file)
        # Import lazily: patcher uses this module's ELF validation boundary.
        from .patcher import verify_candidate

        try:
            verify_candidate(old_file, new_file, mode)
        except ValueError as exc:
            if mode == "identity":
                raise ValueError(f"Identity image changed original binary bytes: {exc}") from exc
            raise


def verify_repack(base: Image, result: Image, candidate: Path, metadata: dict, *, mode: str = "identity") -> dict:
    if mode not in ("identity", "enterprise-state"):
        raise ValueError(f"Unsupported patch mode: {mode}")
    result.validate()
    if result.layers[:-1] != base.layers or len(result.layers) != len(base.layers) + 1:
        raise ValueError("Repacked image must preserve every base layer and add exactly one")
    for field in ("architecture", "os", "variant"):
        if base.config.get(field) != result.config.get(field):
            raise ValueError(f"Image platform changed: {field}")
    before = copy.deepcopy(base.config.get("config") or {})
    after = copy.deepcopy(result.config.get("config") or {})
    before.pop("Labels", None)
    after.pop("Labels", None)
    if before != after:
        raise ValueError("Runtime configuration was changed")
    labels = (result.config.get("config") or {}).get("Labels") or {}
    for name, value in ((base.config.get("config") or {}).get("Labels") or {}).items():
        if not name.startswith("org.opencontainers.image.") and labels.get(name) != value:
            raise ValueError(f"Upstream notice label changed: {name}")
    if result.config["rootfs"]["diff_ids"][:-1] != base.config["rootfs"]["diff_ids"]:
        raise ValueError("Base diff_ids were changed")
    replacement = replacement_record(result)
    if replacement.name != target_path(metadata["path"]):
        raise ValueError("Replacement layer targets an unexpected path")
    if labels.get("org.dentinel.patch.mode") != mode:
        raise ValueError("Repacked image patch mode does not match verification mode")
    if labels.get("org.dentinel.base.digest") != base.digest:
        raise ValueError("Repacked image base digest does not match the actual base")
    # Full logical lookup catches later layer overrides and verifies every diff_id.
    record = result.find([metadata["path"], START_PATH])[target_path(metadata["path"])]
    original = base.find([metadata["path"], START_PATH])[target_path(metadata["path"])]
    for field in ("uid", "gid", "mode", "size", "uname", "gname", "pax_headers"):
        expected = metadata.get(field, {} if field == "pax_headers" else None)
        if record.metadata()[field] != expected or original.metadata()[field] != expected:
            raise ValueError(f"File metadata changed: {field}")
    with tempfile.TemporaryDirectory(prefix="dentinel-verify-") as temp:
        original_file, extracted_file = Path(temp) / "original", Path(temp) / "binary"
        baseline = base.extract(original, original_file)
        if baseline["sha256"] != metadata["sha256"]:
            raise ValueError("Extraction metadata does not match the actual base binary")
        # Never trust a patch report: authenticate the candidate against real base bytes.
        from .patcher import verify_candidate

        verified = verify_candidate(original_file, candidate, mode)
        extracted = result.extract(record, extracted_file)
        validate_elf(extracted_file)
        if extracted["sha256"] != sha256(candidate):
            raise ValueError("Repacked binary does not match candidate")
    return {
        "source_digest": base.digest, "image_digest": result.digest,
        "binary_sha256": extracted["sha256"], "original_binary_sha256": baseline["sha256"],
        "platform": "linux/amd64",
        "layers": {"original": len(base.layers), "result": len(result.layers)},
        "original_layers": len(base.layers), "result_layers": len(result.layers),
        "mode": mode, "functional_patch_applied": verified["functional_patch_applied"],
        "runtime_config_preserved": True, "round_trip_verified": True,
        "runtime_tested": False,
    }


def pack_layout(root: Path, output: Path) -> None:
    image = Image(root)
    image.validate()
    paths = [root / "oci-layout", root / "index.json"]
    paths.extend(blob_path(root, desc["digest"]) for desc in [image.desc, image.manifest["config"], *image.layers])
    with atomic_file(output) as stream, tarfile.open(fileobj=stream, mode="w|") as archive:
        for path in sorted(set(paths)):
            info = tarfile.TarInfo(path.relative_to(root).as_posix())
            info.size = path.stat().st_size
            info.mode = 0o644
            info.mtime = 0
            with path.open("rb") as source:
                archive.addfile(info, source)


def unpack_layout(archive_path_: Path, output: Path) -> Image:
    """Import only ordinary files in the narrow OCI layout namespace."""
    if output.exists():
        raise FileExistsError(f"Layout already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".oci-import-", dir=output.parent) as tmp:
        stage = Path(tmp) / "layout"
        stage.mkdir()
        seen = set()
        total = 0
        with tarfile.open(archive_path_, "r|*") as archive:
            for info in archive:
                name = archive_path(info.name)
                if name not in ("index.json", "oci-layout") and not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name):
                    raise ValueError(f"Unexpected OCI archive path: {name}")
                if not info.isfile() or info.issparse() or name in seen or info.size > MAX_LAYER_BYTES:
                    raise ValueError("Invalid OCI archive entry")
                total += info.size
                if total > 32 * 1024**3 or len(seen) > 10000:
                    raise ValueError("OCI archive exceeds size limits")
                seen.add(name)
                source = archive.extractfile(info)
                if source is None:
                    raise ValueError("Cannot read OCI entry")
                with atomic_file(stage / name) as destination:
                    shutil.copyfileobj(source, destination, CHUNK)
        image = Image(stage)
        image.validate()
        stage.replace(output)
    return Image(output)
