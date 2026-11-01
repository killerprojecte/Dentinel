"""Artifact-oriented pipeline; extraction, patching and repacking are independent."""

from __future__ import annotations

import gzip
import logging
import re
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .common import atomic_file, load_json, sha256, write_json
from .oci import BINARY_PATH, START_PATH, Image, pack_layout, repack, target_path, validate_elf, verify_repack
from . import patcher


def extract(layout: Path, output: Path, lock: dict, binary_path: str = BINARY_PATH) -> dict:
    image = Image(layout)
    if image.digest != lock["digest"] or lock["platform"] != "linux/amd64":
        raise ValueError("Downloaded layout differs from source lock")
    if output.exists():
        raise FileExistsError(f"Extraction output exists: {output}")
    binary_path = target_path(binary_path)
    if binary_path == START_PATH:
        raise ValueError("Binary path cannot be the startup script")
    records = image.find([binary_path, START_PATH])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".extract-", dir=output.parent) as tmp:
        stage = Path(tmp) / "original"
        stage.mkdir()
        binary = image.extract(records[binary_path], stage / "altcha-sentinel")
        validate_elf(stage / "altcha-sentinel")
        startup = image.extract(records[START_PATH], stage / "start.sh")
        metadata = {"schema_version": 1, "source_digest": image.digest, "platform": "linux/amd64", "binary": binary, "startup": startup}
        write_json(stage / "manifest.json", image.manifest)
        write_json(stage / "config.json", image.config)
        write_json(stage / "source-lock.json", lock)
        write_json(stage / "extraction.json", metadata)
        with atomic_file(stage / "SHA256SUMS") as stream:
            for path in sorted(stage.iterdir()):
                if path.name != "SHA256SUMS":
                    stream.write(f"{sha256(path)}  {path.name}\n".encode("utf-8"))
        stage.replace(output)
    return metadata


def patch(original: Path, patched: Path, mode: str = "enterprise-state") -> dict:
    if mode not in patcher.MODES:
        raise ValueError(f"Unsupported patch mode: {mode}")
    if patched.exists() or patched.is_symlink():
        raise FileExistsError(f"Candidate directory exists: {patched}")
    if patched.resolve().is_relative_to(original.resolve()):
        raise ValueError("Candidate directory must be separate from the original")
    metadata = load_json(original / "extraction.json")
    patched.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".patch-", dir=patched.parent) as tmp:
        stage = Path(tmp) / "patched"
        stage.mkdir()
        patcher.apply_patch(original / "altcha-sentinel", stage / "altcha-sentinel", metadata["binary"]["sha256"], stage / "patch-report.json", mode=mode)
        report = load_json(stage / "patch-report.json")
        if patched.exists() or patched.is_symlink():
            raise FileExistsError(f"Candidate directory exists: {patched}")
        stage.replace(patched)
    return report


def identity(original: Path, patched: Path) -> None:
    patch(original, patched, mode="identity")


def tracking_labels(source_url: str | None, revision: str | None, mode: str = "identity") -> dict:
    if mode not in patcher.MODES:
        raise ValueError(f"Unsupported patch mode: {mode}")
    description = "Sentinel identity repack; no functional patches applied" if mode == "identity" else "Sentinel community repack with a local enterprise-state patch; not vendor-signed or vendor-endorsed"
    labels = {"org.opencontainers.image.title": "Dentinel", "org.opencontainers.image.description": description}
    if source_url:
        parsed = urlsplit(source_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or any(ord(c) < 32 for c in source_url):
            raise ValueError("Source URL must be a credential-free HTTPS URL")
        labels["org.opencontainers.image.source"] = source_url
    if revision:
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", revision):
            raise ValueError("Revision must be a Git commit hash")
        labels["org.opencontainers.image.revision"] = revision
    return labels


def rebuild(work: Path, *, source_url: str | None = None, revision: str | None = None, patched: Path | None = None, output: Path | None = None) -> dict:
    layout, original = work / "upstream", work / "original"
    patched = patched if patched is not None else work / "patched"
    output = output if output is not None else work
    # Never place new products inside source/candidate artifacts, including the
    # previous identity candidate when a separate enterprise candidate is used.
    for protected in (layout, original, patched, work / "patched", work / "result"):
        if output.resolve().is_relative_to(protected.resolve()):
            raise ValueError(f"Repack output overlaps protected input: {protected}")
    names = ("result", "dentinel.oci.tar", "repack-report.json")
    for name in names:
        destination = output / name
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"Repack output exists: {destination}")
    metadata = load_json(original / "extraction.json")
    lock = load_json(original / "source-lock.json")
    patch_report = load_json(patched / "patch-report.json")
    mode = patch_report.get("mode")
    if mode not in patcher.MODES:
        raise ValueError(f"Unsupported patch mode: {mode}")
    base = Image(layout)
    if base.digest != lock["digest"] or base.digest != metadata["source_digest"]:
        raise ValueError("Source provenance mismatch")
    expected = metadata["binary"]["sha256"]
    if sha256(original / "altcha-sentinel") != expected:
        raise ValueError("Original binary hash differs from extraction metadata")
    verified = patcher.verify_candidate(original / "altcha-sentinel", patched / "altcha-sentinel", mode)
    for key in ("mode", "input_sha256", "output_sha256", "functional_patch_applied"):
        if key not in patch_report or key not in verified or type(patch_report[key]) is not type(verified[key]) or patch_report[key] != verified[key]:
            raise ValueError(f"Patch report differs from verified candidate: {key}")
    if verified["input_sha256"] != expected or verified["output_sha256"] != sha256(patched / "altcha-sentinel"):
        raise ValueError("Candidate verification hash mismatch")
    if type(verified["functional_patch_applied"]) is not bool:
        raise ValueError("Candidate verification requires a boolean functional flag")
    labels = tracking_labels(source_url, revision, mode)
    # Derive metadata from the actual input image, not a caller-editable JSON claim.
    record = base.find([metadata["binary"]["path"]])[target_path(metadata["binary"]["path"])]
    for key, value in record.metadata().items():
        if metadata["binary"].get(key) != value:
            raise ValueError(f"Extraction metadata changed: {key}")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rebuild-", dir=output) as tmp:
        stage = Path(tmp)
        result = repack(base, patched / "altcha-sentinel", metadata["binary"], stage / "result", labels=labels, mode=mode)
        report = verify_repack(base, result, patched / "altcha-sentinel", metadata["binary"], mode=mode)
        pack_layout(result.root, stage / "dentinel.oci.tar")
        write_json(stage / "repack-report.json", report)
        for name in names:
            destination = output / name
            if destination.exists() or destination.is_symlink():
                raise FileExistsError(f"Repack output exists: {destination}")
            (stage / name).replace(destination)
    return report


def analysis_bundle(work: Path) -> Path:
    output = work / "analysis.tar.gz"
    files = [(path, "original/" + path.name) for path in sorted((work / "original").iterdir())]
    files.extend((work / name, name) for name in ("source-lock.json", "repack-report.json"))
    files.append((work / "patched" / "patch-report.json", "patch-report.json"))
    with atomic_file(output) as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                for path, name in files:
                    if path.is_symlink() or not path.is_file():
                        raise ValueError("Unexpected analysis bundle entry")
                    info = tarfile.TarInfo(name)
                    info.size = path.stat().st_size
                    info.mode = 0o755 if name in ("original/altcha-sentinel", "original/start.sh") else 0o644
                    if name.startswith("original/") and path.name in ("altcha-sentinel", "start.sh"):
                        meta = load_json(work / "original" / "extraction.json")
                        item = meta["binary" if path.name == "altcha-sentinel" else "startup"]
                        info.mode, info.uid, info.gid = item["mode"], item["uid"], item["gid"]
                        info.uname, info.gname = item["uname"], item["gname"]
                        info.pax_headers = item.get("pax_headers", {})
                    with path.open("rb") as source:
                        archive.addfile(info, source)
    return output


def run(source: str, work: Path, cache: Path, *, source_url: str | None = None, revision: str | None = None, binary_path: str = BINARY_PATH, patch_mode: str = "identity") -> dict:
    # Import here: offline commands never bootstrap or contact any registry.
    from .registry import pull, resolve
    from .tooling import ensure_crane

    if work.exists() and any(work.iterdir()):
        raise FileExistsError("Run requires a new/empty work directory; use individual commands to resume")
    tracking_labels(source_url, revision, patch_mode)
    work.mkdir(parents=True, exist_ok=True)
    logging.info("[1/6] 校验固定版本 crane")
    crane = ensure_crane(cache)
    logging.info("[2/6] 锁定 linux/amd64 平台并下载镜像")
    lock = resolve(crane, source)
    write_json(work / "source-lock.json", lock)
    logging.info("上游 digest: %s", lock["digest"])
    pull(crane, lock, work / "upstream")
    logging.info("[3/6] 提取原始二进制及 Linux 元数据")
    extract(work / "upstream", work / "original", lock, binary_path)
    logging.info("[4/6] Patcher 模式：%s", patch_mode)
    patch(work / "original", work / "patched", mode=patch_mode)
    logging.info("[5/6] 离线生成替换层、回包并验证候选字节")
    report = rebuild(work, source_url=source_url, revision=revision)
    logging.info("[6/6] 保存后续分析用的原始产物归档")
    analysis_bundle(work)
    logging.info("完成，回包 digest: %s", report["image_digest"])
    return report
