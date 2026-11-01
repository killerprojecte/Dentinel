"""Cross-platform CLI. Registry I/O is isolated from offline operations."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tarfile
import tempfile
from pathlib import Path

from . import __version__, patcher, pipeline
from .common import load_json, write_json
from .oci import BINARY_PATH, Image, unpack_layout, verify_publish, verify_repack

DEFAULT_SOURCE = "ghcr.io/altcha-org/sentinel:latest"


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="dentinel", description="无 Docker daemon 的 amd64 镜像提取、可验证补丁与回包工具。")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    boot = commands.add_parser("bootstrap", help="校验并安装固定版本 crane")
    boot.add_argument("--cache", type=Path, default=Path(".tools"))
    fetch = commands.add_parser("fetch", help="锁定 linux/amd64 digest 并下载 OCI layout")
    fetch.add_argument("--source", default=DEFAULT_SOURCE)
    fetch.add_argument("--work", type=Path, default=Path("work"))
    fetch.add_argument("--cache", type=Path, default=Path(".tools"))
    take = commands.add_parser("extract", help="离线提取原始二进制和启动脚本")
    take.add_argument("--work", type=Path, default=Path("work"))
    take.add_argument("--binary-path", default=BINARY_PATH)
    identity = commands.add_parser("identity", help="原样复制到独立候选文件；不应用实际补丁")
    identity.add_argument("--work", type=Path, default=Path("work"))
    patch = commands.add_parser("patch", help="离线生成独立候选文件及可验证补丁报告")
    patch.add_argument("--work", type=Path, default=Path("work"))
    patch.add_argument("--mode", choices=patcher.MODES, default="enterprise-state")
    patch.add_argument("--output", type=Path, help="候选目录（默认：<work>/patched-enterprise）")
    rebuild = commands.add_parser("repack", help="离线追加候选文件层并验证、生成 OCI 归档")
    check = commands.add_parser("verify", help="离线重新校验回包镜像")
    bundle = commands.add_parser("bundle", help="打包后续分析所需原始产物")
    all_steps = commands.add_parser("run", help="执行下载、提取、指定模式补丁、回包、验证和分析包生成")
    for sub in (rebuild, check, bundle, all_steps):
        sub.add_argument("--work", type=Path, default=Path("work"))
    for sub in (rebuild, all_steps):
        sub.add_argument("--source-url", help="Dentinel 项目的 HTTPS 来源 URL")
        sub.add_argument("--revision", help="Dentinel Git commit hash")
    for sub in (rebuild, check):
        sub.add_argument("--patched", type=Path, help="候选目录（默认：<work>/patched）")
        sub.add_argument("--output", type=Path, help="回包产物目录（默认：<work>）")
    all_steps.add_argument("--patch-mode", choices=patcher.MODES, default="identity")
    all_steps.add_argument("--source", default=DEFAULT_SOURCE)
    all_steps.add_argument("--cache", type=Path, default=Path(".tools"))
    all_steps.add_argument("--binary-path", default=BINARY_PATH)
    publish = commands.add_parser("publish", help="从 OCI 归档发布 GHCR（token 仅从环境读取）")
    publish.add_argument("--archive", type=Path, required=True)
    publish.add_argument("--target", required=True, help="ghcr.io/<owner>/dentinel:<tag>")
    publish.add_argument("--cache", type=Path, default=Path(".tools"))
    return root


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    args = parser().parse_args(argv)
    try:
        if args.command == "bootstrap":
            from .tooling import ensure_crane
            print(ensure_crane(args.cache))
        elif args.command == "fetch":
            from .registry import pull, resolve
            from .tooling import ensure_crane
            args.work.mkdir(parents=True, exist_ok=True)
            lock_path = args.work / "source-lock.json"
            if lock_path.exists():
                lock = load_json(lock_path)
                if lock.get("source") != args.source:
                    raise ValueError("Existing source lock belongs to a different source; use a new work directory")
            else:
                if (args.work / "upstream").exists():
                    raise ValueError("Existing layout has no source lock")
                crane = ensure_crane(args.cache)
                lock = resolve(crane, args.source)
                write_json(lock_path, lock)
            if (args.work / "upstream").exists():
                image = Image(args.work / "upstream")
                image.validate()
                if image.digest != lock["digest"]:
                    raise ValueError("Existing layout differs from source lock")
            else:
                pull(ensure_crane(args.cache), lock, args.work / "upstream")
            print(json.dumps(lock))
        elif args.command == "extract":
            print(json.dumps(pipeline.extract(args.work / "upstream", args.work / "original", load_json(args.work / "source-lock.json"), args.binary_path)))
        elif args.command == "identity":
            pipeline.identity(args.work / "original", args.work / "patched")
            print("identity-only; no functional patch applied")
        elif args.command == "patch":
            output = args.output if args.output is not None else args.work / "patched-enterprise"
            print(json.dumps(pipeline.patch(args.work / "original", output, mode=args.mode)))
        elif args.command == "repack":
            print(json.dumps(pipeline.rebuild(args.work, source_url=args.source_url, revision=args.revision, patched=args.patched, output=args.output)))
        elif args.command == "verify":
            metadata = load_json(args.work / "original" / "extraction.json")["binary"]
            output = args.output if args.output is not None else args.work
            patched = args.patched if args.patched is not None else args.work / "patched"
            report_path = output / "repack-report.json"
            mode = load_json(report_path).get("mode") if report_path.exists() else "identity"
            if mode not in patcher.MODES:
                raise ValueError(f"Unsupported patch mode: {mode}")
            print(json.dumps(verify_repack(Image(args.work / "upstream"), Image(output / "result"), patched / "altcha-sentinel", metadata, mode=mode)))
        elif args.command == "bundle":
            print(pipeline.analysis_bundle(args.work))
        elif args.command == "run":
            print(json.dumps(pipeline.run(args.source, args.work, args.cache, source_url=args.source_url, revision=args.revision, binary_path=args.binary_path, patch_mode=args.patch_mode)))
        elif args.command == "publish":
            from .registry import publish, validate_target
            from .tooling import ensure_crane
            validate_target(args.target)
            # Validate the complete archive before authentication or upload.
            with tempfile.TemporaryDirectory(prefix="dentinel-publish-") as temporary:
                image = unpack_layout(args.archive, Path(temporary) / "layout")
                verify_publish(image)
                crane = ensure_crane(args.cache)
                reference = publish(crane, image.root, args.target)
                digest = reference.rsplit("@", 1)[-1]
                if digest != image.digest:
                    raise ValueError("Published manifest digest differs from verified OCI archive")
                print(digest)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"Dentinel: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Dentinel: interrupted", file=sys.stderr)
        return 130
