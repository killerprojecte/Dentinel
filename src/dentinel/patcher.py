"""Atomic patchers and source-bound verification shared by CLI and OCI checks."""

from __future__ import annotations

import mmap
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .common import copy_atomic, sha256, write_json
from .oci import validate_elf

MODES = ("identity", "enterprise-state")


@dataclass(frozen=True)
class PatchResult:
    mode: str
    input_sha256: str
    output_sha256: str
    functional_patch_applied: bool = False
    details: dict = field(default_factory=dict)

    def report(self) -> dict:
        result = {
            "schema_version": 1, "mode": self.mode,
            "input_sha256": self.input_sha256, "output_sha256": self.output_sha256,
            "functional_patch_applied": self.functional_patch_applied,
            "status": "identity-only" if self.mode == "identity" else "local-enterprise-state",
        }
        if self.details:
            result["details"] = self.details
        return result


class Patcher(Protocol):
    def apply(self, source: Path, destination: Path, expected_sha256: str) -> PatchResult: ...


def _paths(source: Path, destination: Path) -> None:
    if source.resolve() == destination.resolve() or destination.exists() or destination.is_symlink():
        raise ValueError("Patcher output must be a new file distinct from the original")


class IdentityPatcher:
    def apply(self, source: Path, destination: Path, expected_sha256: str) -> PatchResult:
        _paths(source, destination)
        validate_elf(source)
        before = sha256(source)
        if before != expected_sha256:
            raise ValueError("Original binary hash differs from extraction metadata")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".patch-", dir=destination.parent) as temporary:
            candidate = Path(temporary) / "candidate"
            copy_atomic(source, candidate)
            after = sha256(candidate)
            if after != before or sha256(source) != before:
                raise ValueError("Identity copy failed hash verification")
            _paths(source, destination)
            candidate.replace(destination)
        return PatchResult("identity", before, after)


class EnterpriseStatePatcher:
    def apply(self, source: Path, destination: Path, expected_sha256: str) -> PatchResult:
        from .license_state import expected_sha256 as predicted_hash, plan

        _paths(source, destination)
        validate_elf(source)
        before = sha256(source)
        if before != expected_sha256:
            raise ValueError("Original binary hash differs from extraction metadata")
        recipe = plan(source)
        expected_output = predicted_hash(source, recipe)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".enterprise-patch-", dir=destination.parent) as temporary:
            candidate = Path(temporary) / "candidate"
            copy_atomic(source, candidate)
            with candidate.open("r+b") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_WRITE) as mapped:
                offset, size = recipe.offset, len(recipe.original)
                if mapped[offset:offset + size] != recipe.original:
                    raise ValueError("License loader preimage mismatch")
                mapped[offset:offset + size] = recipe.replacement
                mapped.flush()
            with candidate.open("r+b") as stream:
                os.fsync(stream.fileno())
            after = sha256(candidate)
            if candidate.stat().st_size != source.stat().st_size or after != expected_output or sha256(source) != before:
                raise ValueError("Patched output/source changed during atomic verification")
            _paths(source, destination)
            candidate.replace(destination)
        return PatchResult("enterprise-state", before, after, True, recipe.details())


def verify_candidate(source: Path, candidate: Path, mode: str) -> dict:
    """Recompute the only permitted result from actual source, not a report."""
    if mode not in MODES:
        raise ValueError(f"Unsupported patch mode: {mode}")
    validate_elf(source)
    validate_elf(candidate)
    before, after = sha256(source), sha256(candidate)
    if source.stat().st_size != candidate.stat().st_size:
        raise ValueError("Patcher must preserve original binary size")
    details = {}
    if mode == "identity":
        if before != after:
            raise ValueError("Identity image changed original binary bytes")
    else:
        from .license_state import expected_sha256, plan
        recipe = plan(source)
        if expected_sha256(source, recipe) != after:
            raise ValueError("Candidate differs from the source-derived enterprise-state recipe")
        details = recipe.details()
    if sha256(source) != before:
        raise ValueError("Original changed during candidate verification")
    return PatchResult(mode, before, after, mode != "identity", details).report()


def apply_patch(source: Path, destination: Path, expected_sha256: str, report: Path, mode: str = "identity") -> PatchResult:
    if mode not in MODES:
        raise ValueError(f"Unsupported patch mode: {mode}")
    if report.resolve() in (source.resolve(), destination.resolve()):
        raise ValueError("Patch report must be separate from input and output")
    if report.exists() or report.is_symlink():
        raise FileExistsError(f"Patch report already exists: {report}")
    patcher = IdentityPatcher() if mode == "identity" else EnterpriseStatePatcher()
    result = patcher.apply(source, destination, expected_sha256)
    try:
        write_json(report, result.report())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return result


def apply_identity(source: Path, destination: Path, expected_sha256: str, report: Path) -> PatchResult:
    return apply_patch(source, destination, expected_sha256, report, "identity")
