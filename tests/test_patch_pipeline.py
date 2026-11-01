from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch as mock_patch

from dentinel import patcher, pipeline
from dentinel.cli import main, parser
from dentinel.common import load_json, sha256, write_json
from dentinel.oci import Image
from test_oci import make_image


MODES = ("identity", "enterprise-state")


class PatchPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.base = Image(make_image(self.work / "upstream"))
        self.lock = {"digest": self.base.digest, "platform": "linux/amd64"}
        self.metadata = pipeline.extract(self.base.root, self.work / "original", self.lock)
        self.original = self.work / "original" / "altcha-sentinel"
        self.original_bytes = self.original.read_bytes()
        modes = mock_patch.object(patcher, "MODES", MODES, create=True)
        modes.start()
        self.addCleanup(modes.stop)

    def fake_apply(self, source, destination, expected_sha256, report, mode="identity"):
        self.assertEqual(sha256(source), expected_sha256)
        destination.write_bytes(source.read_bytes() + (b"patched" if mode == "enterprise-state" else b""))
        data = self.fake_verify(source, destination, mode)
        write_json(report, data)
        return SimpleNamespace(**data)

    def fake_verify(self, source, candidate, mode):
        expected = source.read_bytes() + (b"patched" if mode == "enterprise-state" else b"")
        if candidate.read_bytes() != expected:
            raise ValueError("Candidate bytes do not match requested mode")
        return {"mode": mode, "input_sha256": sha256(source), "output_sha256": sha256(candidate), "functional_patch_applied": mode != "identity"}

    def create_candidate(self, destination, mode="enterprise-state"):
        with mock_patch.object(patcher, "apply_patch", side_effect=self.fake_apply, create=True):
            return pipeline.patch(self.work / "original", destination, mode=mode)

    def rebuild(self, *, patched=None, output=None):
        def repack(base, candidate, metadata, destination, *, labels, mode):
            self.assertEqual(base.digest, self.base.digest)
            self.assertEqual(metadata, self.metadata["binary"])
            destination.mkdir()
            (destination / "fixture").write_text(mode, encoding="utf-8")
            return SimpleNamespace(root=destination)

        def verify(base, result, candidate, metadata, *, mode):
            return {"mode": mode, "image_digest": "sha256:" + "1" * 64, "functional_patch_applied": mode != "identity"}

        with mock_patch.object(patcher, "verify_candidate", side_effect=self.fake_verify, create=True), mock_patch.object(pipeline, "repack", side_effect=repack), mock_patch.object(pipeline, "verify_repack", side_effect=verify), mock_patch.object(pipeline, "pack_layout", side_effect=lambda root, destination: destination.write_bytes(b"archive")):
            return pipeline.rebuild(self.work, patched=patched, output=output)

    def snapshot(self, root):
        return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def command(self, *arguments):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(arguments))
        return code, stdout.getvalue()

    def test_patch_default_dispatch_and_atomic_failure(self):
        destination = self.work / "enterprise"
        with mock_patch.object(patcher, "apply_patch", side_effect=self.fake_apply, create=True) as apply:
            report = pipeline.patch(self.work / "original", destination)
        self.assertEqual(apply.call_args.kwargs["mode"], "enterprise-state")
        self.assertTrue(report["functional_patch_applied"])
        self.assertEqual(self.original.read_bytes(), self.original_bytes)
        self.assertEqual(load_json(destination / "patch-report.json"), report)
        with self.assertRaises(FileExistsError):
            pipeline.patch(self.work / "original", destination)

        failed = self.work / "failed"
        def fail(source, candidate, expected, report, *, mode):
            candidate.write_bytes(b"partial")
            raise ValueError("unsupported fixture")
        with mock_patch.object(patcher, "apply_patch", side_effect=fail, create=True), self.assertRaisesRegex(ValueError, "unsupported"):
            pipeline.patch(self.work / "original", failed)
        self.assertFalse(failed.exists())
        self.assertFalse(list(self.work.glob(".patch-*")))
        self.assertEqual(self.original.read_bytes(), self.original_bytes)

    def test_identity_delegates_to_identity_mode(self):
        with mock_patch.object(pipeline, "patch") as apply:
            pipeline.identity(self.work / "original", self.work / "patched")
        apply.assert_called_once_with(self.work / "original", self.work / "patched", mode="identity")

    def test_invalid_modes_fail_before_patch_or_repack(self):
        with mock_patch.object(patcher, "apply_patch", create=True) as apply:
            with self.assertRaisesRegex(ValueError, "Unsupported patch mode"):
                pipeline.patch(self.work / "original", self.work / "bad", mode="unknown")
            apply.assert_not_called()
        candidate = self.work / "enterprise"
        self.create_candidate(candidate)
        report = load_json(candidate / "patch-report.json")
        report["mode"] = "unknown"
        write_json(candidate / "patch-report.json", report, replace=True)
        with self.assertRaisesRegex(ValueError, "Unsupported patch mode"):
            self.rebuild(patched=candidate, output=self.work / "bad-output")
        with self.assertRaisesRegex(ValueError, "Unsupported patch mode"):
            pipeline.tracking_labels(None, None, "unknown")
        self.assertFalse((self.work / "bad-output").exists())

    def test_explicit_directories_preserve_all_previous_artifacts(self):
        self.create_candidate(self.work / "patched", "identity")
        self.rebuild()
        candidate = self.work / "patched-enterprise"
        self.create_candidate(candidate)
        before = self.snapshot(self.work)
        output = self.root / "enterprise-result"
        report = self.rebuild(patched=candidate, output=output)
        self.assertEqual(report["mode"], "enterprise-state")
        self.assertEqual(set(path.name for path in output.iterdir()), {"result", "dentinel.oci.tar", "repack-report.json"})
        self.assertEqual(self.snapshot(self.work), before)
        with self.assertRaises(FileExistsError):
            self.rebuild(patched=candidate, output=output)
        self.assertEqual(self.snapshot(self.work), before)

    def test_output_cannot_be_inside_source_or_candidate_artifacts(self):
        candidate = self.work / "patched-enterprise"
        self.create_candidate(candidate)
        for protected in (self.work / "original", self.work / "upstream", self.work / "patched", self.work / "result", candidate):
            with self.subTest(protected=protected), self.assertRaisesRegex(ValueError, "protected input"):
                self.rebuild(patched=candidate, output=protected / "new")
        with self.assertRaisesRegex(ValueError, "separate from the original"):
            pipeline.patch(self.work / "original", self.work / "original" / "new")

    def test_forged_report_hashes_and_flags_are_rejected(self):
        candidate = self.work / "patched-enterprise"
        valid = self.create_candidate(candidate)
        corruptions = (("input_sha256", "0" * 64), ("output_sha256", "0" * 64), ("functional_patch_applied", False), ("functional_patch_applied", 1), ("mode", "identity"))
        for key, value in corruptions:
            with self.subTest(key=key, value=value):
                forged = {**valid, key: value}
                write_json(candidate / "patch-report.json", forged, replace=True)
                output = self.root / "invalid-output"
                with self.assertRaises(ValueError):
                    self.rebuild(patched=candidate, output=output)
                self.assertFalse(output.exists())
        forged = dict(valid)
        del forged["functional_patch_applied"]
        write_json(candidate / "patch-report.json", forged, replace=True)
        with self.assertRaises(ValueError):
            self.rebuild(patched=candidate, output=self.root / "missing-flag")

    def test_original_and_extraction_metadata_stay_bound_to_base(self):
        candidate = self.work / "patched-enterprise"
        self.create_candidate(candidate)
        self.original.write_bytes(self.original_bytes + b"tamper")
        with self.assertRaisesRegex(ValueError, "Original binary hash"):
            self.rebuild(patched=candidate, output=self.root / "altered-original")
        self.original.write_bytes(self.original_bytes)
        metadata_path = self.work / "original" / "extraction.json"
        metadata = load_json(metadata_path)
        metadata["binary"]["mode"] = 0o777
        write_json(metadata_path, metadata, replace=True)
        with self.assertRaisesRegex(ValueError, "Extraction metadata changed"):
            self.rebuild(patched=candidate, output=self.root / "altered-metadata")

    def test_cli_mode_defaults_and_patch_json(self):
        self.assertEqual(parser().parse_args(["patch"]).mode, "enterprise-state")
        self.assertEqual(parser().parse_args(["run"]).patch_mode, "identity")
        with mock_patch.object(pipeline, "patch", return_value={"mode": "enterprise-state"}) as apply:
            code, stdout = self.command("patch", "--work", "relative-work")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), {"mode": "enterprise-state"})
        apply.assert_called_once_with(Path("relative-work/original"), Path("relative-work/patched-enterprise"), mode="enterprise-state")
        with mock_patch.object(pipeline, "patch", return_value={"mode": "identity"}) as apply:
            self.assertEqual(self.command("patch", "--work", "relative-work", "--mode", "identity", "--output", "separate")[0], 0)
        apply.assert_called_once_with(Path("relative-work/original"), Path("separate"), mode="identity")
        for command, option in (("patch", "--mode"), ("run", "--patch-mode")):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args([command, option, "unknown"])

    def test_cli_repack_and_run_forward_options(self):
        with mock_patch.object(pipeline, "rebuild", return_value={}) as rebuild:
            self.assertEqual(self.command("repack", "--work", "relative-work", "--patched", "candidate", "--output", "result-work")[0], 0)
        rebuild.assert_called_once_with(Path("relative-work"), source_url=None, revision=None, patched=Path("candidate"), output=Path("result-work"))
        with mock_patch.object(pipeline, "run", return_value={}) as run:
            self.assertEqual(self.command("run", "--work", "relative-work", "--patch-mode", "enterprise-state", "--source-url", "https://example.test/project", "--revision", "1234567")[0], 0)
        self.assertEqual(run.call_args.args[1], Path("relative-work"))
        self.assertEqual(run.call_args.kwargs["patch_mode"], "enterprise-state")
        self.assertEqual(run.call_args.kwargs["source_url"], "https://example.test/project")
        self.assertEqual(run.call_args.kwargs["revision"], "1234567")

    def test_cli_verify_dispatches_target_mode_and_recomputes(self):
        output, candidate = self.root / "outputs", self.root / "candidate"
        output.mkdir()
        write_json(output / "repack-report.json", {"mode": "enterprise-state", "round_trip_verified": True})
        arguments = ("verify", "--work", str(self.work), "--patched", str(candidate), "--output", str(output))
        with mock_patch("dentinel.cli.Image") as image, mock_patch("dentinel.cli.verify_repack", return_value={"fresh": True}) as verify:
            code, stdout = self.command(*arguments)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), {"fresh": True})
        self.assertEqual(verify.call_args.kwargs, {"mode": "enterprise-state"})
        self.assertEqual(verify.call_args.args[2], candidate / "altcha-sentinel")
        self.assertEqual(image.call_args_list[-1].args, (output / "result",))
        with mock_patch("dentinel.cli.Image"), mock_patch("dentinel.cli.verify_repack", side_effect=ValueError("actual candidate invalid")):
            self.assertEqual(self.command(*arguments)[0], 1)
        (output / "repack-report.json").unlink()
        with mock_patch("dentinel.cli.Image"), mock_patch("dentinel.cli.verify_repack", return_value={}) as verify:
            self.assertEqual(self.command(*arguments)[0], 0)
        self.assertEqual(verify.call_args.kwargs["mode"], "identity")
        write_json(output / "repack-report.json", {"mode": "unknown"})
        with mock_patch("dentinel.cli.verify_repack") as verify:
            self.assertEqual(self.command(*arguments)[0], 1)
            verify.assert_not_called()

    def test_run_uses_requested_patch_mode_and_validates_before_download(self):
        for mode in MODES:
            work = self.root / ("run-" + mode)
            with mock_patch("dentinel.tooling.ensure_crane", return_value=Path("crane")), mock_patch("dentinel.registry.resolve", return_value=self.lock), mock_patch("dentinel.registry.pull"), mock_patch.object(pipeline, "extract"), mock_patch.object(pipeline, "patch") as apply, mock_patch.object(pipeline, "rebuild", return_value={"image_digest": self.base.digest}), mock_patch.object(pipeline, "analysis_bundle"):
                kwargs = {} if mode == "identity" else {"patch_mode": mode}
                pipeline.run("fixture", work, self.root / "tools", **kwargs)
                apply.assert_called_once_with(work / "original", work / "patched", mode=mode)
        with mock_patch("dentinel.tooling.ensure_crane") as bootstrap, self.assertRaisesRegex(ValueError, "Unsupported patch mode"):
            pipeline.run("fixture", self.root / "bad-run", self.root / "tools", patch_mode="unknown")
        bootstrap.assert_not_called()
        self.assertFalse((self.root / "bad-run").exists())

    def test_tracking_labels_describe_modes_without_claiming_vendor_signature(self):
        identity = pipeline.tracking_labels(None, None)
        enterprise = pipeline.tracking_labels("https://example.test/project", "1234567", "enterprise-state")
        self.assertIn("no functional patches", identity["org.opencontainers.image.description"])
        self.assertIn("local enterprise-state patch", enterprise["org.opencontainers.image.description"])
        self.assertIn("not vendor-signed", enterprise["org.opencontainers.image.description"])
        self.assertEqual(enterprise["org.opencontainers.image.source"], "https://example.test/project")

    def test_workflow_dispatch_mode_is_quoted_and_manual_publish_stays_opt_in(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        mode_input = workflow.split("      patch_mode:\n", 1)[1].split("      publish:\n", 1)[0]
        self.assertIn("type: choice", mode_input)
        self.assertIn("- identity", mode_input)
        self.assertIn("- enterprise-state", mode_input)
        self.assertIn("default: enterprise-state", mode_input)
        self.assertIn("PATCH_MODE: ${{ inputs.patch_mode || 'enterprise-state' }}", workflow)
        self.assertIn('--patch-mode "$PATCH_MODE"', workflow)
        self.assertIn("report.get('mode') != os.environ['PATCH_MODE']", workflow)
        self.assertIn("补丁模式", workflow)
        publish_input = workflow.split("      publish:\n", 1)[1].split("      tag:\n", 1)[0]
        self.assertIn("default: false", publish_input)


if __name__ == "__main__":
    unittest.main()
