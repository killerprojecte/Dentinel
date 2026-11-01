from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dentinel.common import sha256
from dentinel.oci import (
    BINARY_PATH, START_PATH, Image, repack, verify_publish, verify_repack,
)
from test_oci import elf, entry, make_image


class OCIModeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = Image(make_image(self.root / "base"))
        self.candidate = self.root / "candidate"
        self.metadata = self.base.extract(
            self.base.find([BINARY_PATH])[BINARY_PATH], self.candidate,
        )
        self.verifications = []
        verifier_patch = patch(
            "dentinel.patcher.verify_candidate", side_effect=self.verify_candidate,
            create=True,
        )
        self.verifier = verifier_patch.start()
        self.addCleanup(verifier_patch.stop)

    def verify_candidate(self, source, candidate, mode):
        before, after = source.read_bytes(), candidate.read_bytes()
        self.verifications.append((before, after, mode))
        if before != elf():
            raise ValueError("Verifier did not receive the actual original")
        expected = elf() if mode == "identity" else elf(b"patched!")
        if after != expected:
            raise ValueError("Candidate does not match restricted expected output")
        return {
            "mode": mode,
            "input_sha256": hashlib.sha256(before).hexdigest(),
            "output_sha256": hashlib.sha256(after).hexdigest(),
            "functional_patch_applied": mode == "enterprise-state",
        }

    def rebuild(self, mode="enterprise-state", *, labels=None):
        if mode == "enterprise-state":
            self.candidate.write_bytes(elf(b"patched!"))
        return repack(
            self.base, self.candidate, self.metadata, self.root / "result",
            mode=mode, labels=labels,
        )

    def test_enterprise_repack_verification_and_publish_use_real_bytes(self):
        result = self.rebuild()
        labels = result.config["config"]["Labels"]
        self.assertEqual(labels["org.dentinel.patch.mode"], "enterprise-state")
        self.assertEqual(labels["org.dentinel.base.digest"], self.base.digest)
        self.assertIn("enterprise-state", result.config["history"][-1]["created_by"])
        self.assertNotIn("identity", json.dumps(result.config["history"][-1]))
        self.assertEqual(result.layers[:-1], self.base.layers)
        report = verify_repack(
            self.base, result, self.candidate, self.metadata, mode="enterprise-state",
        )
        self.assertEqual(report["mode"], "enterprise-state")
        self.assertTrue(report["functional_patch_applied"])
        self.assertEqual(report["original_binary_sha256"], self.metadata["sha256"])
        self.assertEqual(report["binary_sha256"], sha256(self.candidate))
        self.assertNotEqual(report["binary_sha256"], report["original_binary_sha256"])
        self.assertEqual(report["layers"], {"original": len(self.base.layers), "result": len(result.layers)})
        self.assertTrue(report["runtime_config_preserved"])
        self.assertTrue(report["round_trip_verified"])
        self.assertFalse(report["runtime_tested"])
        verify_publish(result)
        self.assertEqual(self.verifications, [(elf(), elf(b"patched!"), "enterprise-state")] * 2)

    def test_default_identity_remains_deterministic_and_uses_verifier(self):
        result = repack(self.base, self.candidate, self.metadata, self.root / "result")
        explicit = repack(
            self.base, self.candidate, self.metadata, self.root / "explicit", mode="identity",
        )
        self.assertEqual(result.digest, explicit.digest)
        self.assertEqual(result.config["history"][-1], {
            "created_by": "Dentinel identity repack", "comment": "No functional binary patch applied",
        })
        report = verify_repack(self.base, result, self.candidate, self.metadata)
        self.assertEqual(report["mode"], "identity")
        self.assertFalse(report["functional_patch_applied"])
        self.assertEqual(report["original_binary_sha256"], report["binary_sha256"])
        verify_publish(result)
        self.assertEqual(self.verifications, [(elf(), elf(), "identity")] * 2)

    def test_repack_cannot_override_selected_mode_with_labels(self):
        result = self.rebuild(labels={"org.dentinel.patch.mode": "identity"})
        self.assertEqual(result.config["config"]["Labels"]["org.dentinel.patch.mode"], "enterprise-state")

    def test_unknown_modes_rejected_before_candidate_verification(self):
        result = self.rebuild()
        for mode in ("unknown", "Enterprise-state", "", None):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, "mode"):
                    repack(self.base, self.candidate, self.metadata, self.root / "unused", mode=mode)
                with self.assertRaisesRegex(ValueError, "mode"):
                    verify_repack(self.base, result, self.candidate, self.metadata, mode=mode)
                result.config["config"]["Labels"]["org.dentinel.patch.mode"] = mode
                with self.assertRaisesRegex(ValueError, "mode"):
                    verify_publish(result)
        self.verifier.assert_not_called()
        self.assertFalse((self.root / "unused").exists())

    def test_verification_mode_must_match_image_label(self):
        result = self.rebuild()
        with self.assertRaisesRegex(ValueError, "mode"):
            verify_repack(self.base, result, self.candidate, self.metadata)
        self.verifier.assert_not_called()

    def test_enterprise_hash_metadata_is_bound_to_actual_base(self):
        result = self.rebuild()
        forged = {**self.metadata, "sha256": sha256(self.candidate)}
        with self.assertRaisesRegex(ValueError, "actual base"):
            verify_repack(self.base, result, self.candidate, forged, mode="enterprise-state")
        self.verifier.assert_not_called()

    def test_forged_patch_report_cannot_authorize_arbitrary_candidate(self):
        report = {
            "mode": "enterprise-state", "functional_patch_applied": True,
            "input_sha256": self.metadata["sha256"], "output_sha256": "0" * 64,
        }
        result = self.rebuild(labels={"org.dentinel.patch.report": json.dumps(report)})
        self.candidate.write_bytes(elf(b"arbitrar"))
        metadata = {**self.metadata, "patch_report": report}
        with self.assertRaisesRegex(ValueError, "restricted expected output"):
            verify_repack(self.base, result, self.candidate, metadata, mode="enterprise-state")
        self.assertEqual(self.verifications[0][0], elf())

    def test_publish_rejects_invalid_candidate_despite_success_report(self):
        self.candidate.write_bytes(elf(b"arbitrar"))
        result = repack(
            self.base, self.candidate, self.metadata, self.root / "result",
            mode="enterprise-state", labels={"org.dentinel.patch.report": '{"functional_patch_applied":true}'},
        )
        with self.assertRaisesRegex(ValueError, "restricted expected output"):
            verify_publish(result)
        self.assertEqual(self.verifications, [(elf(), elf(b"arbitrar"), "enterprise-state")])

    def test_repacked_bytes_must_match_verified_candidate(self):
        result = self.rebuild()
        other = self.root / "other"
        other.write_bytes(elf(b"otherone"))
        self.verifier.side_effect = None
        self.verifier.return_value = {"functional_patch_applied": True}
        with self.assertRaisesRegex(ValueError, "does not match candidate"):
            verify_repack(self.base, result, other, self.metadata, mode="enterprise-state")

    def test_original_metadata_cannot_be_forged(self):
        self.candidate.write_bytes(elf(b"patched!"))
        forged = {**self.metadata, "uid": 0}
        result = repack(
            self.base, self.candidate, forged, self.root / "result", mode="enterprise-state",
        )
        with self.assertRaisesRegex(ValueError, "File metadata changed: uid"):
            verify_repack(self.base, result, self.candidate, forged, mode="enterprise-state")
        with self.assertRaisesRegex(ValueError, "binary metadata: uid"):
            verify_publish(result)
        self.verifier.assert_not_called()

    def test_enterprise_still_rejects_extra_replacement_entries(self):
        original = [entry(BINARY_PATH, elf()), entry(START_PATH, b"#!/bin/sh\nexec ./altcha-sentinel\n")]
        result = Image(make_image(self.root / "evil", [
            original, [entry(BINARY_PATH, elf(b"patched!")), entry("sentinel/server/.wh.start.sh")],
        ]))
        self.candidate.write_bytes(elf(b"patched!"))
        with self.assertRaisesRegex(ValueError, "Replacement layer"):
            verify_repack(self.base, result, self.candidate, self.metadata, mode="enterprise-state")
        result.config["config"]["Labels"].update({
            "org.dentinel.patch.mode": "enterprise-state", "org.dentinel.base.digest": self.base.digest,
        })
        with self.assertRaisesRegex(ValueError, "Replacement layer"):
            verify_publish(result)
        self.verifier.assert_not_called()

    def test_enterprise_preserves_startup_and_runtime_checks(self):
        result = self.rebuild()
        result.config["config"]["Env"] = ["PORT=9999"]
        with self.assertRaisesRegex(ValueError, "Runtime configuration"):
            verify_repack(self.base, result, self.candidate, self.metadata, mode="enterprise-state")
        missing = Image(make_image(self.root / "missing", [[entry(BINARY_PATH, elf())]]))
        result = repack(
            missing, self.candidate, self.metadata, self.root / "missing-result", mode="enterprise-state",
        )
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_repack(missing, result, self.candidate, self.metadata, mode="enterprise-state")
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_publish(result)
        self.verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
