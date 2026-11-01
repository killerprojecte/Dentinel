from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dentinel.cli import DEFAULT_SOURCE, main
from dentinel.common import write_json
from dentinel.oci import Image, pack_layout
from dentinel import pipeline
from test_oci import make_image


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.image = Image(make_image(self.work / "upstream"))
        self.lock = {"source": DEFAULT_SOURCE, "digest": self.image.digest, "pinned": "ghcr.io/altcha-org/sentinel@" + self.image.digest, "platform": "linux/amd64"}
        write_json(self.work / "source-lock.json", self.lock)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(list(args))

    def test_existing_fetch_validates_without_network_or_tool(self):
        with patch("dentinel.tooling.ensure_crane", side_effect=AssertionError("No tool")), patch("dentinel.registry.resolve", side_effect=AssertionError("No resolution")):
            self.assertEqual(self.command("fetch", "--work", str(self.work)), 0)
            self.assertEqual(self.command("fetch", "--work", str(self.work), "--source", "other/image:tag"), 1)

    def test_failed_fetch_resumes_existing_pinned_lock(self):
        other = self.root / "resume"
        other.mkdir()
        write_json(other / "source-lock.json", self.lock)
        with patch("dentinel.tooling.ensure_crane", return_value=Path("crane")), patch("dentinel.registry.resolve", side_effect=AssertionError("Must reuse locked digest")), patch("dentinel.registry.pull") as pull:
            self.assertEqual(self.command("fetch", "--work", str(other)), 0)
            self.assertEqual(pull.call_args.args[1], self.lock)

    def test_offline_cli_commands_do_not_use_network_or_subprocess(self):
        with patch("socket.socket.connect", side_effect=AssertionError("No network")), patch("subprocess.run", side_effect=AssertionError("No process")):
            for command in ("extract", "identity", "repack", "verify", "bundle"):
                self.assertEqual(self.command(command, "--work", str(self.work)), 0, command)
            self.assertTrue((self.work / "analysis.tar.gz").is_file())

    def test_invalid_target_fails_before_reading_archive_or_bootstrap(self):
        with patch("dentinel.cli.unpack_layout", side_effect=AssertionError("Must reject target first")), patch("dentinel.tooling.ensure_crane", side_effect=AssertionError("Must not bootstrap")):
            self.assertEqual(self.command("publish", "--archive", "absent.tar", "--target", "evil.example/owner/dentinel:tag"), 1)

    def test_failed_publish_preflight_never_authenticates(self):
        archive = self.root / "upstream.tar"
        pack_layout(self.image.root, archive)
        with patch("dentinel.tooling.ensure_crane", side_effect=AssertionError("Must not bootstrap")), patch("dentinel.registry.publish", side_effect=AssertionError("Must not publish")):
            self.assertEqual(self.command("publish", "--archive", str(archive), "--target", "ghcr.io/owner/dentinel:tag"), 1)

    def test_identity_never_overwrites_existing_source_or_candidate(self):
        pipeline.extract(self.image.root, self.work / "original", self.lock)
        pipeline.identity(self.work / "original", self.work / "patched")
        original = (self.work / "original/altcha-sentinel").read_bytes()
        candidate = (self.work / "patched/altcha-sentinel").read_bytes()
        self.assertEqual(self.command("identity", "--work", str(self.work)), 1)
        self.assertEqual((self.work / "original/altcha-sentinel").read_bytes(), original)
        self.assertEqual((self.work / "patched/altcha-sentinel").read_bytes(), candidate)


if __name__ == "__main__":
    unittest.main()
