from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from dentinel import tooling


def make_archive(entries: list[tuple[str, bytes | None]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in entries:
            entry = tarfile.TarInfo(name)
            if content is None:
                entry.type = tarfile.SYMTYPE
                entry.linkname = "outside"
                archive.addfile(entry)
            else:
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


class ToolingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name) / "cache"
        self.binary = b"verified mock crane executable"
        self.archive = make_archive([("crane", self.binary)])
        self.assets = {
            "Linux": (
                "go-containerregistry_Linux_x86_64.tar.gz",
                hashlib.sha256(self.archive).hexdigest(),
                "crane",
            )
        }
        for patcher in (
            mock.patch.object(tooling.platform, "system", return_value="Linux"),
            mock.patch.object(tooling.platform, "machine", return_value="x86_64"),
            mock.patch.object(tooling, "_ASSETS", self.assets),
            mock.patch.object(tooling.time, "sleep"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def download_mock(self):
        patcher = mock.patch.object(
            tooling.urllib.request, "urlopen", side_effect=lambda *a, **k: io.BytesIO(self.archive)
        )
        opened = patcher.start()
        self.addCleanup(patcher.stop)
        return opened

    def test_pinned_release_checksums(self) -> None:
        # Access the actual defaults rather than the fixture assets installed in setUp.
        source = Path(tooling.__file__).read_text(encoding="utf-8")
        self.assertIn("v0.20.6", source)
        self.assertIn("399491efa1d88d1ee18c6642d025aa0c67a49bfe8297033fb485b1272ad70c9d", source)
        self.assertIn("c1d593d01551f2c9a3df5ca0a0be4385a839bd9b86d4a76e18d7b17d16559127", source)

    def test_download_is_verified_atomic_and_does_not_change_path(self) -> None:
        opened = self.download_mock()
        previous_path = os.environ.get("PATH")
        executable = tooling.ensure_crane(self.cache)
        self.assertEqual(self.binary, executable.read_bytes())
        self.assertEqual(previous_path, os.environ.get("PATH"))
        self.assertEqual("crane", executable.name)
        self.assertEqual(1, opened.call_count)
        request = opened.call_args.args[0]
        self.assertIn("/v0.20.6/go-containerregistry_Linux_x86_64.tar.gz", request.full_url)
        self.assertGreater(opened.call_args.kwargs["timeout"], 0)
        metadata = json.loads((executable.parent / "verified.json").read_text())
        self.assertEqual(hashlib.sha256(self.binary).hexdigest(), metadata["executable_sha256"])
        self.assertFalse(list(executable.parent.glob(".download-*")))
        self.assertFalse(list(executable.parent.glob(".crane-*")))
        self.assertEqual(executable, tooling.ensure_crane(self.cache))
        self.assertEqual(1, opened.call_count)

    def test_executable_corruption_is_repaired_from_verified_archive(self) -> None:
        opened = self.download_mock()
        executable = tooling.ensure_crane(self.cache)
        executable.write_bytes(b"corrupted")
        metadata = executable.parent / "verified.json"
        record = json.loads(metadata.read_text())
        record["executable_sha256"] = hashlib.sha256(b"corrupted").hexdigest()
        metadata.write_text(json.dumps(record))
        self.assertEqual(executable, tooling.ensure_crane(self.cache))
        self.assertEqual(self.binary, executable.read_bytes())
        self.assertEqual(1, opened.call_count)

    def test_archive_is_revalidated_on_every_cache_use(self) -> None:
        opened = self.download_mock()
        executable = tooling.ensure_crane(self.cache)
        (executable.parent / self.assets["Linux"][0]).write_bytes(b"corrupt archive")
        tooling.ensure_crane(self.cache)
        self.assertEqual(2, opened.call_count)
        self.assertEqual(self.binary, executable.read_bytes())

    def test_invalid_cache_metadata_is_repaired(self) -> None:
        self.download_mock()
        executable = tooling.ensure_crane(self.cache)
        metadata = executable.parent / "verified.json"
        metadata.write_text("not JSON")
        tooling.ensure_crane(self.cache)
        self.assertEqual(hashlib.sha256(self.binary).hexdigest(), json.loads(metadata.read_text())["executable_sha256"])

    def test_bad_download_hash_never_installs_executable(self) -> None:
        with mock.patch.object(tooling.urllib.request, "urlopen", return_value=io.BytesIO(b"bad")):
            with self.assertRaisesRegex(RuntimeError, "SHA256"):
                tooling.ensure_crane(self.cache)
        self.assertFalse([path for path in self.cache.rglob("crane") if path.is_file()])
        self.assertFalse(list(self.cache.rglob(".download-*")))
        self.assertFalse(list(self.cache.rglob("*.tar.gz")))

    def test_network_failures_are_bounded_and_clean_up(self) -> None:
        with mock.patch.object(
            tooling.urllib.request, "urlopen", side_effect=urllib.error.URLError("timeout")
        ) as opened:
            with self.assertRaises(RuntimeError):
                tooling.ensure_crane(self.cache)
        self.assertEqual(3, opened.call_count)
        self.assertFalse(list(self.cache.rglob(".download-*")))

    def test_network_timeout_can_recover(self) -> None:
        with mock.patch.object(
            tooling.urllib.request, "urlopen", side_effect=[TimeoutError(), io.BytesIO(self.archive)]
        ) as opened:
            executable = tooling.ensure_crane(self.cache)
        self.assertEqual(self.binary, executable.read_bytes())
        self.assertEqual(2, opened.call_count)

    def test_download_total_deadline_is_enforced(self) -> None:
        self.download_mock()
        with mock.patch.object(tooling.time, "monotonic", side_effect=[0, 1000] * 3):
            with self.assertRaises(RuntimeError):
                tooling.ensure_crane(self.cache)
        self.assertFalse(list(self.cache.rglob(".download-*")))

    def test_only_the_selected_regular_file_is_extracted(self) -> None:
        self.archive = make_archive([("../outside", b"bad"), ("crane", self.binary), ("gcrane", b"unused")])
        self.assets["Linux"] = (self.assets["Linux"][0], hashlib.sha256(self.archive).hexdigest(), "crane")
        self.download_mock()
        executable = tooling.ensure_crane(self.cache)
        self.assertEqual(self.binary, executable.read_bytes())
        self.assertFalse((Path(self.temporary.name) / "outside").exists())
        self.assertFalse(list(self.cache.rglob("gcrane")))

    def test_symlink_duplicate_and_missing_executables_are_rejected(self) -> None:
        for entries in (
            [("crane", None)],
            [("crane", b"first"), ("./crane", b"second")],
            [("../crane", b"bad")],
            [("crane", b"")],
        ):
            with self.subTest(entries=entries):
                archive = self.cache.parent / "fixture.tar.gz"
                archive.write_bytes(make_archive(entries))
                with self.assertRaises(RuntimeError):
                    tooling._executable_from_archive(archive, "crane")

    def test_unsupported_architecture_is_rejected_before_network(self) -> None:
        with mock.patch.object(tooling.platform, "machine", return_value="aarch64"):
            with mock.patch.object(tooling.urllib.request, "urlopen") as opened:
                with self.assertRaises(RuntimeError):
                    tooling.ensure_crane(self.cache)
                opened.assert_not_called()

    def test_windows_asset_installs_exe(self) -> None:
        archive = make_archive([("crane.exe", self.binary)])
        with mock.patch.object(tooling.platform, "system", return_value="Windows"), mock.patch.object(
            tooling, "_ASSETS", {"Windows": ("windows.tar.gz", hashlib.sha256(archive).hexdigest(), "crane.exe")}
        ), mock.patch.object(tooling.urllib.request, "urlopen", return_value=io.BytesIO(archive)):
            executable = tooling.ensure_crane(self.cache)
        self.assertEqual("crane.exe", executable.name)
        self.assertEqual(self.binary, executable.read_bytes())


if __name__ == "__main__":
    unittest.main()
