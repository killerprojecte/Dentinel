from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from dentinel.common import json_bytes, sha256, write_json
from dentinel.oci import (
    BINARY_PATH, START_PATH, OCI_CONFIG, OCI_LAYER, OCI_MANIFEST, Image,
    archive_path, blob_path, pack_layout, put_blob, repack, unpack_layout,
    validate_elf, verify_repack,
)
from dentinel.patcher import IdentityPatcher, apply_identity
from dentinel import pipeline


def elf(payload=b"original"):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[18:20] = b"\x3e\x00"
    return bytes(header) + payload


def entry(name, data=b"", kind="file"):
    return name, data, kind


def make_image(root: Path, layers=None, *, arch="amd64", runtime=None):
    root.mkdir(parents=True)
    if layers is None:
        layers = [[entry(BINARY_PATH, elf()), entry(START_PATH, b"#!/bin/sh\nexec ./altcha-sentinel\n")]]
    descriptors, diffs = [], []
    for entries in layers:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                info.uid, info.gid, info.mode = 1001, 1001, 0o755
                info.uname, info.gname = "sentinel", "sentinel"
                if kind == "symlink":
                    info.type, info.linkname = tarfile.SYMTYPE, data.decode()
                elif kind == "hardlink":
                    info.type, info.linkname = tarfile.LNKTYPE, data.decode()
                elif kind == "dir":
                    info.type = tarfile.DIRTYPE
                elif kind == "device":
                    info.type = tarfile.CHRTYPE
                else:
                    info.size = len(data)
                archive.addfile(info, io.BytesIO(data) if kind == "file" else None)
        raw = buffer.getvalue()
        diffs.append("sha256:" + hashlib.sha256(raw).hexdigest())
        descriptors.append(put_blob(root, gzip.compress(raw, mtime=0), OCI_LAYER))
    config = {
        "architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": diffs},
        "config": runtime or {"Entrypoint": ["./start.sh"], "User": "0", "WorkingDir": "/sentinel/server", "Env": ["PORT=8080"], "Volumes": {"/data": {}}, "ExposedPorts": {"8080/tcp": {}}, "Labels": {"license.notice": "preserve-me"}},
        "history": [{"created_by": "fixture"} for _ in descriptors],
    }
    cfg = put_blob(root, json_bytes(config), OCI_CONFIG)
    manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": cfg, "layers": descriptors}
    desc = put_blob(root, json_bytes(manifest), OCI_MANIFEST)
    write_json(root / "index.json", {"schemaVersion": 2, "manifests": [desc]})
    write_json(root / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    return root


class OCITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def image(self, layers=None):
        return Image(make_image(self.root / "image", layers))

    def test_find_extract(self):
        image = self.image()
        record = image.find([BINARY_PATH])[BINARY_PATH]
        meta = image.extract(record, self.root / "binary")
        self.assertEqual((self.root / "binary").read_bytes(), elf())
        self.assertEqual(meta["uid"], 1001)
        self.assertEqual(meta["mode"], 0o755)

    def test_layer_override(self):
        image = self.image([[entry(BINARY_PATH, elf())], [entry(BINARY_PATH, elf(b"new"))]])
        record = image.find([BINARY_PATH])[BINARY_PATH]
        self.assertEqual(record.layer, 1)
        image.extract(record, self.root / "binary")
        self.assertEqual((self.root / "binary").read_bytes(), elf(b"new"))

    def test_whiteout_and_parent_whiteout(self):
        for whiteout in ("sentinel/server/.wh.altcha-sentinel", ".wh.sentinel"):
            with self.subTest(whiteout=whiteout), tempfile.TemporaryDirectory() as tmp:
                image = Image(make_image(Path(tmp) / "image", [[entry(BINARY_PATH, elf())], [entry(whiteout)]]))
                with self.assertRaisesRegex(ValueError, "missing"):
                    image.find([BINARY_PATH])

    def test_opaque_hides_previous_descendants(self):
        image = self.image([[entry(BINARY_PATH, elf())], [entry("sentinel/.wh..wh..opq")]])
        with self.assertRaisesRegex(ValueError, "missing"):
            image.find([BINARY_PATH])

    def test_same_layer_whiteout_does_not_hide_new_file(self):
        for entries in (
            [entry(BINARY_PATH, elf(b"new")), entry("sentinel/server/.wh..wh..opq")],
            [entry("sentinel/server/.wh.altcha-sentinel"), entry(BINARY_PATH, elf(b"new"))],
        ):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                image = Image(make_image(Path(tmp) / "image", [[entry(BINARY_PATH, elf())], entries]))
                self.assertEqual(image.find([BINARY_PATH])[BINARY_PATH].layer, 1)

    def test_dangerous_target_and_parent_links(self):
        cases = (
            [[entry(BINARY_PATH, b"elsewhere", "symlink")]],
            [[entry(BINARY_PATH, b"elsewhere", "hardlink")]],
            [[entry("sentinel", b"elsewhere", "symlink")], [entry(BINARY_PATH, elf())]],
            [[entry(BINARY_PATH, elf())], [entry("sentinel/server", b"elsewhere", "symlink")]],
            [[entry(BINARY_PATH, b"", "device")]],
        )
        for layers in cases:
            with self.subTest(layers=layers), tempfile.TemporaryDirectory() as tmp:
                image = Image(make_image(Path(tmp) / "image", layers))
                with self.assertRaises(ValueError):
                    image.find([BINARY_PATH])

    def test_directory_recreation_removes_old_children(self):
        image = self.image([[entry("sentinel", b"elsewhere", "symlink")], [entry("sentinel", kind="dir"), entry(BINARY_PATH, elf())]])
        self.assertEqual(image.find([BINARY_PATH])[BINARY_PATH].layer, 1)

    def test_archive_path_traversal(self):
        for path in ("../evil", "/evil", "a/../evil", "a\\evil", "C:evil", "bad\x00name"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                archive_path(path)
        self.assertEqual(archive_path("./a/b"), "a/b")

    def test_layer_traversal_and_duplicates_rejected(self):
        for entries in ([entry("../../evil")], [entry(BINARY_PATH, elf()), entry("./" + BINARY_PATH, elf())]):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                image = Image(make_image(Path(tmp) / "image", [entries]))
                with self.assertRaises(ValueError):
                    image.find([BINARY_PATH])

    def test_corrupt_compressed_blob_rejected(self):
        image = self.image()
        blob = blob_path(image.root, image.layers[0]["digest"])
        data = bytearray(blob.read_bytes())
        data[-1] ^= 1
        blob.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "Corrupt"):
            image.validate()

    def test_bad_diff_id_rejected(self):
        image = self.image()
        image.config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "diff_id"):
            image.find([BINARY_PATH])

    def test_wrong_platform_rejected(self):
        make_image(self.root / "arm", arch="arm64")
        with self.assertRaisesRegex(ValueError, "linux/amd64"):
            Image(self.root / "arm")

    def test_elf_checks(self):
        binary = self.root / "binary"
        binary.write_bytes(elf())
        validate_elf(binary)
        for header in (b"hello", elf().replace(b"\x3e\x00", b"\xb7\x00"), elf().replace(b"ELF\x02", b"ELF\x01")):
            binary.write_bytes(header)
            with self.assertRaises(ValueError):
                validate_elf(binary)

    def test_round_trip_metadata_and_determinism(self):
        base = self.image()
        metadata = base.extract(base.find([BINARY_PATH])[BINARY_PATH], self.root / "candidate")
        result = repack(base, self.root / "candidate", metadata, self.root / "result")
        report = verify_repack(base, result, self.root / "candidate", metadata)
        self.assertTrue(report["round_trip_verified"])
        self.assertFalse(report["functional_patch_applied"])
        other = repack(base, self.root / "candidate", metadata, self.root / "other")
        self.assertEqual(result.digest, other.digest)
        self.assertEqual(result.layers[-1], other.layers[-1])
        self.assertEqual(base.layers, result.layers[:-1])
        self.assertEqual(base.config["config"]["User"], result.config["config"]["User"])
        # Independent config/diff_id verification, not just the production verifier.
        raw = gzip.decompress(blob_path(result.root, result.layers[-1]["digest"]).read_bytes())
        self.assertEqual("sha256:" + hashlib.sha256(raw).hexdigest(), result.config["rootfs"]["diff_ids"][-1])
        before = blob_path(base.root, base.layers[0]["digest"]).read_bytes()
        blob_path(result.root, result.layers[0]["digest"]).write_bytes(b"bad")
        self.assertEqual(blob_path(base.root, base.layers[0]["digest"]).read_bytes(), before)

    def test_pack_and_safe_unpack(self):
        image = self.image()
        archive = self.root / "image.tar"
        pack_layout(image.root, archive)
        loaded = unpack_layout(archive, self.root / "restored")
        self.assertEqual(loaded.digest, image.digest)
        loaded.find([BINARY_PATH])

    def test_malicious_oci_archive_rejected(self):
        archive_path_ = self.root / "bad.tar"
        with tarfile.open(archive_path_, "w") as archive:
            info = tarfile.TarInfo("../evil")
            archive.addfile(info, io.BytesIO())
        with self.assertRaises(ValueError):
            unpack_layout(archive_path_, self.root / "restored")
        self.assertFalse((self.root / "restored").exists())

    def test_identity_failure_preserves_source(self):
        source = self.root / "original"
        source.write_bytes(elf())
        with self.assertRaises(ValueError):
            IdentityPatcher().apply(source, self.root / "candidate", "0" * 64)
        self.assertEqual(source.read_bytes(), elf())
        self.assertFalse((self.root / "candidate").exists())
        with self.assertRaises(ValueError):
            IdentityPatcher().apply(source, source, sha256(source))
        self.assertEqual(source.read_bytes(), elf())

    def test_identity_report(self):
        source = self.root / "original"
        source.write_bytes(elf())
        apply_identity(source, self.root / "candidate", sha256(source), self.root / "report.json")
        report = json.loads((self.root / "report.json").read_bytes())
        self.assertEqual(report["status"], "identity-only")
        self.assertFalse(report["functional_patch_applied"])

    def test_full_offline_pipeline(self):
        work = self.root / "work"
        image = Image(make_image(work / "upstream"))
        lock = {"source": "fixture", "digest": image.digest, "pinned": "example@" + image.digest, "platform": "linux/amd64"}
        write_json(work / "source-lock.json", lock)
        pipeline.extract(work / "upstream", work / "original", lock)
        pipeline.identity(work / "original", work / "patched")
        report = pipeline.rebuild(work)
        bundle = pipeline.analysis_bundle(work)
        self.assertTrue(report["round_trip_verified"])
        self.assertTrue((work / "dentinel.oci.tar").exists())
        with tarfile.open(bundle) as archive:
            self.assertEqual(archive.extractfile("original/altcha-sentinel").read(), elf())
            self.assertEqual(archive.getmember("original/altcha-sentinel").uid, 1001)
            self.assertIn("original/SHA256SUMS", archive.getnames())
        with self.assertRaises(FileExistsError):
            pipeline.identity(work / "original", work / "patched")
        with self.assertRaises(FileExistsError):
            pipeline.extract(work / "upstream", work / "original", lock)

    def test_extra_layer_entries_cannot_delete_startup(self):
        entries = [entry(BINARY_PATH, elf()), entry(START_PATH, b"#!/bin/sh\n")]
        base = self.image([entries])
        metadata = base.extract(base.find([BINARY_PATH])[BINARY_PATH], self.root / "candidate")
        evil = Image(make_image(self.root / "evil", [entries, [entry(BINARY_PATH, elf()), entry("sentinel/server/.wh.start.sh")]]))
        with self.assertRaisesRegex(ValueError, "Replacement layer"):
            verify_repack(base, evil, self.root / "candidate", metadata)


    def test_forged_identity_hash_is_bound_to_actual_base(self):
        base = self.image()
        metadata = base.extract(base.find([BINARY_PATH])[BINARY_PATH], self.root / "candidate")
        (self.root / "candidate").write_bytes(elf(b"replaced"))
        metadata["sha256"] = sha256(self.root / "candidate")
        result = repack(base, self.root / "candidate", metadata, self.root / "result")
        with self.assertRaisesRegex(ValueError, "actual base"):
            verify_repack(base, result, self.root / "candidate", metadata)
        from dentinel.oci import verify_publish
        with self.assertRaisesRegex(ValueError, "original binary bytes"):
            verify_publish(result)


    def test_publish_checks_all_diff_ids_and_identity(self):
        from dentinel.oci import verify_publish
        base = self.image()
        metadata = base.extract(base.find([BINARY_PATH])[BINARY_PATH], self.root / "candidate")
        result = repack(base, self.root / "candidate", metadata, self.root / "result")
        verify_publish(result)
        result.config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "diff_id"):
            verify_publish(result)


    def test_null_optional_config_fields(self):
        for null_runtime in (False, True):
            with self.subTest(null_runtime=null_runtime), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                base = Image(make_image(root / "base"))
                base.config["history"] = None
                if null_runtime:
                    base.config["config"] = None
                else:
                    base.config["config"]["Labels"] = None
                manifest = copy.deepcopy(base.manifest)
                manifest["config"] = put_blob(base.root, json_bytes(base.config), OCI_CONFIG)
                desc = put_blob(base.root, json_bytes(manifest), OCI_MANIFEST)
                write_json(base.root / "index.json", {"schemaVersion": 2, "manifests": [desc]}, replace=True)
                base = Image(base.root)
                metadata = base.extract(base.find([BINARY_PATH])[BINARY_PATH], root / "candidate")
                result = repack(base, root / "candidate", metadata, root / "result")
                self.assertTrue(verify_repack(base, result, root / "candidate", metadata)["round_trip_verified"])


    def test_tracking_inputs_validation(self):
        for url in ("http://example.com", "https://user:secret@example.com", "https://example.com\nmalicious"):
            with self.assertRaises(ValueError):
                pipeline.tracking_labels(url, None)
        with self.assertRaises(ValueError):
            pipeline.tracking_labels(None, "not-a-git-sha")


if __name__ == "__main__":
    unittest.main()
