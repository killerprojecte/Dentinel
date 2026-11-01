from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dentinel import registry

IMAGE_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
INDEX_DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST = "sha256:" + "b" * 64
OTHER_DIGEST = "sha256:" + "c" * 64
REPOSITORY = "ghcr.io/altcha-org/sentinel"


def descriptor(digest=IMAGE_DIGEST, architecture="amd64", operating_system="linux") -> dict:
    return {
        "mediaType": IMAGE_TYPE,
        "digest": digest,
        "size": 123,
        "platform": {"os": operating_system, "architecture": architecture},
    }


def image_manifest() -> dict:
    return {"schemaVersion": 2, "mediaType": IMAGE_TYPE, "config": {}, "layers": []}


def create_layout(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    blobs = path / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def blob(content: bytes, media_type: str) -> dict:
        digest = hashlib.sha256(content).hexdigest()
        (blobs / digest).write_bytes(content)
        return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(content)}

    config = blob(json.dumps({"os": "linux", "architecture": "amd64"}).encode(), CONFIG_TYPE)
    layer = blob(b"layer bytes", LAYER_TYPE)
    manifest = {
        "schemaVersion": 2,
        "mediaType": IMAGE_TYPE,
        "config": config,
        "layers": [layer],
    }
    selected = blob(json.dumps(manifest).encode(), IMAGE_TYPE)
    (path / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    (path / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [selected]}))
    return selected["digest"]


class ResolveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.crane = Path("verified-crane")
        self.source = REPOSITORY + ":latest"
        self.config = {"os": "linux", "architecture": "amd64"}

    def resolve_index(self, descriptors: list[dict]):
        index = {"schemaVersion": 2, "mediaType": INDEX_TYPE, "manifests": descriptors}
        commands = []

        def command(crane, arguments, **kwargs):
            self.assertEqual(self.crane, crane)
            commands.append(arguments)
            if arguments == ["digest", self.source]:
                return INDEX_DIGEST + "\n"
            if arguments == ["manifest", REPOSITORY + "@" + INDEX_DIGEST]:
                return json.dumps(index)
            if arguments == ["manifest", REPOSITORY + "@" + IMAGE_DIGEST]:
                return json.dumps(image_manifest())
            if arguments == ["config", "--platform", "linux/amd64", REPOSITORY + "@" + IMAGE_DIGEST]:
                return json.dumps(self.config)
            self.fail(f"Unexpected command: {arguments}")

        with mock.patch.object(registry, "_run", side_effect=command):
            result = registry.resolve(self.crane, self.source)
        return result, commands

    def test_selects_amd64_and_ignores_attestation(self) -> None:
        attestation = descriptor(OTHER_DIGEST, "unknown", "unknown")
        attestation["annotations"] = {"vnd.docker.reference.type": "attestation-manifest"}
        result, commands = self.resolve_index([descriptor(OTHER_DIGEST, "arm64"), attestation, descriptor()])
        self.assertEqual(self.source, result["source"])
        self.assertEqual(REPOSITORY + "@" + IMAGE_DIGEST, result["pinned"])
        self.assertEqual(IMAGE_DIGEST, result["digest"])
        self.assertEqual(INDEX_DIGEST, result["index_digest"])
        self.assertEqual("linux/amd64", result["platform"])
        self.assertEqual(["digest", self.source], commands[0])
        # In particular, no manifest/config command reads the moving tag again.
        self.assertTrue(all(self.source not in command for command in commands[1:]))
        self.assertEqual(["manifest", REPOSITORY + "@" + INDEX_DIGEST], commands[1])

    def test_attestation_marked_amd64_is_still_ignored(self) -> None:
        attestation = descriptor(OTHER_DIGEST)
        attestation["annotations"] = {"vnd.docker.reference.type": "attestation-manifest"}
        result, _ = self.resolve_index([attestation, descriptor()])
        self.assertEqual(IMAGE_DIGEST, result["digest"])

    def test_no_match_and_multiple_matches_fail(self) -> None:
        for candidates in ([], [descriptor(OTHER_DIGEST, "arm64")], [descriptor(), descriptor(OTHER_DIGEST)]):
            with self.subTest(candidates=candidates):
                with self.assertRaisesRegex(RuntimeError, "exactly one"):
                    self.resolve_index(candidates)

    def test_index_platform_is_checked_against_actual_image_config(self) -> None:
        self.config["architecture"] = "arm64"
        with self.assertRaisesRegex(RuntimeError, "config"):
            self.resolve_index([descriptor()])

    def test_single_manifest_requires_linux_amd64_config(self) -> None:
        for config in ({"os": "windows", "architecture": "amd64"}, {"os": "linux", "architecture": "arm64"}, {}):
            with self.subTest(config=config):
                with mock.patch.object(registry, "_run", side_effect=[IMAGE_DIGEST, json.dumps(image_manifest()), json.dumps(config)]):
                    with self.assertRaises(RuntimeError):
                        registry.resolve(self.crane, self.source)

    def test_single_manifest_resolves_and_has_no_index_digest(self) -> None:
        with mock.patch.object(registry, "_run", side_effect=[IMAGE_DIGEST, json.dumps(image_manifest()), json.dumps(self.config)]):
            result = registry.resolve(self.crane)
        self.assertEqual(registry.DEFAULT_SOURCE, result["source"])
        self.assertNotIn("index_digest", result)

    def test_digest_source_never_requeries_a_tag(self) -> None:
        source = REPOSITORY + ":historical@" + IMAGE_DIGEST
        with mock.patch.object(registry, "_run", side_effect=[json.dumps(image_manifest()), json.dumps(self.config)]) as run:
            result = registry.resolve(self.crane, source)
        self.assertEqual(2, run.call_count)
        self.assertEqual(["manifest", REPOSITORY + "@" + IMAGE_DIGEST], run.call_args_list[0].args[1])
        self.assertEqual(REPOSITORY + "@" + IMAGE_DIGEST, result["pinned"])

    def test_rejects_source_option_injection_and_malformed_references(self) -> None:
        for source in (
            "--help", "-v", "a\nb", "repo\x00", "repo\r:tag", "repo\t:tag", "repo with spaces",
            "https://ghcr.io/a/b:latest", "ghcr.io/a/../b", "ghcr.io/a/b:", "ghcr.io/a/b@sha256:abc",
            "ghcr.io/a/b@" + IMAGE_DIGEST.upper(), "repo@@" + IMAGE_DIGEST, "ghcr.io:99999/a/b",
        ):
            with self.subTest(source=source):
                with mock.patch.object(registry, "_run") as run:
                    with self.assertRaises(ValueError):
                        registry.resolve(self.crane, source)
                    run.assert_not_called()

    def test_reference_supports_ports_tags_and_docker_shorthand(self) -> None:
        self.assertEqual(("localhost:5000/team/image", None), registry._reference("localhost:5000/team/image:v1"))
        self.assertEqual(("index.docker.io/library/alpine", None), registry._reference("alpine:3"))
        self.assertEqual(("index.docker.io/library/alpine", IMAGE_DIGEST), registry._reference("docker.io/alpine@" + IMAGE_DIGEST))

    def test_invalid_digest_output_is_rejected(self) -> None:
        with mock.patch.object(registry, "_run", return_value="not a digest"):
            with self.assertRaises(ValueError):
                registry.resolve(self.crane, self.source)

    def test_artifact_or_malformed_manifest_is_rejected(self) -> None:
        for manifest in ({}, [], {**image_manifest(), "artifactType": "attestation"}):
            with self.subTest(manifest=manifest):
                with mock.patch.object(registry, "_run", side_effect=[IMAGE_DIGEST, json.dumps(manifest)]):
                    with self.assertRaises(RuntimeError):
                        registry.resolve(self.crane, self.source)


class TransferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.crane = Path("verified-crane")
        self.fixture = self.root / "fixture"
        self.digest = create_layout(self.fixture)
        self.pinned = REPOSITORY + "@" + self.digest
        self.lock = {"pinned": self.pinned, "digest": self.digest, "platform": "linux/amd64"}
        self.layout = self.root / "downloaded"
        self.target = "ghcr.io/example-owner/dentinel:patched-v1"
        patcher = mock.patch.object(registry.time, "sleep")
        patcher.start()
        self.addCleanup(patcher.stop)
        environment = mock.patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def mock_pull(self, crane, arguments, **kwargs):
        self.assertEqual(self.crane, crane)
        self.assertEqual(["pull", "--platform", "linux/amd64", "--format", "oci", self.pinned], arguments[:-1])
        self.assertNotEqual(str(self.layout), arguments[-1])
        self.assertGreater(kwargs["timeout"], 0)
        create_layout(Path(arguments[-1]))
        return ""

    def test_pull_installs_only_complete_verified_layout(self) -> None:
        with mock.patch.object(registry, "_run", side_effect=self.mock_pull) as run:
            registry.pull(self.crane, self.lock, self.layout)
        self.assertEqual(self.digest, registry._validate_layout(self.layout))
        self.assertEqual(1, run.call_count)
        self.assertFalse(list(self.root.glob(".dentinel-pull-*")))

    def test_pull_does_not_overwrite_existing_layout(self) -> None:
        self.layout.mkdir()
        marker = self.layout / "keep"
        marker.write_text("existing")
        with mock.patch.object(registry, "_run") as run:
            with self.assertRaises(FileExistsError):
                registry.pull(self.crane, self.lock, self.layout)
        run.assert_not_called()
        self.assertEqual("existing", marker.read_text())

    def test_pull_discards_half_download_before_retry(self) -> None:
        paths = []

        def download(crane, arguments, **kwargs):
            path = Path(arguments[-1])
            paths.append(path)
            if len(paths) == 1:
                (path / "partial").write_text("incomplete")
                raise RuntimeError("network error")
            self.assertFalse(paths[0].exists())
            self.assertFalse((path / "partial").exists())
            return self.mock_pull(crane, arguments, **kwargs)

        with mock.patch.object(registry, "_run", side_effect=download):
            registry.pull(self.crane, self.lock, self.layout)
        self.assertEqual(2, len(paths))
        self.assertNotEqual(paths[0], paths[1])
        self.assertFalse(list(self.root.glob(".dentinel-pull-*")))

    def test_failed_or_incomplete_pull_never_installs_layout(self) -> None:
        for side_effect in (RuntimeError("failed"), lambda *a, **k: ""):
            with self.subTest(side_effect=side_effect):
                with mock.patch.object(registry, "_run", side_effect=side_effect) as run:
                    with self.assertRaises(RuntimeError):
                        registry.pull(self.crane, self.lock, self.layout)
                self.assertEqual(3, run.call_count)
                self.assertFalse(self.layout.exists())
                self.assertFalse(list(self.root.glob(".dentinel-pull-*")))

    def test_pull_rejects_inconsistent_and_unpinned_locks(self) -> None:
        for changes in ({"digest": OTHER_DIGEST}, {"platform": "linux/arm64"}, {"pinned": REPOSITORY + ":latest"}):
            with self.subTest(changes=changes):
                with mock.patch.object(registry, "_run") as run:
                    with self.assertRaises(ValueError):
                        registry.pull(self.crane, {**self.lock, **changes}, self.layout)
                    run.assert_not_called()

    def test_pull_rejects_download_with_wrong_digest(self) -> None:
        with mock.patch.object(registry, "_run", side_effect=self.mock_pull):
            bad_lock = {**self.lock, "digest": OTHER_DIGEST, "pinned": REPOSITORY + "@" + OTHER_DIGEST}
            # Use a download independent of the lock-specific command assertion.
            with mock.patch.object(registry, "_run", side_effect=lambda c, a, **k: create_layout(Path(a[-1]))):
                with self.assertRaises(RuntimeError):
                    registry.pull(self.crane, bad_lock, self.layout)
        self.assertFalse(self.layout.exists())

    def test_publish_token_is_only_sent_via_stdin(self) -> None:
        secret = "ghp_super_secret_value"
        expected = "ghcr.io/example-owner/dentinel@" + self.digest
        with mock.patch.dict(os.environ, {"GHCR_USERNAME": "example-owner", "GHCR_TOKEN": secret}):
            with mock.patch.object(
                registry.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, "", ""), subprocess.CompletedProcess([], 0, expected + "\n", "")]
            ) as run:
                self.assertEqual(expected, registry.publish(self.crane, self.fixture, self.target))
        self.assertEqual(2, run.call_count)
        login = run.call_args_list[0]
        self.assertEqual([str(self.crane), "auth", "login", "ghcr.io", "--username", "example-owner", "--password-stdin"], login.args[0])
        self.assertEqual(secret + "\n", login.kwargs["input"])
        for call in run.call_args_list:
            self.assertNotIn(secret, str(call.args))
            self.assertNotIn("GHCR_TOKEN", call.kwargs["env"])
            self.assertNotIn("shell", call.kwargs)
            self.assertGreater(call.kwargs["timeout"], 0)
            self.assertEqual(subprocess.PIPE, call.kwargs["stderr"])
        self.assertIsNone(run.call_args_list[1].kwargs["input"])

    def test_publish_without_token_uses_existing_auth_configuration(self) -> None:
        expected = "ghcr.io/example-owner/dentinel@" + self.digest
        with mock.patch.object(registry, "_run", return_value=expected) as run:
            self.assertEqual(expected, registry.publish(self.crane, self.fixture, self.target))
        run.assert_called_once()
        self.assertEqual(["push", str(self.fixture.absolute()), self.target], run.call_args.args[1])

    def test_publish_rejects_unexpected_digest_output(self) -> None:
        for output in (OTHER_DIGEST, "ghcr.io/example-owner/dentinel@" + OTHER_DIGEST, "ghcr.io/wrong/dentinel@" + self.digest, "unexpected logs\n" + self.digest):
            with self.subTest(output=output):
                with mock.patch.object(registry, "_run", return_value=output):
                    with self.assertRaises((ValueError, RuntimeError)):
                        registry.publish(self.crane, self.fixture, self.target)

    def test_publish_requires_username_when_token_is_supplied(self) -> None:
        with mock.patch.dict(os.environ, {"GHCR_TOKEN": "secret"}):
            with mock.patch.object(registry, "_run") as run:
                with self.assertRaises(ValueError):
                    registry.publish(self.crane, self.fixture, self.target)
                run.assert_not_called()

    def test_publish_target_is_restricted_before_any_subprocess(self) -> None:
        for target in (
            "--help", "ghcr.io/example/sentinel:latest", "docker.io/example/dentinel:latest",
            "ghcr.io/example/nested/dentinel:latest", "ghcr.io/example/dentinel", "ghcr.io/example/dentinel:@bad",
            "ghcr.io/example/dentinel:bad\n", "ghcr.io/example/dentinel@" + self.digest,
        ):
            with self.subTest(target=target):
                with mock.patch.object(registry, "_run") as run:
                    with self.assertRaises(ValueError):
                        registry.publish(self.crane, self.fixture, target)
                    run.assert_not_called()

    def test_corrupt_blob_is_rejected_before_publish(self) -> None:
        index = json.loads((self.fixture / "index.json").read_text())
        digest = index["manifests"][0]["digest"].split(":")[1]
        blob = self.fixture / "blobs" / "sha256" / digest
        original = blob.read_bytes()
        blob.write_bytes(b"x" + original[1:])
        with mock.patch.object(registry, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "digest"):
                registry.publish(self.crane, self.fixture, self.target)
            run.assert_not_called()

    def test_subprocess_failures_do_not_leak_secret_output(self) -> None:
        secret = "secret-must-not-leak"
        with mock.patch.object(registry.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, secret, secret)) as run:
            with self.assertRaises(RuntimeError) as caught:
                registry._run(self.crane, ["auth", "login"], input_text=secret)
        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(3, run.call_count)

    def test_subprocess_timeout_retries_are_bounded_and_redacted(self) -> None:
        secret = "secret-must-not-leak"
        failure = subprocess.TimeoutExpired(["crane"], 1, output=secret, stderr=secret)
        with mock.patch.object(registry.subprocess, "run", side_effect=failure) as run:
            with self.assertRaises(RuntimeError) as caught:
                registry._run(self.crane, ["auth", "login"], input_text=secret)
        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(3, run.call_count)


if __name__ == "__main__":
    unittest.main()
