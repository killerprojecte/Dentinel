from __future__ import annotations

import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/publish.yml').read_text(encoding='utf-8')
        self.scripts = [textwrap.dedent(code) for code in re.findall(
            r"^          python - <<'PY'\n(.*?)^          PY$", self.workflow, re.M | re.S)]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.env = {
            'SOURCE': 'ghcr.io/altcha-org/sentinel:latest', 'PATCH_MODE': 'enterprise-state',
            'REQUESTED_TAG': '', 'REVISION': 'a' * 40, 'REPOSITORY_OWNER': 'killerprojecte',
            'RUN_ID': '123', 'RUN_ATTEMPT': '1', 'GITHUB_REPOSITORY': 'killerprojecte/Dentinel',
            'GITHUB_SHA': 'a' * 40, 'GITHUB_OUTPUT': str(root / 'output'),
            'GITHUB_STEP_SUMMARY': str(root / 'summary'),
            'TARGET': 'ghcr.io/killerprojecte/dentinel:test',
            'LATEST_TARGET': 'ghcr.io/killerprojecte/dentinel:latest',
            'EXPECTED_DIGEST': 'sha256:' + 'b' * 64,
        }

    def script(self, marker):
        matches = [code for code in self.scripts if marker in code]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def execute(self, code):
        with patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            exec(compile(code, '<workflow>', 'exec'), {})

    def test_embedded_scripts_support_runner_python_311(self):
        self.assertEqual(len(self.scripts), 4)
        for code in self.scripts:
            ast.parse(code, feature_version=(3, 11))

    def test_publish_is_guarded_to_master(self):
        self.assertIn('branches: [master]', self.workflow)
        self.assertIn("github.ref == 'refs/heads/master' && (github.event_name == 'push' || inputs.publish)", self.workflow)
        self.assertIn("inputs.patch_mode || 'enterprise-state'", self.workflow)
        self.assertIn("github.event_name == 'push' || (inputs.update_latest && inputs.publish)", self.workflow)
        self.assertIn('packages: write', self.workflow)

    def test_dispatch_inputs_accept_defaults_and_reject_unsafe_values(self):
        code = self.script("source = os.environ['SOURCE']")
        self.execute(code)
        for key, value in [('PATCH_MODE', 'unsafe'), ('REQUESTED_TAG', 'latest'),
                           ('REQUESTED_TAG', 'bad\nvalue'), ('REVISION', 'not-a-commit'),
                           ('SOURCE', 'invalid image'), ('REPOSITORY_OWNER', 'bad/owner')]:
            with self.subTest(key=key, value=value), patch.dict(self.env, {key: value}):
                with self.assertRaises(SystemExit):
                    self.execute(code)

    def test_metadata_uses_the_requested_repository_owner(self):
        code = self.script("report = json.loads(Path(")
        report = {'mode': 'enterprise-state', 'source_digest': 'sha256:' + 'c' * 64,
                  'image_digest': self.env['EXPECTED_DIGEST']}
        with patch.object(Path, 'read_text', return_value=json.dumps(report)):
            self.execute(code)
        outputs = Path(self.env['GITHUB_OUTPUT']).read_text(encoding='utf-8')
        self.assertIn('target=ghcr.io/killerprojecte/dentinel:s', outputs)
        self.assertIn('latest_target=ghcr.io/killerprojecte/dentinel:latest\n', outputs)
        self.assertIn('image_digest=' + self.env['EXPECTED_DIGEST'], outputs)

    def test_metadata_rejects_a_different_patch_mode(self):
        report = {'mode': 'identity'}
        with patch.object(Path, 'read_text', return_value=json.dumps(report)):
            with self.assertRaises(SystemExit):
                self.execute(self.script("report = json.loads(Path("))

    def test_stale_master_cannot_overwrite_latest(self):
        code = self.script("Skip latest:")
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout='d' * 40 + '\n')) as run:
            with self.assertRaises(SystemExit) as stopped:
                self.execute(code)
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][0], 'gh')

    def test_current_master_publishes_latest_with_verified_digest(self):
        code = self.script("Skip latest:")
        results = [SimpleNamespace(stdout=self.env['GITHUB_SHA'] + '\n'),
                   SimpleNamespace(stdout=self.env['EXPECTED_DIGEST'] + '\n')]
        with patch.object(subprocess, 'run', side_effect=results) as run:
            self.execute(code)
        self.assertEqual(run.call_count, 2)
        self.assertIn(self.env['LATEST_TARGET'], run.call_args.args[0])

    def test_publish_rejects_an_unexpected_registry_digest(self):
        code = self.script("'--target', os.environ['TARGET']")
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout='sha256:' + 'e' * 64)):
            with self.assertRaises(SystemExit):
                self.execute(code)


if __name__ == '__main__':
    unittest.main()
