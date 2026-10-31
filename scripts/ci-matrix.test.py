#!/usr/bin/env python3
"""Exercise hosted-runner policy failures without scheduling any CI workload."""

import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

SCRIPT = Path(__file__).with_name("ci-matrix.py")
SPEC = importlib.util.spec_from_file_location("ci_matrix", SCRIPT)
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


def job(runner):
    return {"runs-on": runner, "timeout-minutes": 5, "steps": [{"run": "true"}]}


class HostedRunnerPolicyTests(unittest.TestCase):
    def test_reviewed_literal_labels(self):
        for label in MATRIX.HOSTED_RUNNERS:
            with self.subTest(label=label):
                self.assertEqual(MATRIX.runner_policy_error(job(label)), "")

    def test_custom_labels_groups_and_expressions_fail(self):
        for runner in ["self-hosted", "master2", "ubuntu-custom", "Ubuntu-latest",
                       ["self-hosted", "Linux"], ["ubuntu-latest"],
                       {"group": "private", "labels": "ubuntu-latest"},
                       "${{ inputs.runner }}", "${{ vars.RUNNER }}",
                       "${{ fromJSON(inputs.runner) }}", "${{ matrix.os || 'master2' }}",
                       None, True, 42]:
            with self.subTest(runner=runner):
                self.assertNotEqual(MATRIX.runner_policy_error(job(runner)), "")

    def test_axis_and_include_select_hosted_values(self):
        for matrix in [{"os": ["ubuntu-latest", "windows-latest"]},
                       {"include": [{"os": "macos-15"}, {"os": "ubuntu-24.04-arm"}]},
                       {"os": ["ubuntu-latest"], "include": [{"os": "macos-latest"}]}]:
            with self.subTest(matrix=matrix):
                candidate = job("${{ matrix.os }}")
                candidate["strategy"] = {"matrix": matrix}
                self.assertEqual(MATRIX.runner_policy_error(candidate), "")

    def test_matrix_indirection_and_overrides_fail(self):
        for matrix in ["${{ fromJSON(inputs.matrix) }}", None, [], {},
                       {"os": []}, {"os": "ubuntu-latest"},
                       {"os": ["ubuntu-latest", "master2"]},
                       {"os": ["ubuntu-latest", True]},
                       {"os": ["${{ vars.RUNNER }}"]},
                       {"include": []}, {"include": "ubuntu-latest"},
                       {"include": [{"os": "self-hosted"}]},
                       {"include": [{"os": {"group": "private"}}]},
                       {"include": [{"name": "missing runner"}]},
                       {"os": ["ubuntu-latest"], "include": [{"os": "master2"}]},
                       {"os": ["ubuntu-latest"], "include": [{"name": "missing runner"}]}]:
            with self.subTest(matrix=matrix):
                candidate = job("${{ matrix.os }}")
                candidate["strategy"] = {"matrix": matrix}
                self.assertNotEqual(MATRIX.runner_policy_error(candidate), "")

    def test_reusable_runner_is_not_locally_certified(self):
        candidate = {"uses": "owner/repo/.github/workflows/build.yml@v1"}
        self.assertEqual(MATRIX.runner_policy_error(candidate), "")
        candidate["runs-on"] = "self-hosted"
        self.assertNotEqual(MATRIX.runner_policy_error(candidate), "")

    def check_fixture(self, jobs, concurrency=True):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory, ".github", "workflows", "fixture.yml")
            workflow.parent.mkdir(parents=True)
            document = {"on": "pull_request", "jobs": jobs}
            if concurrency:
                document["concurrency"] = "fixture"
            workflow.write_text(yaml.safe_dump(document), encoding="utf-8")
            env = dict(os.environ, CI_MATRIX_ROOT=directory)
            return subprocess.run([sys.executable, str(SCRIPT), "--check"],
                                  env=env, text=True, capture_output=True, check=False)

    def test_actual_cli_rejects_new_job_on_private_worker(self):
        baseline = {"check": job("ubuntu-latest")}
        passed = self.check_fixture(baseline)
        self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
        mutated = copy.deepcopy(baseline)
        mutated["injected"] = job("master2")
        failed = self.check_fixture(mutated)
        self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
        self.assertIn("injected", failed.stdout)
        self.assertIn("reviewed hosted label", failed.stdout)

    def test_actual_cli_rejects_injected_matrix_worker(self):
        candidate = job("${{ matrix.os }}")
        candidate["strategy"] = {"matrix": {"include": [{"os": "ubuntu-latest"}]}}
        self.assertEqual(self.check_fixture({"check": candidate}).returncode, 0)
        candidate["strategy"]["matrix"]["include"].append({"os": "self-hosted"})
        failed = self.check_fixture({"check": candidate})
        self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
        self.assertIn("runner matrix value", failed.stdout)

    def test_empty_name_expansion_cannot_hide_unsafe_runner(self):
        for name in [None, "validate (${{ matrix.os }})"]:
            with self.subTest(name=name):
                candidate = job("${{ matrix.os }}")
                candidate["strategy"] = {"matrix": {
                    "os": [], "include": [{"os": "self-hosted"}],
                }}
                if name:
                    candidate["name"] = name
                failed = self.check_fixture({"check": candidate})
                self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
                self.assertIn("runner matrix axis", failed.stdout)

    def test_duplicate_runner_keys_rejected(self):
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.load("runs-on: ubuntu-latest\nruns-on: master2\n", Loader=MATRIX.StrictLoader)

    def test_missing_timeout_still_fails(self):
        candidate = job("ubuntu-latest")
        del candidate["timeout-minutes"]
        failed = self.check_fixture({"check": candidate})
        self.assertEqual(failed.returncode, 1)
        self.assertIn("timeout-minutes", failed.stdout)

    def test_missing_concurrency_still_fails(self):
        failed = self.check_fixture({"check": job("ubuntu-latest")}, concurrency=False)
        self.assertEqual(failed.returncode, 1)
        self.assertIn("concurrency group", failed.stdout)


if __name__ == "__main__":
    unittest.main()
