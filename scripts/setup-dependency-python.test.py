#!/usr/bin/env python3
"""Offline prerequisite and workflow contracts for dependency runtime tests."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/setup-dependency-python.py"
SPEC = importlib.util.spec_from_file_location("dependency_prerequisite", SCRIPT)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class PrerequisiteContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.directory = self.home / "fixture"
        self.output = self.home / "github-env"
        self.environment = mock.patch.dict(os.environ, {"GITHUB_ENV": str(self.output)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.version = mock.patch.object(HELPER.sys, "version_info", (3, 12, 14))
        self.version.start()
        self.addCleanup(self.version.stop)

    def successful_command(self, command, **kwargs):
        self.assertTrue(kwargs["check"])
        self.assertGreater(kwargs["timeout"], 0)
        if "venv" in command:
            self.directory.mkdir()
        return subprocess.CompletedProcess(command, 0, json.dumps({"python": [3, 12, 14], "packaging": "26.3"}), "")

    def test_success_publishes_only_checked_interpreter_and_strict_install(self):
        with mock.patch.object(HELPER.subprocess, "run", side_effect=self.successful_command) as run:
            executable = HELPER.provision(self.directory)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0], [sys.executable, "-I", "-m", "venv", str(self.directory)])
        for flag in ("--isolated", "--require-hashes", "--only-binary=:all:", "--no-deps", "--no-compile"):
            self.assertIn(flag, commands[1])
        self.assertEqual(commands[2][-1], HELPER.PREFLIGHT)
        self.assertEqual(self.output.read_text(), f"M3C_DEPENDENCY_TEST_PYTHON={executable}\n")
        self.assertEqual(executable.parent.name, "Scripts" if os.name == "nt" else "bin")

    def test_each_command_failure_never_publishes_interpreter(self):
        for failing in range(3):
            with self.subTest(command=failing):
                if self.directory.exists():
                    self.directory.rmdir()
                calls = 0

                def command(argv, **kwargs):
                    nonlocal calls
                    index = calls
                    calls += 1
                    if index == failing:
                        raise subprocess.CalledProcessError(7, argv)
                    return self.successful_command(argv, **kwargs)

                with mock.patch.object(HELPER.subprocess, "run", side_effect=command):
                    with self.assertRaises(subprocess.CalledProcessError):
                        HELPER.provision(self.directory)
                self.assertFalse(self.output.exists())
                self.assertEqual(calls, failing + 1)

    def test_wrong_preflight_and_missing_environment_output_refused(self):
        for payload in ({"python": [3, 13, 0], "packaging": "26.3"},
                        {"python": [3, 12, 14], "packaging": "0"}, {}):
            with self.subTest(payload=payload):
                with mock.patch.object(HELPER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                    with self.assertRaises(ValueError):
                        HELPER.provision(self.directory)
                self.assertFalse(self.output.exists())
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(HELPER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({"python": [3, 12, 14], "packaging": "26.3"}), "")):
                with self.assertRaises(ValueError):
                    HELPER.provision(self.directory)
        self.assertFalse(self.output.exists())

    def test_invalid_inputs_do_not_execute_tools(self):
        self.directory.mkdir()
        for path in (Path("relative"), self.directory, self.home / "bad\npath"):
            with self.subTest(path=path), mock.patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    HELPER.provision(path)
                run.assert_not_called()
        with mock.patch.object(HELPER.sys, "version_info", (3, 13, 0)), mock.patch.object(HELPER.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                HELPER.provision(self.home / "other")
            run.assert_not_called()

    def test_offline_wheelhouse_disables_index(self):
        wheelhouse = self.home / "wheels"
        wheelhouse.mkdir()
        with mock.patch.object(HELPER.subprocess, "run", side_effect=self.successful_command) as run:
            HELPER.provision(self.directory, wheelhouse)
        command = run.call_args_list[1].args[0]
        self.assertIn("--no-index", command)
        self.assertEqual(command[-1], str(wheelhouse.resolve()))

    def test_actual_cli_refuses_bad_arguments_without_publishing(self):
        env = dict(os.environ, HOME=str(self.home), USERPROFILE=str(self.home))
        for args, expected in (([], 2), (["--directory", "relative"], 1)):
            result = subprocess.run([sys.executable, str(SCRIPT), *args], env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertFalse(self.output.exists())


class WiringContracts(unittest.TestCase):
    def test_all_five_required_producers_have_pinned_prerequisite_before_tests(self):
        for workflow, jobs in (("ci.yml", ("test", "skillctl-race")), ("windows-gate.yml", ("windows-trust", "drift-guard")), ("coverage-gate.yml", ("coverage",))):
            data = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
            for name in jobs:
                with self.subTest(workflow=workflow, job=name):
                    job = data["jobs"][name]
                    self.assertFalse(job.get("continue-on-error", False))
                    steps = job["steps"]
                    setup = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/setup-python@"))
                    provision = next(i for i, s in enumerate(steps) if s.get("name") == "Provision dependency fixture Python")
                    if workflow == "ci.yml":
                        lane = "unit" if name == "test" else "security"
                        test = next(i for i, s in enumerate(steps) if "ci-test-map.py run " + lane in s.get("run", ""))
                    elif workflow == "coverage-gate.yml":
                        test = next(i for i, s in enumerate(steps) if "go test " in s.get("run", "") and "-coverprofile=" in s["run"])
                        self.assertIn("-count=1", steps[test]["run"])
                    else:
                        test = next(i for i, s in enumerate(steps) if "tee lin-trust.json" in s.get("run", "") or "Tee-Object -FilePath win-trust.json" in s.get("run", ""))
                    self.assertLess(setup, provision)
                    self.assertLess(provision, test)
                    self.assertEqual(steps[setup]["uses"], "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1")
                    self.assertEqual(steps[setup]["with"]["python-version"], "3.12.14")
                    self.assertEqual(steps[provision].get("if"), steps[test].get("if"))
                    self.assertFalse(steps[provision].get("continue-on-error", False))
                    self.assertEqual(steps[setup]['id'], 'dependency-python')
                    self.assertIn('${{ steps.dependency-python.outputs.python-path }}', steps[provision]['run'])
                    if name == "windows-trust":
                        self.assertIn("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }", steps[provision]["run"])
                    self.assertIn('scripts/setup-dependency-python.py --directory "${{ runner.temp }}/dependency-python"', steps[provision]["run"])

    def test_mandatory_python_identity_and_executable_contract_are_wired(self):
        selection = json.loads((ROOT / "scripts/ci-test-selection.json").read_text())
        for lane in ("unit", "security"):
            self.assertIn("TestPythonRuntimeFixture", selection["lanes"][lane]["required_tests"]["./pkg/skillctl/dependencies"])
            self.assertIn("TestGraphAggregateBudget", selection["lanes"][lane]["required_tests"]["./pkg/skillctl/dependencies"])
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        self.assertTrue(any(step.get("run") == "python3 scripts/setup-dependency-python.test.py" for step in workflow["jobs"]["python-gate"]["steps"]))
        self.assertTrue(any(contract.get("command") == "python3 scripts/setup-dependency-python.test.py" for contract in selection["python_contracts"]))
        requirement = (ROOT / "scripts/dependency-test-requirements.txt").read_text()
        self.assertIn("packaging==26.3 --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c", requirement)
        coverage = yaml.safe_load((ROOT / ".testcoverage.yml").read_text())
        floors = {entry["path"]: entry["threshold"] for entry in coverage["override"]}
        self.assertGreaterEqual(floors["^pkg/skillctl/dependencies$"], 83)


if __name__ == "__main__":
    unittest.main()
