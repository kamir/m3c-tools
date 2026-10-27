#!/usr/bin/env python3
"""Offline failures for the required native MCP runtime and unit producer."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_mcp_setup", ROOT / "scripts/setup-native-mcp-python.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class NativePrerequisites(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.directory = self.home / "mcp"
        self.output = self.home / "github-env"
        self.environment = mock.patch.dict(os.environ, {"GITHUB_ENV": str(self.output)}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        version = mock.patch.object(HELPER.sys, "version_info", HELPER.PYTHON_VERSION)
        version.start()
        self.addCleanup(version.stop)

    def successful(self, argv, **options):
        self.assertTrue(options["check"])
        self.assertGreater(options["timeout"], 0)
        if "venv" in argv:
            self.directory.mkdir()
        return subprocess.CompletedProcess(argv, 0, json.dumps({"python": list(HELPER.PYTHON_VERSION),
            **HELPER.runtime_pins(), "pytest": HELPER.PYTEST_VERSION}), "")

    def test_success_exports_only_after_import_and_inventory_checks(self):
        with mock.patch.object(HELPER.subprocess, "run", side_effect=self.successful) as run:
            executable = HELPER.provision(self.directory)
        self.assertEqual(len(run.call_args_list), 4)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("--isolated", commands[1])
        self.assertIn("--only-binary=:all:", commands[1])
        self.assertIn("https://pypi.org/simple", commands[1])
        self.assertIn("mcp==" + HELPER.runtime_pins()["mcp"], commands[1])
        self.assertEqual(commands[2][-1], HELPER.PREFLIGHT)
        self.assertEqual(self.output.read_text(), f"M3C_MCP_TEST_PYTHON={executable}\nM3C_REQUIRE_NATIVE_MCP_TESTS=1\n")

    def test_each_command_failure_does_not_export_runtime(self):
        for failed in range(4):
            if self.directory.exists():
                self.directory.rmdir()
            calls = 0

            def command(argv, **options):
                nonlocal calls
                index = calls
                calls += 1
                if index == failed:
                    raise subprocess.CalledProcessError(7, argv)
                return self.successful(argv, **options)

            with self.subTest(command=failed), mock.patch.object(HELPER.subprocess, "run", side_effect=command):
                with self.assertRaises(subprocess.CalledProcessError):
                    HELPER.provision(self.directory)
                self.assertFalse(self.output.exists())

    def test_bad_versions_and_unpinned_or_missing_runtime_deny(self):
        with mock.patch.object(HELPER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")):
            with self.assertRaises(ValueError):
                HELPER.provision(self.directory)
        self.assertFalse(self.output.exists())
        requirements = self.home / "requirements.txt"
        for text in ("mcp>=1.0\nPyYAML==6.0.3\n", "mcp==1.30.0\n", "mcp==1.30.0\nmcp==1.30.0\nPyYAML==6.0.3\n"):
            requirements.write_text(text)
            with mock.patch.object(HELPER, "REQUIREMENTS", requirements), mock.patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    HELPER.provision(self.directory)
                run.assert_not_called()

    def test_invalid_inputs_never_spawn_or_export(self):
        for path in ("relative", str(self.home), str(self.home / "bad\npath")):
            with self.subTest(path=path), mock.patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    HELPER.provision(path)
                run.assert_not_called()
        with mock.patch.object(HELPER.sys, "version_info", (3, 13, 0)), mock.patch.object(HELPER.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                HELPER.provision(self.directory)
            run.assert_not_called()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(HELPER.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                HELPER.provision(self.directory)
            run.assert_not_called()

    def test_explicit_wheelhouse_disables_index(self):
        wheels = self.home / "wheels"
        wheels.mkdir()
        with mock.patch.object(HELPER.subprocess, "run", side_effect=self.successful) as run:
            HELPER.provision(self.directory, wheels)
        argv = run.call_args_list[1].args[0]
        self.assertIn("--no-index", argv)
        self.assertNotIn("--index-url", argv)


class NativeUnitProducer(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.report = self.home / "native.xml"
        self.environment = mock.patch.dict(os.environ, dict(
            GITHUB_SHA="a" * 40, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2",
            GITHUB_JOB="drift-guard", M3C_MCP_TEST_PYTHON=sys.executable,
            M3C_REQUIRE_NATIVE_MCP_TESTS="1"), clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        platform = mock.patch.object(HELPER.sys, "platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)

    def xml(self, mutation=None):
        rows = [f'<testcase classname="{c["classname"]}" name="{c["name"]}"/>' for c in HELPER.UNIT_CASES]
        if mutation == "missing":
            rows.pop()
        elif mutation == "duplicate":
            rows.append(rows[0])
        elif mutation == "skip":
            rows[0] = rows[0][:-2] + "><skipped/></testcase>"
        elif mutation == "failed":
            rows[0] = rows[0][:-2] + "><failure/></testcase>"
        return "<testsuite>" + "".join(rows) + "</testsuite>"

    def test_actual_command_and_success_report_are_bound(self):
        def producer(argv, **options):
            self.assertEqual(argv[:5], [sys.executable, "-I", "-B", "-m", "pytest"])
            self.assertTrue(options["check"])
            self.assertEqual(options["cwd"], ROOT / "mcp-skill-server")
            for name in HELPER.UNIT_FILES:
                self.assertIn(name, argv)
            self.assertIn("test_native_skill_session.py", argv)
            self.assertIn("not test_native_agent_retained_session_stdio and not test_native_skill_retained_session_stdio and not test_native_git_retained_session_stdio", argv)
            self.report.write_text(self.xml())
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(HELPER.subprocess, "run", side_effect=producer):
            HELPER.run_native_units(self.report)
        metadata = json.loads(Path(str(self.report) + ".meta.json").read_text())
        self.assertEqual(metadata["commit"], "a" * 40)
        self.assertEqual(metadata["attempt"], "2")
        self.assertEqual(metadata["counts"], dict(total=7, skipped=0, failed=0))
        self.assertEqual(metadata["required_cases"], HELPER.UNIT_CASES)
        self.assertEqual(metadata["integration_requirements"], ["TestNativeAgentRetainedMCPSubprocess", "TestNativeSkillRetainedMCPSubprocess", "TestNativeGitRetainedMCPSubprocess"])
        self.assertEqual(metadata["excluded_cases"], ["test_native_agent_retained_session_stdio", "test_native_skill_retained_session_stdio", "test_native_git_retained_session_stdio"])

    def test_missing_skipped_duplicate_and_failed_cases_never_bind(self):
        for mode in ("missing", "skip", "duplicate", "failed", "absent", "process-failed"):
            self.report.unlink(missing_ok=True)

            def producer(argv, **options):
                if mode != "absent":
                    self.report.write_text(self.xml(mode))
                if mode == "process-failed":
                    raise subprocess.CalledProcessError(7, argv)
                return subprocess.CompletedProcess(argv, 0)

            with self.subTest(mode=mode), mock.patch.object(HELPER.subprocess, "run", side_effect=producer):
                with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                    HELPER.run_native_units(self.report)
            self.assertFalse(Path(str(self.report) + ".meta.json").exists())

    def test_stale_context_or_absent_required_runtime_never_executes(self):
        for key, value in (("GITHUB_SHA", ""), ("GITHUB_RUN_ID", "0"), ("GITHUB_JOB", "other"),
                           ("M3C_MCP_TEST_PYTHON", ""), ("M3C_REQUIRE_NATIVE_MCP_TESTS", "0")):
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}), mock.patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    HELPER.run_native_units(self.report)
                run.assert_not_called()
        self.report.write_text(self.xml())
        with mock.patch.object(HELPER.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                HELPER.run_native_units(self.report)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
