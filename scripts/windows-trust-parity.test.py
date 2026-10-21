#!/usr/bin/env python3
"""Offline failure contracts for Linux trust execution and OS report parity."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/windows-trust-parity.py"


def event(name="TestSynthetic", action="pass", package="synthetic/pkg"):
    row = {"Action": action, "Package": package}
    if name is not None:
        row["Test"] = name
    return row


class ParityContracts(unittest.TestCase):
    def run_reports(self, linux, windows):
        with tempfile.TemporaryDirectory() as home:
            paths = []
            for name, rows in (("linux", linux), ("windows", windows)):
                path = Path(home) / f"{name}.json"
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                paths.append(str(path))
            env = dict(os.environ, HOME=home, USERPROFILE=home)
            return subprocess.run(
                [sys.executable, str(SCRIPT), *paths],
                env=env, capture_output=True, text=True, check=False,
            )

    def test_success_and_self_skip_remain_executed(self):
        linux = [event(), event("TestOptIn", "skip"), event(None)]
        windows = [event(), event("TestOptIn", "skip"), event(None)]
        result = self.run_reports(linux, windows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Linux executed tests:   2", result.stdout)

    def test_fail_events_reject_even_with_equal_counts(self):
        for os_name in ("linux", "windows"):
            for name in ("TestSynthetic", "TestSynthetic/subcase", None):
                with self.subTest(os=os_name, name=name):
                    good = [event(), event(None)]
                    bad = [event(), event(name, "fail")]
                    args = (bad, good) if os_name == "linux" else (good, bad)
                    result = self.run_reports(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("failed test/package", result.stderr)

    def test_malformed_terminal_identity_rejects_on_either_os(self):
        for os_name in ("linux", "windows"):
            for field in ("Test", "Package"):
                for value in ("", " \t\n", None, 7, []):
                    for action in ("pass", "skip"):
                        with self.subTest(os=os_name, field=field, value=value, action=action):
                            malformed = event(action=action)
                            malformed[field] = value
                            good, bad = [event()], [malformed]
                            args = (bad, good) if os_name == "linux" else (good, bad)
                            result = self.run_reports(*args)
                            self.assertEqual(result.returncode, 1)
                            self.assertIn("invalid terminal", result.stderr)

    def test_examples_and_subtest_names_remain_valid(self):
        rows = [event("ExampleSynthetic"), event("TestSynthetic/subcase", "skip")]
        result = self.run_reports(rows, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Linux executed tests:   2", result.stdout)

    def test_empty_either_side_rejects(self):
        for linux, windows in (([], []), ([], [event()]), ([event()], [])):
            with self.subTest(linux=linux, windows=windows):
                result = self.run_reports(linux, windows)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no executed tests", result.stderr)

    def test_package_only_or_nonobject_is_not_a_test_report(self):
        for rows in ([event(None)], [None], [[]]):
            with self.subTest(rows=rows):
                self.assertNotEqual(self.run_reports(rows, [event()]).returncode, 0)

    def test_gap_threshold_is_still_five(self):
        linux = [event(f"TestSynthetic{i}") for i in range(7)]
        for count, expected in ((2, 0), (1, 1), (8, 0)):
            with self.subTest(windows_count=count):
                windows = [event(f"TestSynthetic{i}") for i in range(count)]
                result = self.run_reports(linux, windows)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn("allowance: 5", result.stdout)

    def test_subtests_are_collapsed(self):
        result = self.run_reports(
            [event("TestSynthetic/a"), event("TestSynthetic/b"), event()],
            [event()],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Linux executed tests:   1", result.stdout)

    def test_missing_report_is_nonzero(self):
        with tempfile.TemporaryDirectory() as home:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(Path(home) / "missing"), "missing"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)


class WorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.safe_load((ROOT / ".github/workflows/windows-gate.yml").read_text())
        cls.job = cls.workflow["jobs"]["drift-guard"]
        cls.step = next(
            step for step in cls.job["steps"]
            if step.get("name") == "Linux run of the same trust set (-json)"
        )

    def test_required_linux_step_has_no_failure_override(self):
        self.assertEqual(self.job["name"], "Drift Guard (opt-out parity)")
        self.assertFalse(self.job.get("continue-on-error", False))
        self.assertFalse(self.step.get("continue-on-error", False))
        self.assertEqual(self.step["shell"], "bash")
        self.assertEqual(self.job["env"]["M3C_TOKEN_STORE"], "file")
        self.assertEqual(self.job["env"]["M3C_TEST_KEYCHAIN"], "0")

    def test_real_snippet_propagates_go_failure_through_successful_tee(self):
        for go_exit in (0, 7):
            with self.subTest(go_exit=go_exit), tempfile.TemporaryDirectory() as home:
                tools = Path(home) / "bin"
                tools.mkdir()
                fake_go = tools / "go"
                fake_go.write_text(
                    "#!/bin/sh\n"
                    'if [ "$1" = env ]; then printf "%s\\n" "$HOME/cache"; exit 0; fi\n'
                    'printf "%s\\n" "$*" > "$ARG_RECORD"\n'
                    'printf "%s\\n" "{\\\"Action\\\":\\\"pass\\\",\\\"Test\\\":\\\"TestSynthetic\\\",\\\"Package\\\":\\\"synthetic/pkg\\\"}"\n'
                    'exit "$FAKE_GO_EXIT"\n'
                )
                fake_go.chmod(0o700)
                record = Path(home) / "args"
                env = dict(
                    os.environ, HOME=home, USERPROFILE=home,
                    PATH=str(tools) + os.pathsep + os.environ["PATH"],
                    ARG_RECORD=str(record), FAKE_GO_EXIT=str(go_exit),
                    **self.job["env"],
                )
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", self.step["run"]],
                    cwd=home, env=env, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, go_exit, result.stderr)
                self.assertTrue((Path(home) / "lin-trust.json").read_text().strip())
                args = record.read_text().split()
                self.assertNotIn("-run", args)
                self.assertEqual(
                    [arg for arg in args if arg.startswith("./")],
                    ["./pkg/skillctl/...", "./cmd/skillctl/...", "./evaluation/..."],
                )

    def test_failure_contracts_are_wired_in_required_pin_guard(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pin-guard.yml").read_text())
        job = next(
            job for job in workflow["jobs"].values()
            if job.get("name") == "Enforce pinning + least-privilege + retention"
        )
        step = next(step for step in job["steps"] if step.get("run") == "python3 scripts/windows-trust-parity.test.py")
        self.assertFalse(step.get("continue-on-error", False))
        self.assertNotIn("if", step)


if __name__ == "__main__":
    unittest.main()
