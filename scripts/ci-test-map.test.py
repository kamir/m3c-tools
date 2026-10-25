#!/usr/bin/env python3
"""Positive and failing-side contracts for test discovery and CI assignment."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import yaml


SPEC = importlib.util.spec_from_file_location("ci_test_map", Path(__file__).with_name("ci-test-map.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(GATE.CONFIG.read_text())
        self.files = GATE.source_files(GATE.ROOT)
        self.packages = {"./" + str(Path(p).parent) for p in self.files
                         if p.endswith("_test.go") and "testdata" not in Path(p).parts}

    def test_current_mapping(self):
        self.assertEqual(GATE.mapping_errors(self.config, self.packages, self.files), [])

    def test_required_test_package_outside_lane_selection(self):
        self.config["lanes"]["unit"]["required_tests"]["./cmd/skillctl"] = ["TestRuntimeFingerprintActualCLI"]
        errors = GATE.mapping_errors(self.config, self.packages, self.files)
        self.assertIn("required Go test package outside lane selection: ./cmd/skillctl", errors)

    def test_new_go_package_requires_assignment(self):
        errors = GATE.mapping_errors(self.config, self.packages | {"./cmd/new-gate"}, self.files)
        self.assertIn("unassigned Go test package: ./cmd/new-gate", errors)
        self.config["lanes"]["release-tools"]["selectors"].append("./cmd/new-gate")
        self.assertEqual(GATE.mapping_errors(self.config, self.packages | {"./cmd/new-gate"}, self.files), [])

    def test_missing_mandatory_target(self):
        errors = GATE.mapping_errors(self.config, self.packages - {"./cmd/release-evidence"}, self.files)
        self.assertIn("missing mandatory target: ./cmd/release-evidence", errors)

    def test_removed_mandatory_selection(self):
        self.config["lanes"]["release-tools"]["selectors"].remove("./cmd/release-evidence")
        errors = GATE.mapping_errors(self.config, self.packages, self.files)
        self.assertIn("missing mandatory target: ./cmd/release-evidence", errors)

    def test_python_new_directory_and_nested_directory(self):
        for file in ["new-server/test_new.py", "mcp-skill-server/nested/test_new.py", "scripts/new.test.py"]:
            with self.subTest(file=file):
                errors = GATE.mapping_errors(self.config, self.packages, self.files | {file})
                self.assertIn("unassigned Python test: " + file, errors)

    def test_python_existing_server_discovers_new_file(self):
        self.assertEqual(GATE.mapping_errors(self.config, self.packages,
                                            self.files | {"mcp-skill-server/test_new.py"}), [])

    def test_missing_python_directory_fails(self):
        files = {p for p in self.files if not p.startswith("rag-mcp-server/")}
        self.assertIn("Python selection has no tests: rag-mcp-server",
                      GATE.mapping_errors(self.config, self.packages, files))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.config = json.loads(GATE.CONFIG.read_text())
        for name in [".github/workflows/ci.yml", ".github/workflows/pin-guard.yml",
                     "docs/security/required-checks.txt", "scripts/check-python.sh"]:
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(GATE.ROOT / name, dest)
        self.path = self.root / ".github/workflows/ci.yml"

    def mutate(self, operation):
        data = yaml.safe_load(self.path.read_text())
        operation(data)
        self.path.write_text(yaml.safe_dump(data))

    def test_current_wiring(self):
        self.assertEqual(GATE.workflow_errors(self.root, self.config), [])

    def test_removed_invocation_even_when_comment_mentions_it(self):
        def remove(data):
            steps = data["jobs"]["test"]["steps"]
            steps[:] = [s for s in steps if s.get("run") != "python3 scripts/ci-test-map.py run release-tools"]
        self.mutate(remove)
        with self.path.open("a") as output:
            output.write("\n# python3 scripts/ci-test-map.py run release-tools\n")
        self.assertTrue(any("missing or conditional invocation" in e
                            for e in GATE.workflow_errors(self.root, self.config)))

    def test_path_filter_and_job_conditions_fail(self):
        original = self.path.read_text()
        for operation in [lambda d: d[True].update(pull_request={"paths": ["cmd/**"]}),
                          lambda d: d["jobs"]["test"].update({"if": "false"}),
                          lambda d: d["jobs"]["test"].update(needs="lint"),
                          lambda d: d["jobs"]["test"].update({"continue-on-error": True})]:
            with self.subTest(operation=operation):
                self.path.write_text(original)
                self.mutate(operation)
                self.assertTrue(GATE.workflow_errors(self.root, self.config))

    def test_filtered_or_tolerated_mandatory_invocation_fails(self):
        original = self.path.read_text()
        for update in [{"if": "false"}, {"continue-on-error": True}]:
            self.path.write_text(original)
            def change(data):
                for step in data["jobs"]["test"]["steps"]:
                    if step.get("run") == "python3 scripts/ci-test-map.py run release-tools":
                        step.update(update)
            self.mutate(change)
            self.assertTrue(GATE.workflow_errors(self.root, self.config))

    def test_removed_python_invocation_fails(self):
        path = self.root / "scripts/check-python.sh"
        path.write_text(path.read_text().replace('  "$PYTHON" scripts/ci-test-map.py run python-rag', ""))
        self.assertIn("missing Python runner invocation: python-rag", GATE.workflow_errors(self.root, self.config))

    def test_removed_discovery_or_result_upload_fails(self):
        original = self.path.read_text()
        for predicate in [lambda s: s.get("run") == "python3 scripts/ci-test-map.py check",
                          lambda s: s.get("with", {}).get("path") == "test-results/"]:
            self.path.write_text(original)
            def remove(data):
                steps = data["jobs"]["python-gate"]["steps"]
                steps[:] = [s for s in steps if not predicate(s)]
            self.mutate(remove)
            self.assertTrue(GATE.workflow_errors(self.root, self.config))


class DiscoveryAndResultTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.env = patch.dict(os.environ, HOME=str(self.root), USERPROFILE=str(self.root),
                              GOCACHE=str(self.root / "cache"), GOPROXY="off", GOSUMDB="off",
                              GOTOOLCHAIN="local")
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_actual_go_metadata_platform_and_tag_discovery(self):
        (self.root / "go.mod").write_text("module example.test/fixture\n\ngo 1.26.0\n")
        for directory, constraint in [("normal", ""), ("windows-only", "//go:build windows\n\n"),
                                      ("tag-only", "//go:build allow_home_override_test\n\n")]:
            path = self.root / directory
            path.mkdir()
            (path / "one_test.go").write_text(constraint + "package fixture\nimport \"testing\"\nfunc TestOne(t *testing.T) {}\n")
        variants = [dict(goos="linux", goarch="amd64", cgo="0", tags="")]
        packages, _ = GATE.discover_go(self.root, variants)
        self.assertEqual(packages, {"./normal"})
        variants.append(dict(goos="windows", goarch="amd64", cgo="0", tags="allow_home_override_test"))
        packages, counts = GATE.discover_go(self.root, variants)
        self.assertEqual(packages, {"./normal", "./windows-only", "./tag-only"})
        self.assertEqual([len(found) for _, found in counts], [1, 3])
        config = dict(lanes={"fixture": dict(kind="go", selectors=["./normal"])}, exceptions=[], python_contracts=[])
        self.assertIn("unassigned Go test package: ./windows-only", GATE.mapping_errors(config, packages, set()))
        self.assertTrue(GATE.mapping_errors(config, {"./normal"}, {"tag-only/one_test.go"}))
        config["lanes"]["fixture"].update(selectors=["./..."], goos="linux")
        errors = GATE.mapping_errors(config, packages, set(), counts)
        self.assertIn("unassigned Go test package: ./windows-only", errors)
        self.assertIn("unassigned Go test package: ./tag-only", errors)

    def test_go_result_positive_and_negative_controls(self):
        path = self.root / "result.jsonl"
        event = dict(Package="example.test/fixture", Action="pass")
        rows = [dict(event, Action="start"), dict(event, Action="run", Test="TestOne"),
                dict(event, Test="TestOne"), event]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        GATE.validate_go(path, {"example.test/fixture"})
        for content in ["", "{", json.dumps(dict(event, Action="skip")),
                        json.dumps(dict(event, Action="fail")),
                        json.dumps(dict(event, Package="other"))]:
            with self.subTest(content=content):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    GATE.validate_go(path, {"example.test/fixture"})
        for rows in (
            [dict(event, Action="start"), event],
            [dict(event, Action="start"), dict(event, Action="run", Test="TestOne"),
             dict(event, Action="skip", Test="TestOne"), event],
        ):
            with self.subTest(rows=rows):
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                with self.assertRaises(ValueError):
                    GATE.validate_go(path, {"example.test/fixture"})
        path.unlink()
        with self.assertRaises(OSError):
            GATE.validate_go(path, {"example.test/fixture"})

    def test_required_scenarios_and_unexpected_skips(self):
        package = "github.com/kamir/m3c-tools/cmd/fixture"
        path = self.root / "result.jsonl"
        lane = dict(required_tests={"./cmd/fixture": ["TestRequired"]}, allow_test_skips=False)
        def write(names):
            rows = [dict(Package=package, Action="start")]
            for name, action in names:
                rows.extend([dict(Package=package, Test=name, Action="run"),
                             dict(Package=package, Test=name, Action=action)])
            rows.append(dict(Package=package, Action="pass"))
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        write([("TestRequired", "pass")])
        self.assertEqual(GATE.validate_go(path, {package}, lane), {"pass": 1, "fail": 0, "skip": 0})
        for names in ([('TestOther', 'pass')], [('TestOther', 'pass'), ('TestRequired', 'skip')],
                      [('TestRequired', 'pass'), ('TestUnexpected', 'skip')]):
            with self.subTest(names=names):
                write(names)
                with self.assertRaises(ValueError):
                    GATE.validate_go(path, {package}, lane)

    def test_python_runner_with_local_report_producer(self):
        # A local module exercises the subprocess/report boundary without
        # installing pytest or claiming that the real server suites ran.
        (self.root / "pytest.py").write_text('''
import os
from pathlib import Path
import sys
assert os.environ["HOME"] == os.environ["USERPROFILE"]
assert os.environ["HOME"] != os.environ["CI_OUTER_HOME"]
assert os.environ["M3C_TEST_KEYCHAIN"] == "0"
assert os.environ["M3C_TOKEN_STORE"] == "file"
path = Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml=")))
mode = os.environ["CI_FIXTURE_RESULT"]
if mode == "missing":
    pass
elif mode == "empty":
    path.write_text("<testsuites/>")
elif mode == "corrupt":
    path.write_text("<")
elif mode == "false-success":
    path.write_text('<testsuites><testsuite><testcase name="synthetic"><failure/></testcase></testsuite></testsuites>')
elif mode == "all-skipped":
    path.write_text('<testsuite><testcase name="synthetic"><skipped/></testcase></testsuite>')
elif mode == "suite-error":
    path.write_text('<testsuite errors="1"><error/><testcase name="synthetic"/></testsuite>')
else:
    path.write_text('<testsuites><testsuite><testcase name="synthetic"/></testsuite></testsuites>')
sys.exit(9 if mode == "failed" else 0)
''')
        lane = dict(kind="pytest", directory=str(self.root))
        results = self.root / "results"
        with patch.dict(os.environ, PYTHONPATH=str(self.root), CI_OUTER_HOME=str(self.root)):
            for mode, expected_code in [("pass", 0), ("missing", 1), ("empty", 1),
                                        ("corrupt", 1), ("failed", 9), ("false-success", 1),
                                        ("all-skipped", 1), ("suite-error", 1)]:
                with self.subTest(mode=mode), patch.dict(os.environ, CI_FIXTURE_RESULT=mode):
                    code = GATE.run_lane(GATE.ROOT, "fixture", lane, results)
                    self.assertEqual(code, expected_code)
                    record = json.loads((results / "fixture.meta.json").read_text())
                    self.assertEqual(record["runner_exit_code"], expected_code)
                    self.assertEqual(record["selection"], lane)
                    self.assertEqual(len(record["commit"]), 40)
                    if mode == "pass":
                        self.assertEqual(record["test_counts"], dict(total=1, skipped=0, failed=0))
                    if mode in ("missing", "empty", "corrupt", "false-success", "all-skipped", "suite-error"):
                        self.assertIn("validation_error", record)


if __name__ == "__main__":
    unittest.main()
