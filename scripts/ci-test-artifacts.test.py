#!/usr/bin/env python3
"""Execution and provenance counterexamples for the required artifact consumer."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from xml.etree import ElementTree as ET

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_artifacts", ROOT / "scripts/ci-test-artifacts.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ArtifactContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.config = json.loads((ROOT / "scripts/ci-test-selection.json").read_text())
        self.context = dict(commit="c" * 40, run_id="123", attempt="2")
        self.needs = {name: dict(result="success", outputs={}) for name in GATE.PRODUCERS}
        self.needs["test"]["outputs"]["code"] = "true"
        self.paths = {}
        self.populate()

    def populate(self):
        for name, lane in GATE.expected_lanes(self.config, self.needs).items():
            folder = self.root / f"test-records-{lane['job']}-{'c' * 40}-123-2"
            folder.mkdir(exist_ok=True)
            raw = folder / (name + (".jsonl" if lane["kind"] == "go" else ".xml"))
            meta = dict(self.context, github_sha=self.context["commit"], lane=name, job=lane["job"],
                        selection=lane, exit_code=0, runner_exit_code=0,
                        platform=[lane.get("goos", "linux"), "amd64"], toolchain="fixture toolchain")
            if lane["kind"] == "go":
                expected = lane.get("mandatory") or [s[:-4] + "/fixture" if s.endswith("/...") else s.rstrip("/")
                                                       for s in lane["selectors"]]
                expected = sorted(set(expected) | set(lane.get("required_tests", {})))
                packages = [GATE.MODULE + p[1:] for p in expected]
                rows = []
                for package in packages:
                    names = lane.get("required_tests", {}).get("." + package.removeprefix(GATE.MODULE), ["TestFixture"])
                    # Keep package success independent of every required-case mutation.
                    names = [*names, "TestUnrelatedFixture"]
                    rows.append(dict(Package=package, Action="start"))
                    for case_name in names:
                        rows.extend([dict(Package=package, Test=case_name, Action="run"),
                                     dict(Package=package, Test=case_name, Action="pass")])
                    rows.append(dict(Package=package, Action="pass"))
                raw.write_text("".join(json.dumps(e) + "\n" for e in rows))
                meta["expected_test_packages"] = packages
                meta["test_terminal_counts"] = {"pass": sum(e["Action"] == "pass" and "Test" in e for e in rows),
                                                "skip": 0, "fail": 0}
            else:
                suite = ET.Element("testsuite")
                required = lane.get("required_cases") or [dict(classname="fixture", name="fixture")]
                for identity in required:
                    ET.SubElement(suite, "testcase", identity)
                raw.write_bytes(ET.tostring(suite))
                meta["test_counts"] = dict(total=len(required), skipped=0, failed=0)
            meta["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
            path = folder / (name + ".meta.json")
            path.write_text(json.dumps(meta))
            (folder / (name + ".log")).write_text("")
            self.paths[name] = raw, path

    def run_gate(self):
        return GATE.verify(self.root, self.config, self.needs, self.context)

    def mutate_meta(self, name, operation):
        path = self.paths[name][1]
        meta = json.loads(path.read_text())
        operation(meta)
        path.write_text(json.dumps(meta))

    def test_all_expected_lanes_pass(self):
        self.assertEqual(set(self.run_gate()), set(self.config["lanes"]))

    def test_required_python_case_cannot_hide_behind_passing_other_cases(self):
        raw, meta_path = self.paths["python-mcp"]
        original, metadata = raw.read_bytes(), meta_path.read_bytes()
        for identity in self.config["lanes"]["python-mcp"]["required_cases"]:
            for mode in ("missing", "skip", "duplicate", "foreign_class"):
                with self.subTest(mode=mode):
                    suite = ET.Element("testsuite")
                    ET.SubElement(suite, "testcase", dict(classname="other", name="passing_control"))
                    for other in self.config["lanes"]["python-mcp"]["required_cases"]:
                        if other != identity:
                            ET.SubElement(suite, "testcase", dict(other))
                    if mode != "missing":
                        attrs = dict(identity)
                        if mode == "foreign_class":
                            attrs["classname"] = "other"
                        case = ET.SubElement(suite, "testcase", attrs)
                        if mode == "skip":
                            ET.SubElement(case, "skipped")
                        if mode == "duplicate":
                            ET.SubElement(suite, "testcase", attrs)
                    raw.write_bytes(ET.tostring(suite))
                    meta = json.loads(metadata)
                    meta["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
                    meta["test_counts"] = GATE.python_counts(raw.read_bytes())
                    meta_path.write_text(json.dumps(meta))
                    with self.assertRaisesRegex(ValueError, "required Python case"):
                        self.run_gate()
                    command = [sys.executable, str(ROOT / "scripts/ci-test-artifacts.py"), str(self.root)]
                    for key, value in self.context.items():
                        command.extend(["--" + key.replace("_", "-"), value])
                    environment = dict(os.environ, TEST_PRODUCER_RESULTS=json.dumps(self.needs))
                    result = subprocess.run(command, env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("required Python case", result.stderr)
        raw.write_bytes(original)
        meta_path.write_bytes(metadata)
        self.assertEqual(set(self.run_gate()), set(self.config["lanes"]))

    def test_mcp_bridge_identity_from_directory_producer(self):
        # The real lane runs pytest with cwd=mcp-skill-server, not repo root.
        # Keep this producer identity independent of catalog-generated fixtures.
        raw, metadata_path = self.paths["python-mcp"]
        report = ('<testsuite tests="3" errors="0" failures="0" skipped="0">'
                  '<testcase classname="test_other" name="passing_control"/>'
                  '<testcase classname="test_enterprise_profile" '
                  'name="test_real_cli_enterprise_profile_and_stdio"/>'
                  '<testcase classname="test_native_enterprise_profile" '
                  'name="test_native_enterprise_profile_denied_before_exec"/></testsuite>')
        raw.write_text(report)
        metadata = json.loads(metadata_path.read_text())
        metadata["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
        metadata["test_counts"] = GATE.python_counts(raw.read_bytes())
        metadata_path.write_text(json.dumps(metadata))
        self.assertIn("python-mcp", self.run_gate())
        # A repo-root name must fail even when producer selection and digest
        # metadata are rebound consistently to that incorrect catalog value.
        wrong_lane = self.config["lanes"]["python-mcp"]
        wrong_lane["required_cases"][0]["classname"] = "mcp-skill-server.test_enterprise_profile"
        metadata["selection"] = wrong_lane
        metadata_path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, "required Python case"):
            self.run_gate()

    def test_required_python_identity_configuration_is_strict(self):
        valid = dict(classname="suite", name="case")
        report = '<testsuite><testcase classname="suite" name="case"/></testsuite>'
        for required in (False, {}, [None], [dict(name="case")], [dict(valid, extra="x")],
                         [dict(valid, classname="")], [valid, valid]):
            with self.subTest(required=required), self.assertRaisesRegex(ValueError, "Python identit"):
                GATE.python_counts(report, required)
        self.assertEqual(GATE.python_counts(report, [valid]), dict(total=1, skipped=0, failed=0))

    def test_missing_artifact_or_lane_file_rejected(self):
        for which in ("raw", "meta", "log", "folder"):
            with self.subTest(which=which):
                raw, meta = self.paths["release-tools"]
                path = dict(raw=raw, meta=meta, log=raw.with_suffix(".log"), folder=raw.parent)[which]
                saved = path.with_name(path.name + ".moved")
                path.rename(saved)
                with self.assertRaises(ValueError):
                    self.run_gate()
                saved.rename(path)

    def test_log_directory_is_not_evidence(self):
        path = self.paths["release-tools"][0].with_suffix(".log")
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(ValueError, "non-file"):
            self.run_gate()

    def test_every_producer_must_succeed(self):
        for job in GATE.PRODUCERS:
            for result in ("failure", "skipped", "cancelled", "timed_out", None):
                with self.subTest(job=job, result=result):
                    original = self.needs[job]["result"]
                    self.needs[job]["result"] = result
                    with self.assertRaises(ValueError):
                        self.run_gate()
                    self.needs[job]["result"] = original

    def test_binding_and_producer_metadata_rejected(self):
        path = self.paths["release-tools"][1]
        original = path.read_bytes()
        for field, value in (("commit", "d" * 40), ("github_sha", "d" * 40),
                             ("run_id", "124"), ("attempt", "1"), ("job", "foreign"),
                             ("lane", "foreign"), ("selection", {}), ("exit_code", 7),
                             ("runner_exit_code", 1), ("exit_code", False),
                             ("platform", ["linux", "amd64"]), ("toolchain", "")):
            with self.subTest(field=field, value=value):
                self.mutate_meta("release-tools", lambda m: m.update({field: value}))
                with self.assertRaises(ValueError):
                    self.run_gate()
                path.write_bytes(original)

    def test_digest_and_report_validation_rejects_tampering(self):
        raw, meta = self.paths["release-tools"]
        original = raw.read_bytes()
        raw.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.run_gate()
        for content in (b"", b"{", b'{"Action":"fail","Package":"fixture"}\n'):
            with self.subTest(content=content):
                raw.write_bytes(content)
                self.mutate_meta("release-tools", lambda m: m.update(result_sha256=hashlib.sha256(content).hexdigest()))
                with self.assertRaises(ValueError):
                    self.run_gate()
        raw.write_bytes(original)

    def test_success_without_executed_tests_and_all_skip_rejected(self):
        raw, _ = self.paths["release-tools"]
        rows = [json.loads(line) for line in raw.read_text().splitlines()]
        for skip in (False, True):
            with self.subTest(all_skip=skip):
                changed = copy.deepcopy(rows)
                if skip:
                    for row in changed:
                        if "Test" in row and row["Action"] == "pass":
                            row["Action"] = "skip"
                else:
                    changed = [row for row in changed if "Test" not in row]
                raw.write_text("".join(json.dumps(row) + "\n" for row in changed))
                self.mutate_meta("release-tools", lambda m: m.update(result_sha256=hashlib.sha256(raw.read_bytes()).hexdigest()))
                with self.assertRaises(ValueError):
                    self.run_gate()

    def test_only_declared_optional_skips_are_allowed(self):
        lane = self.config["lanes"]["e2e-offline"]
        package = GATE.MODULE + "/e2e"
        raw, _ = self.paths["e2e-offline"]
        original = raw.read_text()
        allowed_name = next(iter(lane["allowed_test_skips"]["./e2e"]))
        for name, should_pass in ((allowed_name, True), ("TestUnexpectedSkip", False),
                                  (lane["required_tests"]["./e2e"][0], False)):
            with self.subTest(name=name):
                rows = [json.loads(line) for line in original.splitlines()]
                rows = [r for r in rows if r.get("Test") != name]
                rows[-1:-1] = [dict(Package=package, Test=name, Action="run"),
                               dict(Package=package, Test=name, Action="skip")]
                raw.write_text("".join(json.dumps(row) + "\n" for row in rows))
                counts = {"pass": sum(r["Action"] == "pass" and "Test" in r for r in rows), "skip": 1, "fail": 0}
                self.mutate_meta("e2e-offline", lambda m: m.update(result_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
                                                                  test_terminal_counts=counts))
                if should_pass:
                    self.run_gate()
                else:
                    with self.assertRaises(ValueError):
                        self.run_gate()

    def test_python_failure_and_all_skip_rejected(self):
        raw, meta = self.paths["python-mcp"]
        for child in ("failure", "error", "skipped"):
            with self.subTest(child=child):
                raw.write_text(f'<testsuites><testsuite><testcase><{child}/></testcase></testsuite></testsuites>')
                self.mutate_meta("python-mcp", lambda m: m.update(result_sha256=hashlib.sha256(raw.read_bytes()).hexdigest()))
                with self.assertRaises(ValueError):
                    self.run_gate()

    def test_junit_identity_suite_failures_and_totals(self):
        for report in (
            '<testsuites><testsuite><testcase/></testsuite></testsuites>',
            '<testsuite errors="1"><testcase name="x"/></testsuite>',
            '<testsuite><error/><testcase name="x"/></testsuite>',
            '<testsuite tests="2"><testcase name="x"/></testsuite>',
            '<other><testcase name="x"/></other>',
        ):
            with self.subTest(report=report), self.assertRaises(ValueError):
                GATE.python_counts(report)
        self.assertEqual(GATE.python_counts('<testsuite tests="1" errors="0"><testcase name="x"/></testsuite>'),
                         dict(total=1, skipped=0, failed=0))

    def test_prior_attempt_artifacts_require_all_producers_to_rerun(self):
        self.context["attempt"] = "3"
        with self.assertRaisesRegex(ValueError, "producer artifact"):
            self.run_gate()

    def test_prose_only_scope_is_explicit(self):
        self.needs["test"]["outputs"]["code"] = "false"
        for name in ("unit", "e2e-offline", "security"):
            raw, meta = self.paths[name]
            raw.unlink()
            meta.unlink()
            raw.with_suffix(".log").unlink()
            if not list(raw.parent.iterdir()):
                raw.parent.rmdir()
        verified = self.run_gate()
        self.assertEqual(set(verified), set(self.config["lanes"]) - {"unit", "e2e-offline", "security"})

    def test_unknown_classification_conditions_and_needs_fail(self):
        for value in (None, "", "False", "maybe"):
            with self.subTest(value=value):
                self.needs["test"]["outputs"]["code"] = value
                with self.assertRaises(ValueError):
                    self.run_gate()
        self.needs["test"]["outputs"]["code"] = "true"
        self.config["lanes"]["unit"]["step_if"] = "false"
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_duplicate_metadata_and_wrong_counts_fail(self):
        path = self.paths["release-tools"][1]
        original = path.read_text()
        path.write_text(original[:-1] + ', "exit_code":0}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_gate()
        path.write_text(original)
        self.mutate_meta("release-tools", lambda m: m.update(test_terminal_counts={"pass": 999}))
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_cli_failure_is_nonzero(self):
        env = dict(os.environ, TEST_PRODUCER_RESULTS=json.dumps(self.needs))
        args = [sys.executable, str(ROOT / "scripts/ci-test-artifacts.py"), str(self.root),
                "--commit", self.context["commit"], "--run-id", "123", "--attempt", "2"]
        good = subprocess.run(args, env=env, capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.paths["release-tools"][0].unlink()
        bad = subprocess.run(args, env=env, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)

    def test_dependency_python_required_in_both_mac_lanes_actual_cli(self):
        env = dict(os.environ, TEST_PRODUCER_RESULTS=json.dumps(self.needs))
        args = [sys.executable, str(ROOT / "scripts/ci-test-artifacts.py"), str(self.root),
                "--commit", self.context["commit"], "--run-id", "123", "--attempt", "2"]
        good = subprocess.run(args, env=env, capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        for selected in ("TestPythonRuntimeFixture", "TestWindowsMarkerEnvironment"):
            for lane in ("unit", "security"):
                raw, metadata = self.paths[lane]
                original_raw, original_metadata = raw.read_bytes(), metadata.read_bytes()
                for action in ("skip", "missing"):
                    with self.subTest(selected=selected, lane=lane, action=action):
                        rows = [json.loads(line) for line in original_raw.splitlines()]
                        if action == "missing":
                            rows = [r for r in rows if r.get("Test") != selected]
                        else:
                            next(r for r in rows if r.get("Test") == selected and r["Action"] == "pass")["Action"] = "skip"
                        raw.write_text("".join(json.dumps(r) + "\n" for r in rows))
                        meta = json.loads(original_metadata)
                        meta["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
                        meta["test_terminal_counts"] = {
                            status: sum(r["Action"] == status and "Test" in r for r in rows)
                            for status in ("pass", "skip", "fail")
                        }
                        metadata.write_text(json.dumps(meta))
                        bad = subprocess.run(args, env=env, capture_output=True, text=True)
                        self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
                        self.assertIn("mandatory Go scenario", bad.stderr)
                        raw.write_bytes(original_raw)
                        metadata.write_bytes(original_metadata)

    def test_dependency_graph_budget_required_in_both_mac_lanes_actual_cli(self):
        env = dict(os.environ, TEST_PRODUCER_RESULTS=json.dumps(self.needs))
        args = [sys.executable, str(ROOT / "scripts/ci-test-artifacts.py"), str(self.root),
                "--commit", self.context["commit"], "--run-id", "123", "--attempt", "2"]
        good = subprocess.run(args, env=env, capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        for lane in ("unit", "security"):
            raw, metadata = self.paths[lane]
            original_raw, original_metadata = raw.read_bytes(), metadata.read_bytes()
            for action in ("skip", "missing"):
                with self.subTest(lane=lane, action=action):
                    rows = [json.loads(line) for line in original_raw.splitlines()]
                    if action == "missing":
                        rows = [r for r in rows if r.get("Test") != "TestGraphAggregateBudget"]
                    else:
                        next(r for r in rows if r.get("Test") == "TestGraphAggregateBudget" and r["Action"] == "pass")["Action"] = "skip"
                    raw.write_text("".join(json.dumps(r) + "\n" for r in rows))
                    meta = json.loads(original_metadata)
                    meta["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
                    meta["test_terminal_counts"] = {
                        status: sum(r["Action"] == status and "Test" in r for r in rows)
                        for status in ("pass", "skip", "fail")
                    }
                    metadata.write_text(json.dumps(meta))
                    bad = subprocess.run(args, env=env, capture_output=True, text=True)
                    self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
                    self.assertIn("mandatory Go scenario", bad.stderr)
                    raw.write_bytes(original_raw)
                    metadata.write_bytes(original_metadata)

    def test_project_guards_required_with_correct_rebound_metadata_actual_cli(self):
        probes = (
            ("unit", "TestSessionRecheckStaleFloorPreventsClockRecovery"),
            ("unit", "TestProjectProfileSnapshotsAndSelection"),
            ("unit", "TestProjectRuntimeRecheckBeforeArchive"),
            ("security", "TestInstallEnterpriseProfileHTTPPreflightActualCLI"),
            ("unit", "TestRuntimeTreeObservationReadOnly"),
            ("security", "TestRuntimeTreeObservationReadOnly"),
            ("unit", "TestRuntimeTreeObservationInvalid"),
            ("security", "TestRuntimeFingerprintActualCLI"),
            ("unit", "TestUnpackInflatedBudget"),
            ("unit", "TestSnapshotRejectsPathReopen"),
            ("security", "TestSnapshotBoundedInputs"),
            ('unit', 'TestRetainedRootLocalSnapshot'),
            ('unit', 'TestRetainedRootHTTPStagingSnapshot'),
            ('unit', 'TestRetainedRootManifestAndAdoption'),
            ('security', 'TestRetainedRootLocalSnapshot'),
            ('security', 'TestRetainedRootHTTPStagingSnapshot'),
            ('security', 'TestRetainedRootManifestAndAdoption'),
            ('security', 'TestInstallRetainedRootSnapshotActualCLI'),
            ('unit', 'TestBoundIdentityReaderResponses'),
            ('unit', 'TestBoundIdentityReaderPhases'),
            ('unit', 'TestBoundIdentityReaderTransport'),
            ('unit', 'TestProjectRegistryIdentitySnapshot'),
            ('unit', 'TestProjectRegistryIdentityFinalRecheck'),
            ('unit', 'TestRegistryIdentityGovernancePolicy'),
            ('security', 'TestBoundIdentityReaderResponses'),
            ('security', 'TestBoundIdentityReaderPhases'),
            ('security', 'TestBoundIdentityReaderTransport'),
            ('security', 'TestProjectRegistryIdentitySnapshot'),
            ('security', 'TestProjectRegistryIdentityFinalRecheck'),
            ('security', 'TestRegistryIdentityGovernancePolicy'),
            ('security', 'TestInstallRegistryIdentityActualCLI'),
            ('unit', 'TestGETBoundaryContract'),
            ('unit', 'TestManagedClientBoundary'),
            ('unit', 'TestManagedClientSnapshotAndLifecycle'),
            ('unit', 'TestManagedRegistryTransportRedirectBoundary'),
            ('unit', 'TestManagedRegistryTransportSnapshotAndErrors'),
            ('security', 'TestGETBoundaryContract'),
            ('security', 'TestManagedClientBoundary'),
            ('security', 'TestManagedClientSnapshotAndLifecycle'),
            ('security', 'TestManagedRegistryTransportRedirectBoundary'),
            ('security', 'TestManagedRegistryTransportSnapshotAndErrors'),
            ('security', 'TestInstallManagedTransportActualCLI'),
            ('unit', 'TestAgentEvidenceRecordFraming'),
            ('unit', 'TestAgentEvidenceContextSnapshotBounds'),
            ('unit', 'TestAgentEvidencePlatformPublication'),
            ('unit', 'TestAgentEvidenceProcessLock'),
            ('unit', 'TestAgentRetainedProofSameBytesAndContext'),
            ('unit', 'TestAgentRetainedProofIdentityAndBounds'),
            ('unit', 'TestAgentRetainedProofPublicationFailures'),
            ('security', 'TestAgentEvidenceRecordFraming'),
            ('security', 'TestAgentEvidenceContextSnapshotBounds'),
            ('security', 'TestAgentEvidencePlatformPublication'),
            ('security', 'TestAgentEvidenceProcessLock'),
            ('security', 'TestAgentRetainedProofSameBytesAndContext'),
            ('security', 'TestAgentRetainedProofIdentityAndBounds'),
            ('security', 'TestAgentRetainedProofPublicationFailures'),
            ('security', 'TestPullInstallAgentRetainedProofActualCLI'),
            ('unit', 'TestNativeJournalEnrollmentAndHistory'),
            ('unit', 'TestNativeJournalEpochClockAndFullSet'),
            ('unit', 'TestNativeJournalLockAndPersistence'),
            ('unit', 'TestNativeOfflineInstallSessionBinding'),
            ('unit', 'TestNativeOfflineInstallPublicationBoundary'),
            ('security', 'TestNativeJournalEnrollmentAndHistory'),
            ('security', 'TestNativeJournalEpochClockAndFullSet'),
            ('security', 'TestNativeJournalLockAndPersistence'),
            ('security', 'TestNativeOfflineInstallSessionBinding'),
            ('security', 'TestNativeOfflineInstallPublicationBoundary'),
            ('unit', 'TestNativeProfileStrictSelection'),
            ('unit', 'TestNativeRootRoleSnapshots'),
            ('unit', 'TestNativeRevocationEvidenceBounds'),
            ('unit', 'TestNativeEnterpriseProfileEarlyDenial'),
            ('unit', 'TestNativeEnterpriseIntentDenials'),
            ('security', 'TestNativeProfileStrictSelection'),
            ('security', 'TestNativeRootRoleSnapshots'),
            ('security', 'TestNativeRevocationEvidenceBounds'),
            ('security', 'TestNativeEnterpriseProfileEarlyDenial'),
            ('security', 'TestNativeEnterpriseIntentDenials'),
            ('security', 'TestPullNativeEnterpriseProfilePreflightActualCLI'),
            ('security', 'TestPublishNativeEnterpriseProfilePreflightActualCLI'),
            ("unit", "TestStateRealProcessLock"),
            ("security", "TestStateRealProcessLock"),
            ('unit', 'TestInstalledSkillSourceSignedActiveProof'),
            ('unit', 'TestInstalledSkillSourceRejectsUnsignedAndLegacy'),
            ('unit', 'TestInstalledSkillSourceBindsIdentityVersionAndDeclarations'),
            ('unit', 'TestInstalledSkillGraphTransitiveAndCycles'),
            ('unit', 'TestInstalledSkillRecheckBeforeArchive'),
            ('unit', 'TestInstalledSkillSubjectRevocationAndClock'),
            ('unit', 'TestInstalledSkillNoProvisioningOrIgnoreBypass'),
            ('unit', 'TestInstalledSkillGraphSelectedRuntime'),
            ('unit', 'TestInstalledSkillSourceBoundedInputs'),
            ('unit', 'TestInstalledSkillSourceRejectsAmbiguousOrForeignEvidence'),
            ('security', 'TestInstalledSkillSourceSignedActiveProof'),
            ('security', 'TestInstalledSkillSourceRejectsUnsignedAndLegacy'),
            ('security', 'TestInstalledSkillSourceBindsIdentityVersionAndDeclarations'),
            ('security', 'TestInstalledSkillGraphTransitiveAndCycles'),
            ('security', 'TestInstalledSkillRecheckBeforeArchive'),
            ('security', 'TestInstalledSkillSubjectRevocationAndClock'),
            ('security', 'TestInstalledSkillNoProvisioningOrIgnoreBypass'),
            ('security', 'TestInstalledSkillGraphSelectedRuntime'),
            ('security', 'TestInstalledSkillSourceBoundedInputs'),
            ('security', 'TestInstalledSkillSourceRejectsAmbiguousOrForeignEvidence'),
            ('security', 'TestInstallInstalledSkillDependenciesActualCLI'),
            ('security', 'TestInstallInstalledSkillDependenciesTamperActualCLI'),
            ('security', 'TestInstallInstalledSkillDependenciesRevokedActualCLI'),
        )
        env = dict(os.environ, TEST_PRODUCER_RESULTS=json.dumps(self.needs))
        args = [sys.executable, str(ROOT / "scripts/ci-test-artifacts.py"), str(self.root),
                "--commit", self.context["commit"], "--run-id", "123", "--attempt", "2"]
        for lane, name in probes:
            raw, metadata = self.paths[lane]
            original_raw, original_metadata = raw.read_bytes(), metadata.read_bytes()
            for action in ("skip", "missing"):
                with self.subTest(lane=lane, name=name, action=action):
                    rows = [json.loads(line) for line in original_raw.splitlines()]
                    if action == "missing":
                        rows = [r for r in rows if r.get("Test") != name]
                    else:
                        next(r for r in rows if r.get("Test") == name and r["Action"] == "pass")["Action"] = "skip"
                    raw.write_text("".join(json.dumps(r) + "\n" for r in rows))
                    meta = json.loads(original_metadata)
                    meta["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
                    meta["test_terminal_counts"] = {
                        status: sum(r["Action"] == status and "Test" in r for r in rows)
                        for status in ("pass", "skip", "fail")
                    }
                    metadata.write_text(json.dumps(meta))
                    try:
                        result = subprocess.run(args, env=env, capture_output=True, text=True)
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertIn("mandatory Go scenario", result.stderr)
                    finally:
                        raw.write_bytes(original_raw)
                        metadata.write_bytes(original_metadata)

    def test_consumer_is_in_required_always_job(self):
        data = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = data["jobs"]["sim-gate"]
        self.assertEqual(set(job["needs"]), GATE.PRODUCERS)
        self.assertEqual(job["if"], "always()")
        self.assertFalse(job.get("continue-on-error", False))
        download = next(step for step in job["steps"] if step.get("name") == "Download current test execution records")
        self.assertEqual(download["with"]["pattern"],
                         "test-records-*-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}")
        self.assertEqual(download["with"]["path"], "test-artifacts/")
        self.assertNotIn("if", download)
        self.assertFalse(download.get("continue-on-error", False))
        self.assertNotIn("run-id", download["with"])
        self.assertNotIn("repository", download["with"])
        commands = [step for step in job["steps"]
                    if step.get("run") == "python3 scripts/ci-test-artifacts.py test-artifacts"]
        self.assertEqual(len(commands), 1)
        self.assertNotIn("if", commands[0])
        self.assertFalse(commands[0].get("continue-on-error", False))
        self.assertEqual(commands[0]["env"]["TEST_PRODUCER_RESULTS"], "${{ toJSON(needs) }}")
        required = (ROOT / "docs/security/required-checks.txt").read_text()
        self.assertIn(job["name"], required)


if __name__ == "__main__":
    unittest.main()
