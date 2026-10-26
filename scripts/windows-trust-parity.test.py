#!/usr/bin/env python3
"""Offline CLI counterexamples for scoped Windows/Linux trust parity."""

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
PACKAGE = "github.com/kamir/m3c-tools/pkg/skillctl/verify"
PARENT = "TestExitCode_Sentinels"
CHILD = PARENT + "/digest_mismatch"
DEPENDENCY_PACKAGE = "github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
DEPENDENCY_TESTS = (
    'TestReleaseConstraints',
    'TestProfileStrict',
    'TestGraphAndLock',
    'TestGraphDenials',
    'TestSelectedSystemRuntime',
    'TestProbeLimitsAndCancellation',
    'TestProfileSnapshotAndCaps',
    'TestCatalogVersionBacktracking',
    'TestProfileByteBoundary',
    'TestPythonRuntimeFixture',
    'TestPythonCanonicalDeclarationIdentity',
    'TestTypedProfilePreMarshalBounds',
    'TestSiteTreeContract',
    'TestRuntimeReportWireField',
    'TestSiteTreeGoldenAndBounds',
    'TestWindowsVenvSiteClassification',
    'TestGraphAggregateBudget',
    'TestWindowsMarkerEnvironment',
    'TestRuntimeTreeObservationGolden',
    'TestRuntimeTreeObservationReadOnly',
    'TestRuntimeTreeObservationInvalid',
)
PROJECT_TESTS = {
    'github.com/kamir/m3c-tools/pkg/httpsafe': (
        'TestGETBoundaryContract',
    ),
    'github.com/kamir/m3c-tools/pkg/skillbundle': (
        'TestUnpackInflatedBudget',
    ),
    'github.com/kamir/m3c-tools/pkg/skillctl/artifact': (
        'TestNativeEnterpriseIntentDenials',
    ),
    'github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy': (
        'TestNativeProfileStrictSelection',
        'TestNativeEvidenceProfileSourceBinding',
        'TestNativeEvidenceExplicitAdopt',
        'TestProjectProfileSnapshotsAndSelection',
        'TestProjectProfileStrictInputs',
        'TestProjectProfilePinnedRolesAndYAML',
    ),
    'github.com/kamir/m3c-tools/pkg/skillctl/mutationstate': (
        'TestSessionRecheckFreshClockFloorAndOriginalBinding',
        'TestSessionRecheckStaleFloorPreventsClockRecovery',
        'TestSessionRecheckRevokedAdditionalSubjectPersistsClock',
        'TestSessionRecheckInvalidInputsDoNotWrite',
        'TestSessionRecheckRejectsHistoryReplacement',
        'TestSessionRecheckPersistenceUncertaintyInvalidatesSession',
        'TestSessionRecheckCloseAndDecisionConcurrent',
        'TestStateRealProcessLock',
    ),
    'github.com/kamir/m3c-tools/pkg/skillctl/registry': (
        'TestNativeEvidenceHTTPSReaderContract',
        'TestNativeJournalEnrollmentAndHistory',
        'TestNativeJournalEpochClockAndFullSet',
        'TestNativeJournalLockAndPersistence',
        'TestNativeOfflineInstallSessionBinding',
        'TestNativeOfflineInstallPublicationBoundary',
        'TestNativeRootRoleSnapshots',
        'TestNativeRevocationEvidenceBounds',
        'TestNativeEnterpriseProfileEarlyDenial',
        'TestBoundIdentityReaderResponses',
        'TestBoundIdentityReaderPhases',
        'TestBoundIdentityReaderTransport',
        'TestManagedClientBoundary',
        'TestManagedClientSnapshotAndLifecycle',
        'TestAgentEvidenceRecordFraming',
        'TestAgentEvidenceContextSnapshotBounds',
        'TestAgentEvidencePlatformPublication',
        'TestAgentEvidenceProcessLock',
        'TestAgentRetainedProofSameBytesAndContext',
        'TestAgentRetainedProofIdentityAndBounds',
        'TestAgentRetainedProofPublicationFailures',
    ),
    'github.com/kamir/m3c-tools/pkg/skillctl/install': (
        'TestProjectManagedInstallRequiresPolicyBeforeIO',
        'TestProjectSignedDependenciesCannotBeHidden',
        'TestProjectSignedTopLevelDependencyAliases',
        'TestProjectManagedInstallActualSignedRoutes',
        'TestProjectRuntimeRecheckBeforeArchive',
        'TestProjectMetadataSnapshotBudget',
        'TestProjectRequestedVersionBindsSignedManifest',
        'TestInstalledSkillSourceSignedActiveProof',
        'TestInstalledSkillSourceRejectsUnsignedAndLegacy',
        'TestInstalledSkillSourceBindsIdentityVersionAndDeclarations',
        'TestInstalledSkillGraphTransitiveAndCycles',
        'TestInstalledSkillRecheckBeforeArchive',
        'TestInstalledSkillSubjectRevocationAndClock',
        'TestInstalledSkillNoProvisioningOrIgnoreBypass',
        'TestInstalledSkillGraphSelectedRuntime',
        'TestInstalledSkillSourceBoundedInputs',
        'TestInstalledSkillSourceRejectsAmbiguousOrForeignEvidence',
        'TestRetainedRootLocalSnapshot',
        'TestRetainedRootHTTPStagingSnapshot',
        'TestRetainedRootManifestAndAdoption',
        'TestProjectRegistryIdentitySnapshot',
        'TestProjectRegistryIdentityFinalRecheck',
        'TestRegistryIdentityGovernancePolicy',
        'TestManagedRegistryTransportRedirectBoundary',
        'TestManagedRegistryTransportSnapshotAndErrors',
    ),
    'github.com/kamir/m3c-tools/cmd/skillctl': (
        'TestTrustNativeEvidenceAdoptActualCLI',
        'TestPullNativeEnterpriseProfilePreflightActualCLI',
        'TestPublishNativeEnterpriseProfilePreflightActualCLI',
        'TestInstallEnterpriseProfileActualCLI',
        'TestInstallEnterpriseProfileUsageBeforeReads',
        'TestInstallEnterpriseProfileHTTPPreflightActualCLI',
        'TestRuntimeFingerprintActualCLI',
        'TestRuntimeFingerprintUsageBeforeReads',
        'TestRuntimeFingerprintOutputFailure',
        'TestInstallInstalledSkillDependenciesActualCLI',
        'TestInstallInstalledSkillDependenciesTamperActualCLI',
        'TestInstallInstalledSkillDependenciesRevokedActualCLI',
        'TestInstallRetainedRootSnapshotActualCLI',
        'TestInstallRegistryIdentityActualCLI',
        'TestInstallManagedTransportActualCLI',
        'TestPullInstallAgentRetainedProofActualCLI',
    ),
}
SNAPSHOT_TESTS = ('TestSnapshotSameBytesScopes', 'TestSnapshotRejectsPathReopen', 'TestSnapshotBoundedInputs', 'TestSnapshotExistingVerifyParity')
COMMIT = "c" * 40


def event(name=None, action="pass", package=PACKAGE):
    row = {"Action": action, "Package": package}
    if name is not None:
        row["Test"] = name
    return row


def successful_report():
    rows = [event(action="start")]
    for name in (
        "TestVerify_HappyPath", "TestVerify_DigestMismatch_BundleTampered",
        "TestVerify_AuthorSig_WrongPubkey", "TestVerify_IdentityRevoke_Sentinel",
        "TestSnapshotSameBytesScopes", "TestSnapshotRejectsPathReopen", "TestSnapshotBoundedInputs", "TestSnapshotExistingVerifyParity",
    ):
        rows.extend([event(name, "run"), event(name)])
    rows.append(event(PARENT, "run"))
    for name in (
        "digest_mismatch", "author_sig_invalid", "registry_not_trusted",
        "governance_below_min", "deps_unsatisfied", "blob_missing",
        "intent_inconsistent", "identity_mismatch",
    ):
        rows.extend([event(PARENT + "/" + name, "run"), event(PARENT + "/" + name)])
    dependency_rows = [event(action="start", package=DEPENDENCY_PACKAGE)]
    for name in DEPENDENCY_TESTS:
        dependency_rows.extend([event(name, "run", DEPENDENCY_PACKAGE), event(name, package=DEPENDENCY_PACKAGE)])
    dependency_rows.append(event(package=DEPENDENCY_PACKAGE))
    integration_rows = []
    for package, names in PROJECT_TESTS.items():
        integration_rows.append(event(action="start", package=package))
        for name in names:
            integration_rows.extend([event(name, "run", package), event(name, package=package)])
        integration_rows.append(event(package=package))
    return integration_rows + dependency_rows + rows + [event(PARENT), event()]


def exception(**changes):
    row = dict(package=PACKAGE, test=CHILD, platform="windows",
               reason="Synthetic platform limitation for oracle regression only",
               owner="test-owner", review="synthetic-review", expires="2999-01-01")
    return dict(row, **changes)


class ParityContracts(unittest.TestCase):
    def run_reports(self, linux=None, windows=None, *, bound=False, mutate=None,
                    exceptions=None, flags=(), raw=None):
        with tempfile.TemporaryDirectory() as home:
            env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
            env.update(HOME=home, USERPROFILE=home)
            paths = []
            for platform, rows in (("linux", linux), ("windows", windows)):
                path = Path(home) / f"{platform}.json"
                rows = successful_report() if rows is None else rows
                path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                if raw is not None and platform == "windows":
                    path.write_text(raw, encoding="utf-8")
                paths.append(str(path))
                if bound:
                    producer_env = dict(env, GITHUB_SHA=COMMIT, GITHUB_RUN_ID="123",
                                        GITHUB_RUN_ATTEMPT="2", GITHUB_JOB=(
                                            "drift-guard" if platform == "linux" else "windows-trust"))
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "record", str(path), "--platform", platform],
                        env=producer_env, capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    metadata_path = Path(str(path) + ".meta.json")
                    if mutate and platform == "windows":
                        metadata = json.loads(metadata_path.read_text())
                        mutate(metadata, path)
                        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            args = [sys.executable, str(SCRIPT), *paths]
            if bound:
                env.update(GITHUB_SHA=COMMIT, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2")
            if exceptions is not None:
                path = Path(home) / "exceptions.json"
                path.write_text(json.dumps(exceptions), encoding="utf-8")
                args.extend(["--exceptions", str(path)])
            return subprocess.run(args + list(flags), env=env, capture_output=True,
                                  text=True, check=False)

    def reject(self, result, message):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_same_required_cases_pass_with_denominator(self):
        result = self.run_reports()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("linux lane=trust required=117 pass=117 skip=0 missing=0 exceptions=0", result.stdout)
        self.assertIn("windows lane=trust required=117 pass=117 skip=0 missing=0 exceptions=0", result.stdout)
        self.assertIn("UNBOUND", result.stdout)

    def test_dependency_python_skip_or_missing_cannot_hide_behind_package_pass(self):
        for selected in ("TestPythonRuntimeFixture", "TestWindowsMarkerEnvironment",
                         "TestRuntimeTreeObservationGolden", "TestRuntimeTreeObservationReadOnly",
                         "TestRuntimeTreeObservationInvalid"):
            for status in ("skip", "missing"):
                for platform in ("linux", "windows"):
                    with self.subTest(selected=selected, status=status, platform=platform):
                        rows = successful_report()
                        if status == "missing":
                            rows = [r for r in rows if r.get("Test") != selected]
                        else:
                            next(r for r in rows if r.get("Test") == selected and r["Action"] == "pass")["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}), "is " + ("missing" if status == "missing" else "skip"))

    def test_dependency_graph_budget_skip_or_missing_cannot_hide_behind_package_pass(self):
        for status in ("skip", "missing"):
            for platform in ("linux", "windows"):
                with self.subTest(status=status, platform=platform):
                    rows = successful_report()
                    if status == "missing":
                        rows = [r for r in rows if r.get("Test") != "TestGraphAggregateBudget"]
                    else:
                        next(r for r in rows if r.get("Test") == "TestGraphAggregateBudget" and r["Action"] == "pass")["Action"] = "skip"
                    self.reject(self.run_reports(**{platform: rows}), "is " + ("missing" if status == "missing" else "skip"))

    def test_project_policy_session_install_and_cli_are_mandatory(self):
        for package, names in PROJECT_TESTS.items():
            for status in ("skip", "missing"):
                for platform in ("linux", "windows"):
                    with self.subTest(package=package, status=status, platform=platform):
                        rows = successful_report()
                        selected = names[0]
                        if status == "missing":
                            rows = [r for r in rows if (r.get("Package"), r.get("Test")) != (package, selected)]
                        else:
                            next(r for r in rows if r.get("Package") == package and r.get("Test") == selected
                                 and r["Action"] == "pass")["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), "is " + status)

    def test_runtime_cli_observation_cases_cannot_skip(self):
        for name in ("TestRuntimeFingerprintActualCLI", "TestRuntimeFingerprintUsageBeforeReads",
                     "TestRuntimeFingerprintOutputFailure"):
            for status in ("skip", "missing"):
                for platform in ("linux", "windows"):
                    with self.subTest(name=name, status=status, platform=platform):
                        rows = successful_report()
                        if status == "missing":
                            rows = [r for r in rows if r.get("Test") != name]
                        else:
                            next(r for r in rows if r.get("Test") == name
                                 and r["Action"] == "pass")["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), "is " + status)

    def test_equal_counts_disjoint_ids_rejected(self):
        rows = successful_report()
        for row in rows:
            if "Test" in row:
                row["Test"] = row["Test"].replace("Test", "TestDifferent", 1)
        self.reject(self.run_reports(windows=rows), "is missing")

    def test_snapshot_and_inflated_guards_cannot_skip_or_disappear(self):
        cases = [(PACKAGE, name) for name in SNAPSHOT_TESTS]
        cases.append(("github.com/kamir/m3c-tools/pkg/skillbundle", "TestUnpackInflatedBudget"))
        for package, name in cases:
            for platform in ("linux", "windows"):
                for action in ("skip", "missing"):
                    with self.subTest(package=package, name=name, platform=platform, action=action):
                        rows = successful_report()
                        if action == "missing":
                            rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                        else:
                            next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                 (package, name, "pass"))["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}), name)

    def test_installed_dependency_guards_cannot_skip_or_disappear(self):
        for package in ("github.com/kamir/m3c-tools/pkg/skillctl/install", "github.com/kamir/m3c-tools/cmd/skillctl"):
            for name in PROJECT_TESTS[package]:
                if not name.startswith(("TestInstalledSkill", "TestInstallInstalledSkill")):
                    continue
                for platform in ("linux", "windows"):
                    for action in ("skip", "missing"):
                        with self.subTest(package=package, name=name, platform=platform, action=action):
                            rows = successful_report()
                            if action == "missing":
                                rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                            else:
                                next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                     (package, name, "pass"))["Action"] = "skip"
                            self.reject(self.run_reports(**{platform: rows}), name)

    def test_real_process_lock_cannot_skip_or_disappear(self):
        package = "github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
        name = "TestStateRealProcessLock"
        for platform in ("linux", "windows"):
            for action in ("skip", "missing"):
                with self.subTest(platform=platform, action=action):
                    rows = successful_report()
                    if action == "missing":
                        rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                    else:
                        next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                             (package, name, "pass"))["Action"] = "skip"
                    self.reject(self.run_reports(**{platform: rows}), name)

    def test_retained_root_guards_cannot_skip_or_disappear(self):
        cases = [("github.com/kamir/m3c-tools/pkg/skillctl/install", name) for name in (
            "TestRetainedRootLocalSnapshot", "TestRetainedRootHTTPStagingSnapshot",
            "TestRetainedRootManifestAndAdoption")]
        cases.append(("github.com/kamir/m3c-tools/cmd/skillctl", "TestInstallRetainedRootSnapshotActualCLI"))
        for package, name in cases:
            for platform in ("linux", "windows"):
                for action in ("skip", "missing"):
                    with self.subTest(package=package, name=name, platform=platform, action=action):
                        rows = successful_report()
                        if action == "missing":
                            rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                        else:
                            next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                 (package, name, "pass"))["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), name)

    def test_registry_identity_guards_cannot_skip_or_disappear(self):
        cases = [("github.com/kamir/m3c-tools/pkg/skillctl/registry", name) for name in (
            "TestBoundIdentityReaderResponses", "TestBoundIdentityReaderPhases",
            "TestBoundIdentityReaderTransport")]
        cases.extend(("github.com/kamir/m3c-tools/pkg/skillctl/install", name) for name in (
            "TestProjectRegistryIdentitySnapshot", "TestProjectRegistryIdentityFinalRecheck",
            "TestRegistryIdentityGovernancePolicy"))
        cases.append(("github.com/kamir/m3c-tools/cmd/skillctl", "TestInstallRegistryIdentityActualCLI"))
        for package, name in cases:
            for platform in ("linux", "windows"):
                for action in ("skip", "missing"):
                    with self.subTest(package=package, name=name, platform=platform, action=action):
                        rows = successful_report()
                        if action == "missing":
                            rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                        else:
                            next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                 (package, name, "pass"))["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), name)

    def test_managed_transport_guards_cannot_skip_or_disappear(self):
        cases = [("github.com/kamir/m3c-tools/pkg/httpsafe", "TestGETBoundaryContract")]
        cases.extend(("github.com/kamir/m3c-tools/pkg/skillctl/registry", name) for name in (
            "TestManagedClientBoundary", "TestManagedClientSnapshotAndLifecycle"))
        cases.extend(("github.com/kamir/m3c-tools/pkg/skillctl/install", name) for name in (
            "TestManagedRegistryTransportRedirectBoundary", "TestManagedRegistryTransportSnapshotAndErrors"))
        cases.append(("github.com/kamir/m3c-tools/cmd/skillctl", "TestInstallManagedTransportActualCLI"))
        for package, name in cases:
            for platform in ("linux", "windows"):
                for action in ("skip", "missing"):
                    with self.subTest(package=package, name=name, platform=platform, action=action):
                        rows = successful_report()
                        if action == "missing":
                            rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                        else:
                            next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                 (package, name, "pass"))["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), name)

    def test_agent_evidence_guards_cannot_skip_or_disappear(self):
        cases = [("github.com/kamir/m3c-tools/pkg/skillctl/registry", name) for name in (
            "TestAgentEvidenceRecordFraming", "TestAgentEvidenceContextSnapshotBounds",
            "TestAgentEvidencePlatformPublication", "TestAgentEvidenceProcessLock",
            "TestAgentRetainedProofSameBytesAndContext", "TestAgentRetainedProofIdentityAndBounds",
            "TestAgentRetainedProofPublicationFailures")]
        cases.append(("github.com/kamir/m3c-tools/cmd/skillctl", "TestPullInstallAgentRetainedProofActualCLI"))
        for package, name in cases:
            for platform in ("linux", "windows"):
                for action in ("skip", "missing"):
                    with self.subTest(package=package, name=name, platform=platform, action=action):
                        rows = successful_report()
                        if action == "missing":
                            rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                        else:
                            next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                 (package, name, "pass"))["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), name)

    def test_native_profile_guards_cannot_skip_or_disappear(self):
        cases = [('github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy', 'TestNativeProfileStrictSelection'), ('github.com/kamir/m3c-tools/pkg/skillctl/registry', 'TestNativeRootRoleSnapshots'), ('github.com/kamir/m3c-tools/pkg/skillctl/registry', 'TestNativeRevocationEvidenceBounds'), ('github.com/kamir/m3c-tools/pkg/skillctl/registry', 'TestNativeEnterpriseProfileEarlyDenial'), ('github.com/kamir/m3c-tools/pkg/skillctl/artifact', 'TestNativeEnterpriseIntentDenials'), ('github.com/kamir/m3c-tools/cmd/skillctl', 'TestPullNativeEnterpriseProfilePreflightActualCLI'), ('github.com/kamir/m3c-tools/cmd/skillctl', 'TestPublishNativeEnterpriseProfilePreflightActualCLI')]
        cases.extend([
            ('github.com/kamir/m3c-tools/pkg/skillctl/registry', 'TestNativeEvidenceHTTPSReaderContract'),
            ('github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy', 'TestNativeEvidenceProfileSourceBinding'),
            ('github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy', 'TestNativeEvidenceExplicitAdopt'),
            ('github.com/kamir/m3c-tools/cmd/skillctl', 'TestTrustNativeEvidenceAdoptActualCLI'),
        ])
        for package, name in cases:
            for platform in ("linux", "windows"):
                for action in ("skip", "missing"):
                    with self.subTest(package=package, name=name, platform=platform, action=action):
                        rows = successful_report()
                        if action == "missing":
                            rows = [r for r in rows if (r["Package"], r.get("Test")) != (package, name)]
                        else:
                            next(r for r in rows if (r["Package"], r.get("Test"), r["Action"]) ==
                                 (package, name, "pass"))["Action"] = "skip"
                        self.reject(self.run_reports(**{platform: rows}, bound=True), name)

    def test_all_windows_skip_is_not_pass(self):
        rows = successful_report()
        for row in rows:
            if row["Action"] == "pass" and "Test" in row:
                row["Action"] = "skip"
        result = self.run_reports(windows=rows)
        self.reject(result, "is skip")
        self.assertIn("windows lane=trust required=117 pass=0 skip=117", result.stdout)

    def test_missing_or_skipped_subtest_with_passing_parent_rejected(self):
        for status in ("missing", "skip"):
            with self.subTest(status=status):
                rows = successful_report()
                if status == "missing":
                    rows = [row for row in rows if row.get("Test") != CHILD]
                else:
                    next(row for row in rows if row.get("Test") == CHILD and row["Action"] == "pass")["Action"] = "skip"
                self.reject(self.run_reports(windows=rows), CHILD + " is " + status)

    def test_failures_survive_parent_pass_rerun_and_exception(self):
        for platform in ("linux", "windows"):
            for name in (CHILD, PARENT, "TestOutsideScope", None):
                with self.subTest(platform=platform, name=name):
                    rows = successful_report()
                    rows.insert(2, event(name, "fail"))
                    rows.insert(3, event(name))
                    self.reject(self.run_reports(**{platform: rows}, exceptions=[exception()]), "failed test/package")

    def test_empty_package_only_and_interrupted_runs_rejected(self):
        for platform in ("linux", "windows"):
            for rows in ([], [event(action="start"), event()], successful_report()[:-1],
                         successful_report()[:-3], [event(action="start"), event("TestInterrupted", "run")]):
                with self.subTest(platform=platform, rows=len(rows)):
                    self.assertEqual(self.run_reports(**{platform: rows}).returncode, 1)

    def test_non_json_and_truncated_json_rejected(self):
        for raw in ("build failed\n", "{", "null\n", "[]\n", '{"Action":"pass"}\n'):
            with self.subTest(raw=raw):
                self.assertEqual(self.run_reports(raw=raw).returncode, 1)

    def test_malformed_identities_rejected(self):
        for field in ("Test", "Package"):
            for value in ("", " \t", None, 7, []):
                with self.subTest(field=field, value=value):
                    rows = successful_report()
                    rows[1][field] = value
                    self.reject(self.run_reports(windows=rows), "invalid")

    def test_duplicate_contradictory_and_unstarted_events_rejected(self):
        for extra in (event(CHILD), event(CHILD, "skip"), event(action="start"),
                      event("TestNeverStarted"), event(action="surprise"),
                      event(PARENT, "pause"), event(action="skip")):
            with self.subTest(extra=extra):
                rows = successful_report()
                rows.insert(-1, extra)
                self.assertEqual(self.run_reports(windows=rows).returncode, 1)

    def test_unfinished_unselected_child_is_not_hidden_by_parent_pass(self):
        rows = successful_report()
        rows.insert(-2, event(PARENT + "/unselected", "run"))
        self.reject(self.run_reports(windows=rows), "unfinished subtest")

    def test_parallel_nested_slash_names_and_examples_preserve_identity(self):
        rows = successful_report()
        rows[-1:-1] = [event("TestDynamic", "run"), event("TestDynamic", "pause"),
                       event("TestDynamic", "cont"), event("TestDynamic/time/123", "run"),
                       event("TestDynamic/time/123"), event("TestDynamic"),
                       event("ExampleSynthetic", "run"), event("ExampleSynthetic")]
        result = self.run_reports(windows=rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("3 other identities outside reviewed parity scope", result.stdout)

    def test_wrong_package_does_not_satisfy_identity(self):
        rows = successful_report()
        for row in rows:
            row["Package"] = "other/" + row["Package"]
        self.reject(self.run_reports(windows=rows), "is missing")

    def test_unselected_skips_are_reported_not_passes(self):
        rows = successful_report()
        rows[-1:-1] = [event("TestOptional", "run"), event("TestOptional", "skip")]
        result = self.run_reports(windows=rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observed pass=117 skip=1", result.stdout)
        self.assertIn("1 other identities outside reviewed parity scope", result.stdout)

    def test_bound_same_run_reports_pass(self):
        result = self.run_reports(bound=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("UNBOUND", result.stdout)

    def test_wrong_binding_fields_rejected(self):
        for field, value in (("commit", "d" * 40), ("run_id", "124"), ("attempt", "1"),
                             ("platform", "linux"), ("job", "other"), ("lane", "other"),
                             ("exit_code", 7), ("exit_code", False), ("sha256", "0" * 64),
                             ("schema", "other")):
            with self.subTest(field=field, value=value):
                self.reject(self.run_reports(bound=True, mutate=lambda meta, _: meta.update({field: value})),
                            "wrong metadata " + field)

    def test_report_mutation_after_binding_rejected(self):
        def change_report(_, path):
            path.write_text(path.read_text() + "\n", encoding="utf-8")
        self.reject(self.run_reports(bound=True, mutate=change_report), "wrong metadata sha256")

    def test_binding_cannot_silently_degrade_to_unbound(self):
        self.reject(self.run_reports(flags=("--commit", COMMIT)), "binding requires")
        self.reject(self.run_reports(bound=True, flags=("--attempt", "")), "binding requires")

    def test_valid_exact_platform_exception_is_not_pass(self):
        rows = [row for row in successful_report() if row.get("Test") != CHILD]
        result = self.run_reports(windows=rows, exceptions=[exception()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("EXCEPTION (not PASS)", result.stdout)
        self.assertIn("windows lane=trust required=117 pass=116 skip=0 missing=1 exceptions=1", result.stdout)
        self.assertIn("not acceptance", result.stdout)
        self.reject(self.run_reports(linux=rows, exceptions=[exception()]), "linux: required")

    def test_expired_invalid_and_unused_exceptions_rejected(self):
        for entry in (exception(expires="2020-01-01"), exception(owner=""),
                      exception(review=""), exception(test="*"), exception(platform="all"),
                      exception(reason=""), exception(expires="not-a-date")):
            with self.subTest(entry=entry):
                self.assertEqual(self.run_reports(exceptions=[entry]).returncode, 1)
        self.reject(self.run_reports(exceptions=[exception()]), "unused exception")
        self.reject(self.run_reports(exceptions=[exception(), exception()]), "duplicate")

    def test_missing_report_is_nonzero(self):
        with tempfile.TemporaryDirectory() as home:
            env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
            env.update(HOME=home, USERPROFILE=home)
            result = subprocess.run([sys.executable, str(SCRIPT), str(Path(home) / "missing"), "missing"],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("No such file", result.stderr)

    def test_windows_bom_and_crlf_stream_is_accepted(self):
        raw = "\ufeff" + "".join(json.dumps(row) + "\r\n" for row in successful_report())
        result = self.run_reports(raw=raw)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_duplicate_json_keys_cannot_hide_failure(self):
        raw = "".join(json.dumps(row) + "\n" for row in successful_report())
        raw = raw.replace('"Action": "pass"', '"Action": "fail", "Action": "pass"', 1)
        self.reject(self.run_reports(raw=raw), "malformed JSON")

    def test_record_rejects_bad_context_or_interruption_without_sidecar(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "report.json"
            env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
            env.update(HOME=home, USERPROFILE=home)
            for valid_context, rows in ((False, successful_report()), (True, successful_report()[:-1])):
                with self.subTest(valid_context=valid_context):
                    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                    if valid_context:
                        env.update(GITHUB_SHA=COMMIT, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2", GITHUB_JOB="windows-trust")
                    result = subprocess.run([sys.executable, str(SCRIPT), "record", str(path), "--platform", "windows"],
                                            env=env, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse(Path(str(path) + ".meta.json").exists())

    def test_valid_skip_exception_and_expiry_today(self):
        from datetime import datetime, timezone
        rows = successful_report()
        next(row for row in rows if row.get("Test") == CHILD and row["Action"] == "pass")["Action"] = "skip"
        result = self.run_reports(windows=rows, exceptions=[exception()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pass=116 skip=1 missing=0 exceptions=1", result.stdout)
        today = datetime.now(timezone.utc).date().isoformat()
        self.reject(self.run_reports(windows=rows, exceptions=[exception(expires=today)]), "expired exception")

    def test_missing_sidecar_cannot_pass_in_ci(self):
        def remove_linux_sidecar(_, path):
            (path.parent / "linux.json.meta.json").unlink()
        self.reject(self.run_reports(bound=True, mutate=remove_linux_sidecar), "binding requires")

    def test_platform_and_generated_cases_are_classified(self):
        rows = successful_report()
        rows[-1:-1] = [event("TestMutationFreshnessSignedBoundaries", "run"),
                       event("TestMutationFreshnessSignedBoundaries/install/0s", "run"),
                       event("TestMutationFreshnessSignedBoundaries/install/0s"),
                       event("TestMutationFreshnessSignedBoundaries")]
        pkg = "github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
        rows += [event(action="start", package=pkg),
                 event("TestStoreOnPlatformWithoutAStore", "run", pkg),
                 event("TestStoreOnPlatformWithoutAStore", "skip", pkg), event(package=pkg)]
        result = self.run_reports(windows=rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("platform-specific: protected-store", result.stdout)
        self.assertIn("generated subtests: action/duration", result.stdout)
        self.assertIn("TestMutationFreshnessSignedBoundaries/install/0s status=pass", result.stdout)



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
                    ["./pkg/httpsafe/...", "./pkg/skillctl/...", "./pkg/skillbundle/...", "./cmd/skillctl/...", "./evaluation/..."],
                )

    def test_real_linux_producer_and_binding_step(self):
        import hashlib
        bind = next(step for step in self.job["steps"] if step.get("name") == "Bind Linux parity evidence")
        with tempfile.TemporaryDirectory() as home:
            tools = Path(home) / "bin"
            tools.mkdir()
            fixture = Path(home) / "fixture.json"
            fixture.write_text("".join(json.dumps(row) + "\n" for row in successful_report()))
            fake_go = tools / "go"
            fake_go.write_text('#!/bin/sh\nif [ "$1" = env ]; then printf "%s\n" "$HOME/cache"; exit 0; fi\ncat "$FIXTURE"\n')
            fake_go.chmod(0o700)
            # Run the actual workflow steps in an isolated synthetic checkout.
            (Path(home) / "scripts").mkdir()
            (Path(home) / "scripts/windows-trust-parity.py").write_bytes(SCRIPT.read_bytes())
            env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
            env.update(HOME=home, USERPROFILE=home, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                       FIXTURE=str(fixture), GITHUB_SHA=COMMIT, GITHUB_RUN_ID="123",
                       GITHUB_RUN_ATTEMPT="2", GITHUB_JOB="drift-guard", **self.job["env"])
            for snippet in (self.step["run"], bind["run"]):
                result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", snippet],
                                        cwd=home, env=env, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
            meta = json.loads((Path(home) / "lin-trust.json.meta.json").read_text())
            self.assertEqual(meta["sha256"], hashlib.sha256(fixture.read_bytes()).hexdigest())
            self.assertEqual((meta["commit"], meta["run_id"], meta["attempt"], meta["job"]),
                             (COMMIT, "123", "2", "drift-guard"))

    def test_windows_binding_upload_and_download_match(self):
        windows = self.workflow["jobs"]["windows-trust"]
        run = next(step for step in windows["steps"] if "Tee-Object -FilePath win-trust.json" in step.get("run", ""))
        self.assertIn("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }", run["run"])
        bind = next(step for step in windows["steps"] if step.get("name") == "Bind Windows parity evidence")
        self.assertNotIn("if", bind)
        self.assertIn("record win-trust.json --platform windows", bind["run"])
        upload = next(step for step in windows["steps"] if step.get("name") == "Upload Windows test report (for drift parity)")
        download = next(step for step in self.job["steps"] if step.get("name") == "Download Windows test report")
        self.assertEqual(upload["with"]["name"], download["with"]["name"])
        for key in ("github.sha", "github.run_id", "github.run_attempt"):
            self.assertIn(key, upload["with"]["name"])
        self.assertIn("win-trust.json.meta.json", upload["with"]["path"].splitlines())
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def test_failure_contracts_are_wired_in_required_pin_guard(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pin-guard.yml").read_text())
        job = next(
            job for job in workflow["jobs"].values()
            if job.get("name") == "Enforce pinning + least-privilege + retention"
        )
        step = next(step for step in job["steps"] if step.get("run") == "python3 scripts/windows-trust-parity.test.py")
        self.assertFalse(step.get("continue-on-error", False))
        self.assertNotIn("if", step)

    def test_linux_evidence_is_uploaded_with_current_binding(self):
        upload = next(step for step in self.job["steps"] if step.get("name") == "Upload Linux parity evidence")
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertEqual(upload["with"]["retention-days"], 7)
        self.assertEqual(set(upload["with"]["path"].splitlines()), {"lin-trust.json", "lin-trust.json.meta.json"})
        for key in ("github.sha", "github.run_id", "github.run_attempt"):
            self.assertIn(key, upload["with"]["name"])


if __name__ == "__main__":
    unittest.main()
