#!/usr/bin/env python3
"""Check successful identities in a small portable trust scenario set.

Only REQUIRED is parity scope. Other cases retain full identities and failures
still reject the entire report; their passes/skips do not prove parity.
Sidecars bind report bytes to CI commit/run/attempt, platform, job and lane.
Local streams without sidecars can test the oracle but cannot prove provenance.
"""

import argparse
from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys


VERIFY = "github.com/kamir/m3c-tools/pkg/skillctl/verify"
# Fixed portable verifier and runtime-resolver identities. No generated names.
REQUIRED = {
    (VERIFY, name) for name in (
        "TestVerify_HappyPath",
        "TestVerify_DigestMismatch_BundleTampered",
        "TestVerify_AuthorSig_WrongPubkey",
        "TestVerify_IdentityRevoke_Sentinel",
        "TestSnapshotSameBytesScopes",
        "TestSnapshotRejectsPathReopen",
        "TestSnapshotBoundedInputs",
        "TestSnapshotExistingVerifyParity",
        "TestExitCode_Sentinels",
        "TestExitCode_Sentinels/digest_mismatch",
        "TestExitCode_Sentinels/author_sig_invalid",
        "TestExitCode_Sentinels/registry_not_trusted",
        "TestExitCode_Sentinels/governance_below_min",
        "TestExitCode_Sentinels/deps_unsatisfied",
        "TestExitCode_Sentinels/blob_missing",
        "TestExitCode_Sentinels/intent_inconsistent",
        "TestExitCode_Sentinels/identity_mismatch",
    )
}
DEPENDENCIES = "github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
DEPENDENCY_CASES = (
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
REQUIRED.update({(DEPENDENCIES, name) for name in DEPENDENCY_CASES})
# Fixed project-policy, held-session and actual CLI identities.
PROJECT_CASES = {
    'github.com/kamir/m3c-tools/pkg/skillbundle': (
        'TestUnpackInflatedBudget',
    ),
    'github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy': (
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
    ),
    'github.com/kamir/m3c-tools/cmd/skillctl': (
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
    ),
}
for _package, _cases in PROJECT_CASES.items():
    REQUIRED.update({(_package, name) for name in _cases})
JOBS = {"linux": "drift-guard", "windows": "windows-trust"}
# These are classifications outside REQUIRED, never waivers for required cases.
CLASSIFIED_PARENTS = {
    ("github.com/kamir/m3c-tools/pkg/skillctl/artifactauth", "TestStoreOnPlatformWithoutAStore"):
        "platform-specific: protected-store availability differs by OS",
    ("github.com/kamir/m3c-tools/pkg/skillctl/artifactauth", "TestKeychainRoundTrip"):
        "platform-specific: Darwin-only real Keychain integration, explicit opt-in",
    (VERIFY, "TestMutationFreshnessSignedBoundaries"):
        "generated subtests: action/duration labels, outside the fixed scenario set",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def read_json(path):
    with open(path, encoding="utf-8-sig") as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def report(path):
    """Validate Go event lifecycles, including every observed subtest."""
    packages, running, results = {}, {}, {}
    with open(path, encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line, object_pairs_hook=unique_object)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: malformed JSON") from exc
            if not isinstance(event, dict):
                raise ValueError(f"{path}:{number}: event must be an object")
            action, package, test = (event.get(key) for key in ("Action", "Package", "Test"))
            if action == "fail" or action == "build-fail":
                raise ValueError(f"{path}: failed test/package {package}::{test}")
            if not isinstance(package, str) or not package.strip():
                raise ValueError(f"{path}:{number}: invalid package identity")
            if "Test" in event and (not isinstance(test, str) or not test.strip()):
                raise ValueError(f"{path}:{number}: invalid test identity")
            if action not in {"start", "run", "pause", "cont", "output", "pass", "skip", "bench"}:
                raise ValueError(f"{path}:{number}: unknown action {action}")
            if action == "start":
                if test is not None or package in packages:
                    raise ValueError(f"{path}: duplicate/invalid package start {package}")
                packages[package] = "running"
                continue
            if packages.get(package) != "running":
                raise ValueError(f"{path}: event outside running package {package}")
            key = (package, test)
            if action == "run":
                if test is None or key in running or key in results:
                    raise ValueError(f"{path}: duplicate/invalid test run {key}")
                if "/" in test and not any(
                    pkg == package and test.startswith(parent + "/") for pkg, parent in running
                ):
                    raise ValueError(f"{path}: subtest without running parent {key}")
                running[key] = "running"
            elif action in {"pass", "skip"}:
                if test is None:
                    if any(pkg == package for pkg, _ in running):
                        raise ValueError(f"{path}: unfinished tests in {package}")
                    if action == "skip" and any(pkg == package for pkg, _ in results):
                        raise ValueError(f"{path}: skipped package with completed tests {package}")
                    packages[package] = action
                else:
                    if key not in running or key in results:
                        raise ValueError(f"{path}: duplicate/unstarted terminal test {key}")
                    if any(pkg == package and name.startswith(test + "/") for pkg, name in running):
                        raise ValueError(f"{path}: unfinished subtest of {key}")
                    if running[key] != "running":
                        raise ValueError(f"{path}: terminal test is paused {key}")
                    del running[key]
                    results[key] = action
            elif action in {"pause", "cont"}:
                previous = "running" if action == "pause" else "paused"
                if running.get(key) != previous:
                    raise ValueError(f"{path}: inconsistent pause/continue {key}")
                running[key] = "paused" if action == "pause" else "running"
    if not results:
        raise ValueError(f"{path}: no completed tests")
    if running or "running" in packages.values():
        raise ValueError(f"{path}: interrupted report, unfinished tests/packages")
    return results, packages


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def binding(path, platform, expected):
    metadata = read_json(str(path) + ".meta.json")
    required = dict(schema="trust-parity/v1", platform=platform, lane="trust",
                    job=JOBS[platform], sha256=digest(path), exit_code=0)
    required.update(expected)
    for key, value in required.items():
        if metadata.get(key) != value or (key == "exit_code" and type(metadata.get(key)) is not int):
            raise ValueError(f"{platform}: wrong metadata {key}")
    return metadata


def exceptions(path):
    if path is None:
        return {}
    entries = read_json(path)
    if not isinstance(entries, list):
        raise ValueError("exceptions must be a list")
    allowed = {}
    today = datetime.now(timezone.utc).date()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid exception")
        fields = {"package", "test", "platform", "reason", "owner", "review", "expires"}
        if set(entry) != fields or any(not isinstance(entry[k], str) or not entry[k].strip() for k in fields):
            raise ValueError("exception requires exact identity, platform, reason, owner, review and expiry")
        key = (entry["platform"], (entry["package"], entry["test"]))
        if key[0] not in JOBS or key[1] not in REQUIRED or key in allowed:
            raise ValueError("duplicate or out-of-scope exception")
        if date.fromisoformat(entry["expires"]) <= today:
            raise ValueError("expired exception")
        allowed[key] = entry
    return allowed


def record(argv):
    parser = argparse.ArgumentParser(description="Bind a successful producer report to GitHub context")
    parser.add_argument("path")
    parser.add_argument("--platform", choices=JOBS, required=True)
    args = parser.parse_args(argv)
    context = {key: os.environ.get(env) for key, env in (
        ("commit", "GITHUB_SHA"), ("run_id", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT"))}
    if not all(context.values()) or os.environ.get("GITHUB_JOB") != JOBS[args.platform]:
        raise ValueError("missing/wrong producer GitHub context")
    report(args.path)
    metadata = dict(context, schema="trust-parity/v1", platform=args.platform,
                    job=JOBS[args.platform], lane="trust", exit_code=0, sha256=digest(args.path))
    Path(args.path + ".meta.json").write_text(json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def main(argv):
    try:
        if len(argv) > 1 and argv[1] == "record":
            return record(argv[2:])
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("linux")
        parser.add_argument("windows")
        parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA"))
        parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
        parser.add_argument("--attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT"))
        parser.add_argument("--exceptions")
        args = parser.parse_args(argv[1:])
        expected = dict(commit=args.commit, run_id=args.run_id, attempt=args.attempt)
        sidecars = [Path(path + ".meta.json").exists() for path in (args.linux, args.windows)]
        bound = any(expected.values()) or any(sidecars)
        if bound and (not all(expected.values()) or not all(sidecars)):
            raise ValueError("binding requires commit, run ID, attempt and both metadata sidecars")
        if bound:
            print(f"BOUND: commit={args.commit} run={args.run_id} attempt={args.attempt}")
        else:
            print("UNBOUND: local oracle only; commit/run/attempt provenance not verified")
        allowed = exceptions(args.exceptions)
        used, errors = set(), []
        for platform in JOBS:
            path = getattr(args, platform)
            if bound:
                binding(path, platform, expected)
            results, packages = report(path)
            counts = Counter(results.values())
            missing = skipped = passed = waived = 0
            for identity in sorted(REQUIRED):
                status = results.get(identity, "missing")
                if status == "pass":
                    passed += 1
                    continue
                missing += status == "missing"
                skipped += status == "skip"
                exception = allowed.get((platform, identity))
                if exception:
                    used.add((platform, identity))
                    waived += 1
                    print(f"EXCEPTION (not PASS): {platform} {identity}: {exception}")
                else:
                    errors.append(f"{platform}: required {identity[0]}::{identity[1]} is {status}")
            print(f"{platform} lane=trust required={len(REQUIRED)} pass={passed} skip={skipped} "
                  f"missing={missing} exceptions={waived}; observed pass={counts['pass']} "
                  f"skip={counts['skip']} packages={len(packages)}")
            outside = set(results) - REQUIRED
            print(f"{platform}: {len(outside)} other identities outside reviewed parity scope")
            for identity in sorted(outside):
                parent = (identity[0], identity[1].split("/", 1)[0])
                classification = CLASSIFIED_PARENTS.get(parent, "unselected: no parity assertion")
                print(f"OUTSIDE SCOPE: {platform} {identity[0]}::{identity[1]} "
                      f"status={results[identity]} ({classification})")
        if set(allowed) != used:
            errors.append("unused exception: remove or review it")
        if errors:
            raise ValueError("\n".join(errors))
        print("OK: scoped parity satisfied" + (" with exceptions (not acceptance)" if used else ""))
        return 0
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
