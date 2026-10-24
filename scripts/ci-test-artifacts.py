#!/usr/bin/env python3
"""Require complete current-run test evidence from the declared CI producers."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PRODUCERS = {"test", "docs-gate", "python-gate", "skillctl-race"}
CONDITION = "steps.classify.outputs.code == 'true'"
MODULE = "github.com/kamir/m3c-tools"
MAX_BYTES = 256 * 1024 * 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("missing, linked or oversized evidence: " + str(path))
    return path.read_bytes()


def read_json(path):
    return json.loads(read_file(path), object_pairs_hook=unique_object)


def load_parity():
    spec = importlib.util.spec_from_file_location("trust_parity", ROOT / "scripts/windows-trust-parity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected(package, selector):
    selector = MODULE + selector.rstrip("/")[1:]
    if selector.endswith("/..."):
        base = selector[:-4]
        return package == base or package.startswith(base + "/")
    return package == selector


def expected_lanes(config, needs):
    if set(needs) != PRODUCERS:
        raise ValueError("missing or unexpected producer jobs")
    for name, job in needs.items():
        if job.get("result") != "success":
            raise ValueError("producer did not succeed: " + name)
    code = needs["test"].get("outputs", {}).get("code")
    if code not in {"true", "false"}:
        raise ValueError("missing code/prose classification")
    lanes = {}
    for name, lane in config["lanes"].items():
        if lane["job"] not in PRODUCERS:
            raise ValueError("unreviewed producer: " + lane["job"])
        condition = lane.get("step_if")
        if condition is not None and condition != CONDITION:
            raise ValueError("unreviewed lane condition: " + name)
        if condition is None or code == "true":
            lanes[name] = lane
    return lanes


def python_counts(blob):
    root = ET.fromstring(blob)
    if root.tag not in {"testsuites", "testsuite"}:
        raise ValueError("unsupported JUnit root")
    cases = list(root.iter("testcase"))
    if any(not case.get("name", "").strip() for case in cases):
        raise ValueError("JUnit case has no identity")
    for suite in (node for node in root.iter() if node.tag in {"testsuite", "testsuites"}):
        if suite.find("error") is not None or suite.find("failure") is not None:
            raise ValueError("JUnit suite error")
        members = list(suite.iter("testcase"))
        actual = dict(tests=len(members), skipped=sum(c.find("skipped") is not None for c in members),
                      errors=sum(c.find("error") is not None for c in members),
                      failures=sum(c.find("failure") is not None for c in members))
        for field, value in actual.items():
            if field in suite.attrib and int(suite.attrib[field]) != value:
                raise ValueError("inconsistent JUnit suite " + field)
    skipped = sum(c.find("skipped") is not None for c in cases)
    failed = sum(c.find("failure") is not None or c.find("error") is not None for c in cases)
    if not cases or failed or len(cases) == skipped:
        raise ValueError("no successful Python tests or failed cases")
    return dict(total=len(cases), skipped=skipped, failed=failed)


def go_counts(path, expected, lane, parity=None):
    results, packages = (parity or load_parity()).report(path)
    if not expected or any(packages.get(package) != "pass" for package in expected):
        raise ValueError("missing or unsuccessful Go package result")
    for package in expected:
        if not any(p == package and status == "pass" for (p, _), status in results.items()):
            raise ValueError("Go package has no successful test: " + package)
    for package, names in lane.get("required_tests", {}).items():
        imported = MODULE + package.rstrip("/")[1:]
        if imported not in expected or not names or any(results.get((imported, name)) != "pass" for name in names):
            raise ValueError("missing successful mandatory Go scenario: " + package)
    if lane.get("allow_test_skips") is False and "skip" in results.values():
        raise ValueError("unexpected skip in mandatory Go lane")
    return {action: sum(status == action for status in results.values()) for action in ("pass", "skip", "fail")}


def verify_lane(folder, name, lane, context, parity):
    metadata = read_json(folder / (name + ".meta.json"))
    required = dict(context, lane=name, job=lane["job"], selection=lane)
    required["github_sha"] = context["commit"]
    for field, value in required.items():
        if metadata.get(field) != value:
            raise ValueError(f"{name}: wrong metadata {field}")
    for field in ("exit_code", "runner_exit_code"):
        if type(metadata.get(field)) is not int or metadata[field] != 0:
            raise ValueError(f"{name}: unsuccessful {field}")
    if "validation_error" in metadata:
        raise ValueError(name + ": producer validation failed")
    platform = metadata.get("platform")
    if not isinstance(platform, list) or len(platform) != 2 or not all(platform):
        raise ValueError(name + ": missing platform")
    if lane["kind"] == "go" and platform[0] != lane["goos"]:
        raise ValueError(name + ": wrong platform")
    if lane["kind"] == "pytest" and platform[0] != "linux":
        raise ValueError(name + ": wrong Python producer platform")
    if not isinstance(metadata.get("toolchain"), str) or not metadata["toolchain"].strip():
        raise ValueError(name + ": missing toolchain")
    raw = folder / (name + (".jsonl" if lane["kind"] == "go" else ".xml"))
    blob = read_file(raw)
    if hashlib.sha256(blob).hexdigest() != metadata.get("result_sha256"):
        raise ValueError(name + ": result digest mismatch")
    if lane["kind"] == "go":
        expected = metadata.get("expected_test_packages")
        if not isinstance(expected, list) or not expected or len(expected) != len(set(expected)):
            raise ValueError(name + ": missing/duplicate package inventory")
        if any(not isinstance(p, str) or not any(selected(p, s) for s in lane["selectors"]) for p in expected):
            raise ValueError(name + ": foreign package inventory")
        for package in lane.get("mandatory", []):
            if MODULE + package.rstrip("/")[1:] not in expected:
                raise ValueError(name + ": missing mandatory package")
        counts = go_counts(raw, set(expected), lane, parity)
        if metadata.get("test_terminal_counts") != counts:
            raise ValueError(name + ": inconsistent test counts")
    elif lane["kind"] == "pytest":
        counts = python_counts(blob)
        if metadata.get("test_counts") != counts:
            raise ValueError(name + ": inconsistent Python counts")
    else:
        raise ValueError(name + ": unsupported report kind")
    return counts


def verify(root, config, needs, context):
    if not re.fullmatch(r"[0-9a-f]{40}", context["commit"]):
        raise ValueError("invalid tested commit")
    if not all(re.fullmatch(r"[1-9][0-9]*", context[k]) for k in ("run_id", "attempt")):
        raise ValueError("invalid run/attempt")
    lanes = expected_lanes(config, needs)
    suffix = f"-{context['commit']}-{context['run_id']}-{context['attempt']}"
    directories = {"test-records-" + lane["job"] + suffix for lane in lanes.values()}
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != directories:
        raise ValueError("missing or unexpected producer artifact")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("linked evidence is not allowed")
    parity = load_parity()
    verified = {}
    for directory in directories:
        folder = root / directory
        members = {name: lane for name, lane in lanes.items() if directory == "test-records-" + lane["job"] + suffix}
        expected_files = {name + ending for name, lane in members.items()
                          for ending in (".meta.json", ".log", ".jsonl" if lane["kind"] == "go" else ".xml")}
        if not folder.is_dir() or {p.name for p in folder.iterdir()} != expected_files:
            raise ValueError("missing or unexpected lane files: " + directory)
        if any(not p.is_file() or p.stat().st_size > MAX_BYTES for p in folder.iterdir()):
            raise ValueError("non-file or oversized lane evidence: " + directory)
        for name, lane in members.items():
            verified[name] = verify_lane(folder, name, lane, context, parity)
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--commit", default=os.getenv("GITHUB_SHA"))
    parser.add_argument("--run-id", default=os.getenv("GITHUB_RUN_ID"))
    parser.add_argument("--attempt", default=os.getenv("GITHUB_RUN_ATTEMPT"))
    args = parser.parse_args()
    try:
        config = read_json(ROOT / "scripts/ci-test-selection.json")
        needs = json.loads(os.environ["TEST_PRODUCER_RESULTS"], object_pairs_hook=unique_object)
        context = dict(commit=args.commit, run_id=args.run_id, attempt=args.attempt)
        results = verify(args.root, config, needs, context)
        print(json.dumps(dict(expected_lanes=len(expected_lanes(config, needs)), verified_lanes=len(results),
                              context=context, results=results), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError) as error:
        print("ci-test-artifacts: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
