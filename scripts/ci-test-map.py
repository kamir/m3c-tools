#!/usr/bin/env python3
"""Discover test assignments, check declared CI wiring, and run shared selections."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "scripts/ci-test-selection.json"


def json_stream(data):
    decoder = json.JSONDecoder()
    while data.strip():
        item, end = decoder.raw_decode(data.lstrip())
        yield item
        data = data.lstrip()[end:]


def selected(package, selector):
    selector = selector.rstrip("/")
    if selector.endswith("/..."):
        base = selector[:-4]
        return package == base or package.startswith(base + "/")
    return package == selector


def source_files(root):
    output = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    )
    return {p.decode() for p in output.split(b"\0") if p}


def discover_go(root, variants):
    root = root.resolve()
    packages = set()
    discoveries = []
    for variant in variants:
        env = dict(os.environ, GOOS=variant["goos"], GOARCH=variant["goarch"],
                   CGO_ENABLED=variant["cgo"], GOFLAGS="")
        # -e retains package/test-file metadata despite dependency errors.
        # This inventory does not typecheck dependencies or replace go test.
        output = subprocess.check_output(
            ["go", "list", "-e", "-json", "-tags=" + variant["tags"], "./..."],
            cwd=root, env=env, text=True,
        )
        found = set()
        for package in json_stream(output):
            if package.get("Error"):
                raise ValueError(str(package["Error"]))
            if package.get("TestGoFiles") or package.get("XTestGoFiles"):
                found.add("./" + Path(package["Dir"]).relative_to(root).as_posix())
        if not found:
            raise ValueError("empty Go test discovery: " + str(variant))
        packages.update(found)
        discoveries.append((variant, found))
    return packages, discoveries


def mapping_errors(config, go_packages, files, discoveries=None):
    errors = []
    go_lanes = [lane for lane in config["lanes"].values() if lane["kind"] == "go"]
    exceptions = {entry["package"] for entry in config["exceptions"] if entry["reason"].strip()}
    for package in sorted(go_packages):
        if package not in exceptions and not any(
            selected(package, selector) and (discoveries is None or any(
                variant["goos"] == lane["goos"] and package in found
                for variant, found in discoveries
            )) for lane in go_lanes for selector in lane["selectors"]
        ):
            errors.append("unassigned Go test package: " + package)
    for lane in go_lanes:
        for selector in lane["selectors"]:
            if not any(selected(p, selector) for p in go_packages):
                errors.append("selection has no test package: " + selector)
        for package in lane.get("mandatory", []):
            if package not in go_packages or not any(selected(package, s) for s in lane["selectors"]):
                errors.append("missing mandatory target: " + package)
        for package in lane.get("required_tests", {}):
            if package not in go_packages or not any(selected(package, s) for s in lane["selectors"]):
                errors.append("required Go test package outside lane selection: " + package)
    for package in exceptions - go_packages:
        errors.append("stale Go exception: " + package)
    # A directory outside the metadata union needs a new build variant, not a
    # silent exception. testdata contains inputs, not independently run packages.
    for file in sorted(files):
        path = Path(file)
        if "testdata" in path.parts:
            continue
        if file.endswith("_test.go") and "./" + path.parent.as_posix() not in go_packages:
            errors.append("Go test directory absent from build variants: " + str(path.parent))
        if file.endswith(".py") and (path.name.startswith("test_") or
                                     path.name.endswith(("_test.py", ".test.py"))):
            covered = any(
                lane["kind"] == "pytest" and path.parent.as_posix() == lane["directory"]
                for lane in config["lanes"].values()
            ) or any(entry["file"] == file for entry in config["python_contracts"])
            if not covered:
                errors.append("unassigned Python test: " + file)
    for entry in config["python_contracts"]:
        if entry["file"] not in files:
            errors.append("missing Python contract: " + entry["file"])
    for lane in config["lanes"].values():
        if lane["kind"] == "pytest" and not any(
            str(Path(p).parent) == lane["directory"] and Path(p).name.startswith("test_")
            and p.endswith(".py") for p in files
        ):
            errors.append("Python selection has no tests: " + lane["directory"])
    return errors


def workflow_errors(root, config):
    # Parse YAML structure. Only compare our literal invocation contract; do not
    # try to infer arbitrary shell control flow or reusable workflow execution.
    import yaml

    errors = []
    required = {line.split(None, 2)[2] for line in
                (root / "docs/security/required-checks.txt").read_text().splitlines()
                if line.startswith("workflow ")}

    def require_step(workflow, job_id, command, condition=None):
        data = yaml.safe_load((root / ".github/workflows" / workflow).read_text())
        events = data.get("on", data.get(True, {}))
        job = data.get("jobs", {}).get(job_id, {})
        if not isinstance(events, dict) or "pull_request" not in events or events["pull_request"] not in (None, {}):
            errors.append("requires unfiltered pull_request: " + workflow)
        if job.get("name") not in required or "if" in job or "needs" in job:
            errors.append("required job changed or conditional: " + job_id)
        matches = [step for step in job.get("steps", []) if step.get("run", "").strip() == command]
        if len(matches) != 1 or matches[0].get("if") != condition or matches[0].get("continue-on-error", False):
            errors.append("missing or conditional invocation: " + command)
        if job.get("continue-on-error", False):
            errors.append("job tolerates failures: " + job_id)

    for name, lane in config["lanes"].items():
        if lane["kind"] == "pytest":
            require_step("ci.yml", lane["job"], "./" + lane["via"])
            call = '"$PYTHON" scripts/ci-test-map.py run ' + name
            if (root / lane["via"]).read_text().splitlines().count("  " + call) != 1:
                errors.append("missing Python runner invocation: " + name)
        else:
            require_step("ci.yml", lane["job"], "python3 scripts/ci-test-map.py run " + name,
                         lane.get("step_if"))
            data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
            runner = data["jobs"][lane["job"]].get("runs-on", "")
            prefix = {"darwin": "macos-", "linux": "ubuntu-", "windows": "windows-"}[lane["goos"]]
            if not isinstance(runner, str) or not runner.startswith(prefix):
                errors.append("Go lane platform needs review: " + name)
    for entry in config["python_contracts"]:
        require_step(entry["workflow"], entry["job"], entry["command"])
    require_step("ci.yml", "python-gate", "python3 scripts/ci-test-map.py check")
    data = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    for job_id in {lane["job"] for lane in config["lanes"].values()}:
        uploads = [step for step in data["jobs"][job_id]["steps"]
                   if step.get("uses", "").startswith("actions/upload-artifact@")
                   and step.get("with", {}).get("path") == "test-results/"]
        condition = "always()"
        if job_id == "skillctl-race":
            condition += " && steps.classify.outputs.code == 'true'"
        if len(uploads) != 1 or uploads[0].get("if") != condition or \
                uploads[0].get("with", {}).get("if-no-files-found") != "error":
            errors.append("missing or conditional result upload: " + job_id)
    errors.extend(native_mcp_workflow_errors(root))
    return errors


def native_mcp_workflow_errors(root):
    """The required native bridge cannot silently lose its Python producer."""
    import yaml

    errors = []
    data = yaml.safe_load((root / ".github/workflows/windows-gate.yml").read_text())
    events = data.get("on", data.get(True, {}))
    if not isinstance(events, dict) or "pull_request" not in events or events["pull_request"] not in (None, {}):
        errors.append("requires unfiltered native MCP pull_request")
    for name, prefix in (("windows-trust", "win"), ("drift-guard", "lin")):
        job = data.get("jobs", {}).get(name, {})
        if "if" in job or job.get("continue-on-error", False) or job.get("runs-on") != (
            "windows-latest" if prefix == "win" else "ubuntu-latest"
        ):
            errors.append("conditional or wrong-platform native MCP job: " + name)
        steps = job.get("steps", [])
        setup = [(i, s) for i, s in enumerate(steps) if s.get("id") == "dependency-python"]
        provision = [(i, s) for i, s in enumerate(steps) if s.get("name") == "Provision native MCP fixture Python"]
        units = [(i, s) for i, s in enumerate(steps) if s.get("name") == "Native MCP process and lifecycle unit contracts"]
        go = [(i, s) for i, s in enumerate(steps) if "go test " in s.get("run", "") and
              ("Tee-Object -FilePath win-trust.json" in s["run"] or "tee lin-trust.json" in s["run"])]
        if any(len(rows) != 1 for rows in (setup, provision, units, go)):
            errors.append("missing native MCP producer: " + name)
            continue
        indices = [rows[0][0] for rows in (setup, provision, units, go)]
        if indices != sorted(indices) or len(set(indices)) != 4:
            errors.append("native MCP producer order changed: " + name)
        if (setup[0][1].get("uses") != "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
                or setup[0][1].get("with", {}).get("python-version") != "3.14.9"):
            errors.append("unpinned native MCP Python: " + name)
        if any("if" in step or step.get("continue-on-error", False) for _, step in (setup[0], go[0])):
            errors.append("conditional native MCP runtime or integration: " + name)
        interpreter = '"${{ steps.dependency-python.outputs.python-path }}"'
        lead = "& " if prefix == "win" else ""
        commands = [lead + interpreter + ' scripts/setup-native-mcp-python.py --directory "${{ runner.temp }}/native-mcp-python"',
                    lead + interpreter + f' scripts/setup-native-mcp-python.py --run-tests "${{{{ github.workspace }}}}/{prefix}-native-mcp.xml"']
        for (_, step), expected in zip((provision[0], units[0]), commands):
            lines = step.get("run", "").strip().splitlines()
            wanted = [expected] + (["if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"] if prefix == "win" else [])
            if lines != wanted or "if" in step or step.get("continue-on-error", False):
                errors.append("conditional or changed native MCP invocation: " + name)
        for scope in [job, *[s for _, s in (setup[0], provision[0], units[0], go[0])]]:
            if any(key in scope.get("env", {}) for key in ("M3C_MCP_TEST_PYTHON", "M3C_REQUIRE_NATIVE_MCP_TESTS")):
                errors.append("native MCP prerequisite overridden: " + name)
        uploads = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@") and
                   f"{prefix}-native-mcp.xml" in s.get("with", {}).get("path", "").splitlines()]
        if (len(uploads) != 1 or uploads[0].get("if") != "always()" or uploads[0].get("continue-on-error", False) or
                uploads[0].get("with", {}).get("if-no-files-found") != "error" or
                f"{prefix}-native-mcp.xml.meta.json" not in uploads[0].get("with", {}).get("path", "").splitlines()):
            errors.append("native MCP raw evidence upload missing: " + name)
    return errors


def check(root, config):
    packages, discoveries = discover_go(root, config["variants"])
    files = source_files(root)
    errors = mapping_errors(config, packages, files, discoveries) + workflow_errors(root, config)
    for variant, found in discoveries:
        print(f"Go metadata {variant}: {len(found)} test packages")
    print(f"Assignments: {len(packages)} Go test packages; "
          f"{len({str(Path(p).parent) for p in files if p.endswith('.py') and ('test' in Path(p).name)})} "
          f"Python test directories; {len(errors)} violations")
    for entry in config["exceptions"]:
        print("Separate lane: " + entry["package"] + ": " + entry["reason"])
    for error in errors:
        print(error, file=sys.stderr)
    return bool(errors)


def result_validators():
    spec = importlib.util.spec_from_file_location("ci_artifacts", ROOT / "scripts/ci-test-artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_go(path, expected, lane=None):
    return result_validators().go_counts(path, expected, lane or {})


def run_lane(root, name, lane, results):
    results.mkdir(parents=True, exist_ok=True)
    go = lane["kind"] == "go"
    raw = results / (name + (".jsonl" if go else ".xml"))
    log = results / (name + ".log")
    metadata_path = results / (name + ".meta.json")
    for path in (raw, log, metadata_path):
        path.unlink(missing_ok=True)
    if go:
        command = ["go", "test", "-json", "-count=1"]
        if lane.get("race"):
            command.append("-race")
        if "run" in lane:
            command.extend(["-run", lane["run"]])
        command.extend(lane["selectors"])
        cwd = root
        metadata = subprocess.check_output(
            ["go", "list", "-e", "-json", *lane["selectors"]], cwd=root,
            env=dict(os.environ, GOFLAGS=""), text=True,
        )
        expected = {p["ImportPath"] for p in json_stream(metadata)
                    if p.get("TestGoFiles") or p.get("XTestGoFiles")}
    else:
        command = [sys.executable, "-m", "pytest", "-q", "--junitxml=" + str(raw)]
        cwd = root / lane["directory"]
    toolchain = subprocess.check_output(["go", "version"] if go else [sys.executable, "--version"], text=True).strip()
    platform = subprocess.check_output(["go", "env", "GOOS", "GOARCH"], text=True).split()
    record = dict(lane=name, commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                  github_sha=os.getenv("GITHUB_SHA"), run_id=os.getenv("GITHUB_RUN_ID"),
                  attempt=os.getenv("GITHUB_RUN_ATTEMPT"), job=os.getenv("GITHUB_JOB"),
                  platform=platform, toolchain=toolchain, command=command, selection=lane)
    if go:
        record["expected_test_packages"] = sorted(expected)
    env = dict(os.environ, GOFLAGS="", M3C_TOKEN_STORE="file", M3C_TEST_KEYCHAIN="0", M3C_ER1_KEYCHAIN="off",
               PYTHONDONTWRITEBYTECODE="1")
    # Preserve the tool caches before replacing user paths for config tests.
    for key in ("GOPATH", "GOMODCACHE", "GOCACHE"):
        if key not in env:
            env[key] = subprocess.check_output(["go", "env", key], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="ci-test-home-") as home:
        env.update(HOME=home, USERPROFILE=home)
        if go:
            with raw.open("w") as output, log.open("w") as errors:
                code = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=errors).returncode
        else:
            with log.open("w") as output:
                code = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT).returncode
    record["exit_code"] = code
    try:
        if go:
            record["test_terminal_counts"] = validate_go(raw, expected, lane)
        else:
            record["test_counts"] = result_validators().python_counts(raw.read_bytes(), lane.get("required_cases", []))
    except (ValueError, OSError, ET.ParseError) as error:
        record["validation_error"] = str(error)
        code = code or 1
    record["runner_exit_code"] = code
    if raw.exists():
        record["result_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"{name}: exit {code}; results {raw}")
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "run"])
    parser.add_argument("lane", nargs="?")
    parser.add_argument("--results", type=Path, default=ROOT / "test-results")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text())
    try:
        if args.action == "check":
            return check(ROOT, config)
        lane = config["lanes"][args.lane]
        return run_lane(ROOT, args.lane, lane, args.results.resolve())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("ci-test-map: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
