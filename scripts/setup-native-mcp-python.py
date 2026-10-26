#!/usr/bin/env python3
"""Provision the explicit MCP interpreter used by native process tests."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

PYTHON_VERSION = (3, 14, 9)
PYTEST_VERSION = "8.3.5"
REQUIREMENTS = Path(__file__).resolve().parents[1] / "rag-mcp-server/requirements.txt"
ROOT = REQUIREMENTS.parent.parent
UNIT_CASES = [
    {"classname": "test_native_agent_session", "name": name}
    for name in ("test_native_agent_startup_binding", "test_native_agent_session_protocol",
                 "test_native_agent_session_cleanup")
]
UNIT_CASES += [{"classname": "test_native_skill_session", "name": name}
               for name in ("test_native_skill_startup_binding", "test_native_skill_session_lifecycle")]
UNIT_CASES += [{"classname": "test_native_git_session", "name": name}
               for name in ("test_native_git_startup_binding", "test_native_git_session_lifecycle")]
UNIT_FILES = ["test_native_agent_binding.py", "test_native_agent_protocol.py",
              "test_native_agent_session.py", "test_native_skill_session.py", "test_native_git_session.py"]
PREFLIGHT = (
    "import json,sys,importlib.metadata;from mcp.server.fastmcp import FastMCP;"
    "from mcp import ClientSession;from mcp.client.stdio import stdio_client;"
    "import pytest,yaml;print(json.dumps({'python':list(sys.version_info[:3]),"
    "'mcp':importlib.metadata.version('mcp'),'pytest':pytest.__version__,"
    "'PyYAML':importlib.metadata.version('PyYAML')}))"
)


def runtime_pins():
    """Read the same direct runtime pins as the required Python producer."""
    pins = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        if line.startswith(("mcp", "PyYAML")):
            match = re.fullmatch(r"(mcp|PyYAML)==([0-9]+\.[0-9]+\.[0-9]+)", line)
            if match is None or match[1] in pins:
                raise ValueError("ambiguous MCP runtime pin")
            pins[match[1]] = match[2]
    if set(pins) != {"mcp", "PyYAML"}:
        raise ValueError("missing MCP runtime pins")
    return pins


def provision(directory, wheelhouse=None):
    """Export the runtime only after installation and actual imports succeed.

    Direct pins constrain this fixture; the emitted package inventory records
    resolved transitive versions and is not a fully reproducible lock claim.
    """
    if sys.version_info[:3] != PYTHON_VERSION:
        raise ValueError("pinned Python is required")
    directory = Path(directory)
    destination = os.environ.get("GITHUB_ENV", "")
    if not directory.is_absolute() or directory.exists() or any(c in str(directory) for c in "\r\n\x00"):
        raise ValueError("new absolute fixture directory required")
    if not destination or any(c in destination for c in "\r\n\x00"):
        raise ValueError("GitHub environment output required")
    if wheelhouse is not None and not Path(wheelhouse).is_dir():
        raise ValueError("fixture wheelhouse unavailable")
    pins = runtime_pins()
    subprocess.run([sys.executable, "-I", "-m", "venv", str(directory)],
                   check=True, timeout=120, stdin=subprocess.DEVNULL)
    executable = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    command = [str(executable), "-I", "-m", "pip", "--isolated", "install", "--no-input",
               "--only-binary=:all:", "--disable-pip-version-check", "--no-compile",
               f"mcp=={pins['mcp']}", f"PyYAML=={pins['PyYAML']}", f"pytest=={PYTEST_VERSION}"]
    if wheelhouse is None:
        command += ["--index-url", "https://pypi.org/simple"]
    else:
        command += ["--no-index", "--find-links", str(Path(wheelhouse).resolve())]
    subprocess.run(command, check=True, timeout=180, stdin=subprocess.DEVNULL)
    result = subprocess.run([str(executable), "-I", "-B", "-c", PREFLIGHT], check=True,
                            timeout=30, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    expected = {"python": list(PYTHON_VERSION), **pins, "pytest": PYTEST_VERSION}
    if json.loads(result.stdout) != expected:
        raise ValueError("MCP prerequisite versions differ")
    # Record the complete resolved inventory, including platform dependencies.
    subprocess.run([str(executable), "-I", "-m", "pip", "--isolated", "list", "--format=json"],
                   check=True, timeout=30, stdin=subprocess.DEVNULL)
    output = f"M3C_MCP_TEST_PYTHON={executable}\nM3C_REQUIRE_NATIVE_MCP_TESTS=1\n"
    with open(destination, "a", encoding="utf-8", newline="\n") as stream:
        if stream.write(output) != len(output):
            raise OSError("short prerequisite export")
    print("native MCP interpreter and import versions verified")
    return executable


def report_counts(blob):
    spec = importlib.util.spec_from_file_location("native_mcp_evidence", ROOT / "scripts/ci-test-artifacts.py")
    consumer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumer)
    counts = consumer.python_counts(blob, UNIT_CASES)
    if counts["skipped"]:
        raise ValueError("native MCP unit cases were skipped")
    return counts


def run_native_units(report):
    """Execute the selected runtime and bind its actual unit report to this job."""
    platform = {"win32": "windows", "linux": "linux"}.get(sys.platform)
    job = {"windows": "windows-trust", "linux": "drift-guard"}.get(platform)
    if job is None or os.environ.get("GITHUB_JOB") != job:
        raise ValueError("wrong native MCP producer")
    context = {key: os.environ.get(env, "") for key, env in
               (("commit", "GITHUB_SHA"), ("run_id", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT"))}
    if not re.fullmatch(r"[0-9a-f]{40}", context["commit"]) or not all(
        re.fullmatch(r"[1-9][0-9]*", context[key]) for key in ("run_id", "attempt")
    ):
        raise ValueError("missing native MCP producer context")
    executable = os.environ.get("M3C_MCP_TEST_PYTHON", "")
    if (os.environ.get("M3C_REQUIRE_NATIVE_MCP_TESTS") != "1" or not Path(executable).is_absolute()
            or not Path(executable).is_file() or any(c in executable for c in "\r\n\x00")):
        raise ValueError("explicit native MCP interpreter is required")
    report = Path(report)
    sidecar = Path(str(report) + ".meta.json")
    if not report.is_absolute() or report.exists() or sidecar.exists() or report.is_symlink():
        raise ValueError("new absolute native MCP report is required")
    command = [executable, "-I", "-B", "-m", "pytest", "-q", *UNIT_FILES,
               "-k", "not test_native_agent_retained_session_stdio and not test_native_skill_retained_session_stdio and not test_native_git_retained_session_stdio", "--junitxml=" + str(report)]
    subprocess.run(command, cwd=ROOT / "mcp-skill-server", check=True, timeout=180,
                   stdin=subprocess.DEVNULL)
    if report.is_symlink() or not report.is_file() or report.stat().st_size > 32 << 20:
        raise ValueError("missing or oversized native MCP report")
    blob = report.read_bytes()
    counts = report_counts(blob)
    metadata = dict(context, schema="native-mcp-units/v1", platform=platform, job=job,
                    exit_code=0, sha256=hashlib.sha256(blob).hexdigest(), counts=counts,
                    required_cases=UNIT_CASES, test_files=UNIT_FILES,
                    excluded_case="test_native_agent_retained_session_stdio",
                    integration_requirement="TestNativeAgentRetainedMCPSubprocess",
                    excluded_cases=["test_native_agent_retained_session_stdio",
                                    "test_native_skill_retained_session_stdio",
                                    "test_native_git_retained_session_stdio"],
                    integration_requirements=["TestNativeAgentRetainedMCPSubprocess",
                                              "TestNativeSkillRetainedMCPSubprocess",
                                              "TestNativeGitRetainedMCPSubprocess"])
    with sidecar.open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2)
        stream.write("\n")
    print(json.dumps(metadata, sort_keys=True))
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--directory")
    action.add_argument("--run-tests")
    parser.add_argument("--wheelhouse")
    args = parser.parse_args()
    try:
        if args.run_tests:
            if args.wheelhouse:
                raise ValueError("wheelhouse is only valid for provisioning")
            run_native_units(args.run_tests)
        else:
            provision(args.directory, args.wheelhouse)
    except (ValueError, OSError, subprocess.SubprocessError, ET.ParseError):
        print("native MCP prerequisite failed; do not run the required producer", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
