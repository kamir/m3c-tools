#!/usr/bin/env python3
"""Provision the pinned Python prerequisite for synthetic dependency tests."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

PYTHON_VERSION = (3, 12, 14)
PACKAGING_VERSION = "26.3"
REQUIREMENTS = Path(__file__).with_name("dependency-test-requirements.txt")
PREFLIGHT = (
    "import json,sys,venv,importlib.metadata;import packaging.requirements;"
    "print(json.dumps({'python':list(sys.version_info[:3]),"
    "'packaging':importlib.metadata.version('packaging')}))"
)


def provision(directory, wheelhouse=None):
    """Publish the selected interpreter only after checked installation/preflight."""
    if sys.version_info[:3] != PYTHON_VERSION:
        raise ValueError("pinned Python is required")
    directory = Path(directory)
    if not directory.is_absolute() or directory.exists() or any(c in str(directory) for c in "\r\n\x00"):
        raise ValueError("a new absolute fixture directory is required")
    if wheelhouse is not None and not Path(wheelhouse).is_dir():
        raise ValueError("fixture wheelhouse is unavailable")
    subprocess.run([sys.executable, "-I", "-m", "venv", str(directory)],
                   check=True, timeout=120, stdin=subprocess.DEVNULL)
    executable = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    command = [str(executable), "-I", "-m", "pip", "--isolated", "install",
               "--require-hashes", "--only-binary=:all:", "--no-deps", "--no-compile",
               "--disable-pip-version-check", "-r", str(REQUIREMENTS)]
    if wheelhouse is not None:
        command.extend(["--no-index", "--find-links", str(Path(wheelhouse).resolve())])
    subprocess.run(command, check=True, timeout=120, stdin=subprocess.DEVNULL)
    result = subprocess.run([str(executable), "-I", "-B", "-c", PREFLIGHT],
                            check=True, timeout=30, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True)
    measured = json.loads(result.stdout)
    if measured != {"python": list(PYTHON_VERSION), "packaging": PACKAGING_VERSION}:
        raise ValueError("fixture prerequisite versions differ")
    destination = os.environ.get("GITHUB_ENV")
    if not destination:
        raise ValueError("GitHub environment output is required")
    with open(destination, "a", encoding="utf-8") as stream:
        stream.write(f"M3C_DEPENDENCY_TEST_PYTHON={executable}\n")
    print("dependency fixture Python and packaging versions verified")
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--wheelhouse")
    args = parser.parse_args()
    try:
        provision(args.directory, args.wheelhouse)
    except (ValueError, OSError, subprocess.SubprocessError):
        print("dependency fixture prerequisite failed; no interpreter was published", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
