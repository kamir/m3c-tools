#!/usr/bin/env python3
"""Offline control-flow contracts using synthetic assets and executable stubs."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/skillctl-smoke.sh"
WORKFLOW = ROOT / ".github/workflows/skillctl-smoke-matrix.yml"


class SmokeContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in ("uname", "tr", "sed", "awk", "shasum", "cp", "mktemp", "rm", "mkdir", "chmod"):
            resolved = shutil.which(tool)
            if not resolved:
                self.fail(f"test prerequisite absent: {tool}")
            (self.bin / tool).symlink_to(resolved)
        sha256sum = shutil.which("sha256sum")
        if sha256sum:
            (self.bin / "sha256sum").symlink_to(sha256sum)
        self.trace = self.root / "executed"
        self.env = os.environ.copy()
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "M3C_REGISTRY_TOKEN", "M3C_REGISTRY_TOKEN_RO"):
            self.env.pop(name, None)
        self.env.update(PATH=str(self.bin), SMOKE_TARGET="linux/amd64", SMOKE_REQUIRED="1",
                        SMOKE_STAGED_REQUIRED="1", SMOKE_ASSET_DIR=str(self.assets),
                        TRACE=str(self.trace), COSIGN_TRACE=str(self.root / "cosign-trace"),
                        NET_TRACE=str(self.root / "network"), FAKE_VERSION="skillctl/v9.8.7",
                        TMPDIR=str(self.root), HOME=str(self.root / "original-home"),
                        USERPROFILE=str(self.root / "different-profile"))
        self.cli = b'''#!/bin/sh
[ "$HOME" = "$USERPROFILE" ] || exit 81
[ "$M3C_TOKEN_STORE:$M3C_TEST_KEYCHAIN:$M3C_ER1_KEYCHAIN" = "file:0:off" ] || exit 82
printf '%s\\n' "$1" >> "$TRACE"
[ "${FAKE_FAIL_COMMAND:-}" != "$1" ] || exit 7
if [ "$1" = version ]; then printf '%s\\n' "$FAKE_VERSION"; fi
'''
        self.stub("cosign", '''printf '%s\\n' "$@" > "$COSIGN_TRACE"
exit "${COSIGN_EXIT:-0}"
''')
        self.stub("curl", 'printf network >> "$NET_TRACE"; exit 7\n')
        self.stub("gh", 'printf network >> "$NET_TRACE"; exit 7\n')
        self.asset("linux/amd64")
        (self.assets / "SHA256SUMS.cosign.bundle").write_text("synthetic verifier fixture\n")

    def stub(self, name, body):
        p = self.bin / name
        if p.is_symlink():
            p.unlink()
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)

    def asset(self, target):
        name = "skillctl-" + target.replace("/", "-")
        (self.assets / name).write_bytes(self.cli)
        (self.assets / "SHA256SUMS").write_text(f"{hashlib.sha256(self.cli).hexdigest()}  {name}\n")

    def run_smoke(self):
        return subprocess.run(["/bin/bash", str(SCRIPT), "skillctl/v9.8.7"], env=self.env,
                              capture_output=True, text=True, timeout=15)

    def refuses_before_execution(self):
        result = self.run_smoke()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.trace.exists(), result.stdout + result.stderr)
        return result

    def test_required_positive_and_isolation(self):
        result = self.run_smoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SMOKE PASS", result.stdout)
        self.assertIn("verify-sig", self.trace.read_text())
        args = (self.root / "cosign-trace").read_text().splitlines()
        self.assertIn("--certificate-identity", args)
        self.assertIn("https://github.com/kamir/m3c-tools/.github/workflows/skillctl-release.yml@refs/tags/skillctl/v9.8.7", args)
        self.assertFalse((self.root / "network").exists())

    def test_explicit_target_selects_actual_asset(self):
        # Stubs simulate host identity only; these are not native platform runs.
        self.stub("uname", 'case "$1" in -s) printf Darwin;; -m) printf arm64;; esac\n')
        for target in ("darwin/amd64", "darwin/arm64", "linux/arm64", "linux/amd64"):
            with self.subTest(target=target):
                self.env["SMOKE_TARGET"] = target
                self.asset(target)
                result = self.run_smoke()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("skillctl-" + target.replace("/", "-"), result.stdout)

    def test_unknown_target_refused(self):
        self.env["SMOKE_TARGET"] = "darwin/../../different"
        self.assertEqual(self.refuses_before_execution().returncode, 2)

    def test_hash_mismatch_refused_before_execution(self):
        (self.assets / "skillctl-linux-amd64").write_bytes(self.cli + b"# changed\n")
        self.refuses_before_execution()

    def test_bad_missing_duplicate_digest_refused(self):
        original = (self.assets / "SHA256SUMS").read_text()
        for contents in ("", original + original, "not-a-digest  skillctl-linux-amd64\n"):
            with self.subTest(contents=contents):
                (self.assets / "SHA256SUMS").write_text(contents)
                self.refuses_before_execution()

    def test_missing_staged_inputs_never_download(self):
        for name in ("skillctl-linux-amd64", "SHA256SUMS", "SHA256SUMS.cosign.bundle"):
            with self.subTest(name=name):
                p = self.assets / name
                saved = p.read_bytes()
                p.unlink()
                self.refuses_before_execution()
                self.assertFalse((self.root / "network").exists())
                p.write_bytes(saved)

    def test_missing_cosign_refused(self):
        (self.bin / "cosign").unlink()
        self.refuses_before_execution()

    def test_required_mode_is_default(self):
        self.env.pop("SMOKE_REQUIRED")
        (self.bin / "cosign").unlink()
        self.refuses_before_execution()

    def test_bad_cosign_refused(self):
        self.env["COSIGN_EXIT"] = "7"
        self.refuses_before_execution()

    def test_wrong_version_stops_before_lifecycle(self):
        for version in ("skillctl/v9.8.70", "prefix9.8.7suffix", "dev"):
            with self.subTest(version=version):
                self.env["FAKE_VERSION"] = version
                if self.trace.exists():
                    self.trace.unlink()
                result = self.run_smoke()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.trace.read_text().splitlines(), ["version"])

    def test_lifecycle_failure_cannot_pass(self):
        self.env["FAKE_FAIL_COMMAND"] = "keygen"
        result = self.run_smoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("SMOKE PASS", result.stdout)

    def test_manual_optional_mode_is_explicit(self):
        (self.bin / "cosign").unlink()
        self.env.update(SMOKE_REQUIRED="0", FAKE_VERSION="dev")
        result = self.run_smoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MANUAL OPTIONAL SMOKE COMPLETE", result.stdout)
        self.assertNotIn("SMOKE PASS", result.stdout)

    def test_workflow_required_mapping_and_no_staging_override(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        job = workflow["jobs"]["smoke"]
        rows = job["strategy"]["matrix"]["include"]
        self.assertEqual({r["name"]: r["target"] for r in rows}, {
            "macos-arm64": "darwin/arm64", "macos-amd64": "darwin/amd64",
            "linux-amd64": "linux/amd64", "linux-arm64": "linux/arm64",
            "windows-amd64": "windows/amd64"})
        steps = {s.get("name"): s for s in job["steps"]}
        env = steps["Smoke (macOS/Linux)"]["env"]
        self.assertEqual(env["SMOKE_TARGET"], "${{ matrix.target }}")
        self.assertEqual(env["SMOKE_REQUIRED"], "1")
        self.assertEqual(env["SMOKE_STAGED_REQUIRED"], "${{ github.event_name != 'workflow_dispatch' && '1' || '0' }}")
        for name in ("Stage binaries + SHA256SUMS (skillctl-dist)", "Stage cosign bundle (skillctl-cosign-bundle)"):
            self.assertNotIn("continue-on-error", steps[name])
            self.assertIn("github.event_name != 'workflow_dispatch'", steps[name]["if"])
        self.assertIn("required same-run binary/checksums absent", steps["Smoke (Windows)"]["run"])


if __name__ == "__main__":
    unittest.main()
