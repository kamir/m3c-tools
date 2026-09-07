"""Unit tests for the three SPEC-0188 MCP tools added in stream S11-mcp:
skill_install, skill_verify, skill_attest.

We mock subprocess.run so the tests don't need a real skillctl binary in
CI. Each test asserts on:
  - the argv that was passed to the subprocess (input shape, no shell=True)
  - the dict shape the tool returned (output contract)
  - the exit-code → error_class mapping (SPEC-0188 §11)

Run:
    cd mcp-skill-server
    python3 -m pytest test_spec0188_tools.py -v
"""

from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import patch

import pytest

# Importing the module registers the FastMCP tools as side effect; we then
# call the underlying coroutines directly via their __wrapped__ attribute
# (FastMCP wraps the user function but keeps the original accessible).
import server  # noqa: E402

# The FastMCP @mcp.tool() decorator returns the original function unchanged
# in the version we use, but we look it up defensively below so the test
# survives a future decorator change.


def _run(coro):
    """Helper: run an async tool coroutine to completion.

    asyncio.run, not get_event_loop().run_until_complete: the latter raises a
    DeprecationWarning on 3.12 and a RuntimeError from 3.14 on, which would
    have turned this suite red the first time the CI runner moved forward.
    """
    return asyncio.run(coro)


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    """Build a CompletedProcess-shape that subprocess.run would return."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=True)
def fake_skillctl(tmp_path, monkeypatch):
    """Pin SKILLCTL_BIN to a real-but-fake executable path so the
    _resolve_skillctl_bin helper returns deterministically without
    depending on whatever skillctl happens to be on the developer's
    PATH."""
    fake = tmp_path / "skillctl"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("SKILLCTL_BIN", str(fake))
    return str(fake)


# ---------- skill_install ----------


def test_install_success_parses_chain_summary(fake_skillctl):
    """A clean exit-0 install returns the structured chain summary plus
    install_path. The argv passed to subprocess matches the documented
    CLI shape."""
    digest = "sha256:" + "a" * 64
    stdout = (
        f"{digest}: signed by id:author@m3c, admitted by reg-key-1, attested green\n"
        "installed: /Users/test/.claude/skills/fetch-contract\n"
    )
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _completed(0, stdout=stdout)

    with patch("subprocess.run", side_effect=fake_run):
        out = _run(server.skill_install("fetch-contract"))

    # Argv shape: skillctl install fetch-contract
    assert captured["argv"][0] == fake_skillctl
    assert captured["argv"][1:] == ["install", "fetch-contract"]
    # No shell=True (defense in depth).
    assert captured["kwargs"].get("shell", False) is False
    # capture_output + text are how we get stdout/stderr as strings.
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True

    assert out["ok"] is True
    assert out["exit_code"] == 0
    assert out["digest"] == digest
    assert out["author_identity"] == "id:author@m3c"
    assert out["registry_key_id"] == "reg-key-1"
    assert out["governance_level"] == "green"
    assert out["chain_summary"].startswith(digest)
    assert out["install_path"] == "/Users/test/.claude/skills/fetch-contract"


def test_install_passes_version_and_flags(fake_skillctl):
    """version + registry + governance_min + allow_yellow + ignore_deps
    all flow through to the CLI argv as the right flags."""
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout=(
            "sha256:" + "b" * 64 + ": signed by id:x, admitted by k, attested yellow\n"
            "installed: /tmp/x\n"
        ))

    with patch("subprocess.run", side_effect=fake_run):
        out = _run(server.skill_install(
            "fetch-contract",
            version="1.0.0",
            registry="https://reg.example.com",
            governance_min="yellow",
            allow_yellow=True,
            ignore_deps=True,
        ))

    assert out["ok"] is True
    argv = captured["argv"]
    assert argv[1] == "install"
    assert argv[2] == "fetch-contract@1.0.0"
    assert "--registry" in argv
    assert argv[argv.index("--registry") + 1] == "https://reg.example.com"
    assert "--governance-min" in argv
    assert argv[argv.index("--governance-min") + 1] == "yellow"
    assert "--allow-yellow" in argv
    assert "--ignore-deps" in argv


def test_install_digest_mismatch_maps_to_class_10(fake_skillctl):
    """Tampered-bundle (mocked subprocess returning exit 10) →
    {ok: False, exit_code: 10, error_class: digest_mismatch}."""
    with patch("subprocess.run", return_value=_completed(10, stderr="install: digest mismatch\n")):
        out = _run(server.skill_install("evil-bundle"))

    assert out["ok"] is False
    assert out["exit_code"] == 10
    assert out["error_class"] == "digest_mismatch"
    assert "digest mismatch" in out["stderr"]
    assert "Re-fetch" in out["remediation"]


def test_install_exit_code_mapping(fake_skillctl):
    """All SPEC-0188 §11 numeric exit codes map to the right error_class."""
    cases = [
        (11, "author_sig_invalid"),
        (12, "registry_not_trusted"),
        (13, "governance_below_min"),
        (14, "deps_unsatisfied"),
        (15, "blob_missing"),
        (1, "generic_error"),
        (2, "usage_error"),
        (99, "generic_error"),  # unknown → generic
    ]
    for code, expected_class in cases:
        with patch("subprocess.run", return_value=_completed(code, stderr="x\n")):
            out = _run(server.skill_install("any"))
        assert out["ok"] is False
        assert out["exit_code"] == code
        assert out["error_class"] == expected_class, f"code {code} mapped to {out['error_class']!r}, want {expected_class!r}"


def test_install_validates_governance_min_without_exec(fake_skillctl):
    """Bad governance_min → tool returns validation error without
    exec'ing skillctl (defense in depth)."""
    with patch("subprocess.run") as mock_run:
        out = _run(server.skill_install("x", governance_min="purple"))
        mock_run.assert_not_called()
    assert out["ok"] is False
    assert out["error_class"] == "validation_error"


def test_install_validates_name_without_exec(fake_skillctl):
    """Empty / newline / null-byte name → validation error, no exec."""
    bad_names = ["", "name\nwith-newline", "name\x00with-null"]
    for n in bad_names:
        with patch("subprocess.run") as mock_run:
            out = _run(server.skill_install(n))
            mock_run.assert_not_called()
        assert out["ok"] is False
        assert out["error_class"] == "validation_error", f"name={n!r}"


def test_install_skillctl_not_found(monkeypatch):
    """SKILLCTL_BIN unset + skillctl not on PATH → tool returns ok=False
    with a clear remediation message and never exec'd anything."""
    monkeypatch.delenv("SKILLCTL_BIN", raising=False)
    # Patch shutil.which → None and force the SKILLCTL fallback to also
    # not exist by pointing it at a non-existent file.
    with patch("server.shutil.which", return_value=None), \
         patch("server.SKILLCTL", "/nonexistent/skillctl"), \
         patch("subprocess.run") as mock_run:
        out = _run(server.skill_install("fetch-contract"))
        mock_run.assert_not_called()
    assert out["ok"] is False
    assert out["error_class"] == "skillctl_not_found"
    assert "skillctl not found" in out["stderr"].lower() or "not found" in out["stderr"].lower()
    assert "SKILLCTL_BIN" in out["remediation"] or "skillctl" in out["remediation"].lower()


def test_install_timeout_returns_exec_error(fake_skillctl):
    """subprocess.TimeoutExpired → ok=False, error_class=exec_error."""
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=120)
    with patch("subprocess.run", side_effect=boom):
        out = _run(server.skill_install("slowpoke", timeout=1))
    assert out["ok"] is False
    assert out["error_class"] == "exec_error"
    assert "timed out" in out["stderr"].lower()


# ---------- skill_verify ----------


def test_verify_success_returns_chain_summary(fake_skillctl):
    digest = "sha256:" + "c" * 64
    stdout = f"{digest}: signed by id:author@m3c, admitted by reg-key-2, attested green\n"
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout=stdout)

    with patch("subprocess.run", side_effect=fake_run):
        out = _run(server.skill_verify("fetch-contract"))

    assert captured["argv"][1:] == ["verify", "fetch-contract"]
    assert out["ok"] is True
    assert out["digest"] == digest
    assert out["registry_key_id"] == "reg-key-2"
    assert out["governance_level"] == "green"
    assert "install_path" not in out  # verify does NOT include install_path


def test_verify_rejects_at_version(fake_skillctl):
    """name with @<version> is rejected before exec: verify checks the
    installed copy, not a registry version."""
    with patch("subprocess.run") as mock_run:
        out = _run(server.skill_verify("foo@1.0.0"))
        mock_run.assert_not_called()
    assert out["ok"] is False
    assert out["error_class"] == "validation_error"


def test_verify_propagates_exit_codes(fake_skillctl):
    """Verify uses the same exit-code → error_class mapping as install."""
    with patch("subprocess.run", return_value=_completed(12, stderr="not in trust roots\n")):
        out = _run(server.skill_verify("somebundle"))
    assert out["ok"] is False
    assert out["exit_code"] == 12
    assert out["error_class"] == "registry_not_trusted"


# ---------- skill_attest ----------


def test_attest_success(fake_skillctl):
    digest = "sha256:" + "d" * 64
    stdout = (
        "attestation_id: att_abc123\n"
        f"bundle_digest: {digest}\n"
        "level: green\n"
        "attested_at: 2026-05-05T10:00:00Z\n"
    )
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout=stdout)

    with patch("subprocess.run", side_effect=fake_run):
        out = _run(server.skill_attest(
            digest=digest,
            level="green",
            rationale="reviewed and approved",
            reviewer_id="id:reviewer@m3c",
            key="/abs/path/to/reviewer.key",
        ))

    # Argv shape matches the CLI:
    #   skillctl attest <digest> --level <level> --rationale <text>
    #     --reviewer-id <id> --key <path>
    argv = captured["argv"]
    assert argv[1] == "attest"
    assert argv[2] == digest
    assert argv[argv.index("--level") + 1] == "green"
    assert argv[argv.index("--rationale") + 1] == "reviewed and approved"
    assert argv[argv.index("--reviewer-id") + 1] == "id:reviewer@m3c"
    assert argv[argv.index("--key") + 1] == "/abs/path/to/reviewer.key"

    assert out["ok"] is True
    assert out["attestation_id"] == "att_abc123"
    assert out["bundle_digest"] == digest
    assert out["governance_level"] == "green"
    assert out["reviewer_id"] == "id:reviewer@m3c"


def test_attest_passes_registry_url(fake_skillctl):
    digest = "sha256:" + "e" * 64
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout=f"attestation_id: att_xyz\nbundle_digest: {digest}\nlevel: yellow\nattested_at: 2026-05-05T11:00:00Z\n")

    with patch("subprocess.run", side_effect=fake_run):
        out = _run(server.skill_attest(
            digest=digest,
            level="yellow",
            rationale="needs follow-up review",
            reviewer_id="id:r@m3c",
            key="/k.pem",
            registry="https://reg.example.com/api/skills",
        ))

    argv = captured["argv"]
    assert "--registry" in argv
    assert argv[argv.index("--registry") + 1] == "https://reg.example.com/api/skills"
    assert out["ok"] is True


def test_attest_rejects_bad_digest_format(fake_skillctl):
    """Bad digest format → tool returns validation error WITHOUT
    exec'ing (defense in depth)."""
    bad_digests = [
        "",
        "abc",
        "sha256:tooshort",
        "sha256:" + "x" * 64,  # non-hex
        "md5:" + "a" * 32,
        "sha256:" + "a" * 63,  # one short
        "sha256:" + "a" * 65,  # one long
    ]
    for d in bad_digests:
        with patch("subprocess.run") as mock_run:
            out = _run(server.skill_attest(
                digest=d,
                level="green",
                rationale="x",
                reviewer_id="id:r",
                key="/k",
            ))
            mock_run.assert_not_called()
        assert out["ok"] is False, f"digest={d!r} should have been rejected"
        assert out["error_class"] == "validation_error", f"digest={d!r}"


def test_attest_rejects_bad_level(fake_skillctl):
    """Level not in {green, yellow, red} → validation error, no exec."""
    digest = "sha256:" + "f" * 64
    for bad in ["", "purple", "GREEN", "ok", "blocking"]:
        with patch("subprocess.run") as mock_run:
            out = _run(server.skill_attest(
                digest=digest,
                level=bad,
                rationale="x",
                reviewer_id="id:r",
                key="/k",
            ))
            mock_run.assert_not_called()
        assert out["ok"] is False
        assert out["error_class"] == "validation_error", f"level={bad!r}"


def test_attest_rejects_newline_in_reviewer_id(fake_skillctl):
    digest = "sha256:" + "f" * 64
    with patch("subprocess.run") as mock_run:
        out = _run(server.skill_attest(
            digest=digest,
            level="green",
            rationale="ok",
            reviewer_id="id:r\ninjected",
            key="/k",
        ))
        mock_run.assert_not_called()
    assert out["ok"] is False
    assert out["error_class"] == "validation_error"


def test_attest_non_zero_exit_classified(fake_skillctl):
    """skillctl attest returning non-zero (e.g. registry rejected the
    POST) surfaces as ok=False with the generic_error class."""
    digest = "sha256:" + "f" * 64
    with patch("subprocess.run", return_value=_completed(1, stderr="POST failed: 503\n")):
        out = _run(server.skill_attest(
            digest=digest,
            level="green",
            rationale="x",
            reviewer_id="id:r",
            key="/k",
        ))
    assert out["ok"] is False
    assert out["exit_code"] == 1
    assert out["error_class"] == "generic_error"
    assert "POST failed" in out["stderr"]


# ---------- binary discovery (AUDIT-0001 Befund N.2) ----------


def test_discover_skillctl_prefers_path(monkeypatch, tmp_path):
    """$PATH wins over every standard install dir."""
    on_path = tmp_path / "from-path" / "skillctl"
    on_path.parent.mkdir()
    on_path.write_text("#!/bin/sh\nexit 0\n")
    on_path.chmod(0o755)
    monkeypatch.setattr(server.shutil, "which", lambda _n: str(on_path))
    assert server._discover_skillctl() == str(on_path)


def test_discover_skillctl_falls_back_to_install_dirs(monkeypatch, tmp_path):
    """Nothing on $PATH: the standard install dirs are probed in order, and
    only an executable regular file counts."""
    empty = tmp_path / "empty"
    empty.mkdir()
    installed = tmp_path / "usr-local-bin"
    installed.mkdir()
    binary = installed / "skillctl"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)

    monkeypatch.setattr(server.shutil, "which", lambda _n: None)
    monkeypatch.setattr(server, "_SKILLCTL_INSTALL_DIRS", (empty, installed))
    assert server._discover_skillctl() == str(binary)


def test_discover_skillctl_ignores_non_executable(monkeypatch, tmp_path):
    """A non-executable file named skillctl is not a skillctl."""
    d = tmp_path / "bin"
    d.mkdir()
    (d / "skillctl").write_text("not a binary\n")
    (d / "skillctl").chmod(0o644)

    monkeypatch.setattr(server.shutil, "which", lambda _n: None)
    monkeypatch.setattr(server, "_SKILLCTL_INSTALL_DIRS", (d,))
    assert server._discover_skillctl() == ""


def test_not_found_message_names_every_searched_place(monkeypatch, tmp_path):
    """The remediation string tells the user WHERE we looked, so a missing
    install is diagnosable without reading the source."""
    monkeypatch.delenv("SKILLCTL_BIN", raising=False)
    d = tmp_path / "some-bin-dir"
    monkeypatch.setattr(server.shutil, "which", lambda _n: None)
    monkeypatch.setattr(server, "_SKILLCTL_INSTALL_DIRS", (d,))
    monkeypatch.setattr(server, "SKILLCTL", "")

    path, err = server._resolve_skillctl_bin()
    assert path is None
    assert "SKILLCTL_BIN" in err
    assert "$PATH" in err
    assert str(d / "skillctl") in err


def test_env_var_pointing_at_a_directory_is_rejected(monkeypatch, tmp_path):
    """SKILLCTL_BIN set to something that is not an executable file fails
    loudly rather than falling through to a different binary."""
    monkeypatch.setenv("SKILLCTL_BIN", str(tmp_path))
    path, err = server._resolve_skillctl_bin()
    assert path is None
    assert "not an executable file" in err
