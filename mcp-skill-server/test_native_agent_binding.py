"""Synthetic filesystem/configuration tests; no child or credential provider runs."""

import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

import native_agent_binding as binding


def fixture(tmp_path, auth=None):
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    home.mkdir()
    document = {
        "schema": "m3c.enterprise-project-profile/v4",
        "project_root": str(project),
        "artifact_home": str(home),
        "native": {
            "carrier": {
                "kind": "er1",
                "base_url": "https://native.invalid/prefix",
                "context_id": "native-agent",
                "tls": {"mode": "system"},
                "auth": auth or {"mode": "none"},
            }
        },
    }
    profile = project / "profile.json"
    profile.write_text(json.dumps(document), encoding="utf-8")
    env = {
        "SKILLCTL_NATIVE_AGENT_INSTALL": "1",
        "SKILLCTL_ENTERPRISE_PROFILE": str(profile),
        "SKILLCTL_PROJECT_ROOT": str(project),
        "SKILLCTL_ARTIFACT_HOME": str(home),
        "SKILLCTL_BIN": sys.executable,
    }
    return env, profile, document


def test_native_agent_binding_absence_has_no_file_or_secret_access():
    class Absent(dict):
        def get(self, key, default=None):
            assert key == "SKILLCTL_NATIVE_AGENT_INSTALL"
            return default

    with patch.object(binding, "_path", side_effect=AssertionError("file lookup")):
        captured = binding.capture_native_agent_binding(Absent())
    assert not captured.intent and not captured.enabled and not captured.error


@pytest.mark.parametrize("value", ["", "0", "true", " 1", "1\n", None, 1])
def test_native_agent_binding_present_invalid_never_falls_back(value):
    with patch.object(binding, "_path", side_effect=AssertionError("must not resolve")):
        captured = binding.capture_native_agent_binding(
            {"SKILLCTL_NATIVE_AGENT_INSTALL": value}
        )
    assert (
        captured.intent
        and not captured.enabled
        and captured.error == binding.NATIVE_AGENT_BINDING_ERROR
    )


@pytest.mark.parametrize(
    "family,variable", [("api-key", "ER1_API_KEY"), ("bearer", "ER1_DEVICE_TOKEN")]
)
def test_native_agent_binding_freezes_only_selected_family(tmp_path, family, variable):
    env, profile, _ = fixture(
        tmp_path,
        {
            "mode": "external-env",
            "family": family,
            "origin": "https://native.invalid:443",
        },
    )
    env.update(
        {
            "ER1_API_KEY": "synthetic-api-value",
            "ER1_DEVICE_TOKEN": "synthetic-bearer-value",
            "HTTPS_PROXY": "https://proxy.invalid",
            "PATH": "unselected",
            "M3C_API_KEY": "unselected",
        }
    )
    captured = binding.capture_native_agent_binding(env)
    assert captured.enabled and captured.intent and not captured.error
    assert captured.profile_sha256 == hashlib.sha256(profile.read_bytes()).hexdigest()
    captured.recheck()
    child = captured.child_environment()
    assert set(child) == {"HOME", "USERPROFILE", variable}
    assert child[variable] == env[variable]
    env[variable] = "changed"
    child[variable] = "also-changed"
    assert captured.child_environment()[variable].startswith("synthetic-")
    assert "synthetic-" not in repr(captured)
    argv = captured.argv("sha256:" + "a" * 64)
    assert argv[0] == str(Path(sys.executable).resolve())
    assert argv[-3:] == ("--install", "--trust-mode", "--native-session")
    assert (
        argv[argv.index("--enterprise-profile-sha256") + 1] == captured.profile_sha256
    )
    assert argv[argv.index("--home") + 1] == captured.home


def test_native_agent_binding_authnone_never_selects_secret(tmp_path):
    env, _, _ = fixture(tmp_path)

    class Trapped(dict):
        def get(self, key, default=None):
            assert key not in {"ER1_API_KEY", "ER1_DEVICE_TOKEN", "M3C_API_KEY"}
            return super().get(key, default)

    captured = binding.capture_native_agent_binding(Trapped(env))
    assert captured.enabled
    assert set(captured.child_environment()) == {"HOME", "USERPROFILE"}


@pytest.mark.parametrize(
    "case",
    [
        "schema",
        "auth-null",
        "auth-object-mode",
        "unknown-auth",
        "both-fields",
        "foreign-origin",
        "origin-path",
        "noncanonical-origin",
        "http",
        "context-path",
        "unknown-tls",
        "duplicate",
        "nonfinite",
        "surrogate",
        "depth",
        "tokens",
        "oversize",
        "wrong-project",
        "wrong-home",
    ],
)
def test_native_agent_binding_invalid_metadata_denies_before_selected_secret(
    tmp_path, case
):
    env, profile, doc = fixture(tmp_path)
    carrier = doc["native"]["carrier"]
    if case == "schema":
        doc["schema"] = []
    elif case == "auth-null":
        carrier["auth"] = None
    elif case == "auth-object-mode":
        carrier["auth"] = {"mode": {}}
    elif case == "unknown-auth":
        carrier["auth"] = {"mode": "native-device-token"}
    elif case == "both-fields":
        carrier["auth"] = {"mode": "none", "family": "bearer"}
    elif case in {"foreign-origin", "origin-path", "noncanonical-origin"}:
        carrier["auth"] = {
            "mode": "external-env",
            "family": "api-key",
            "origin": {
                "foreign-origin": "https://foreign.invalid:443",
                "origin-path": "https://native.invalid:443/path",
                "noncanonical-origin": "https://native.invalid",
            }[case],
        }
    elif case == "http":
        carrier["base_url"] = "http://127.0.0.1"
    elif case == "context-path":
        carrier["context_id"] = "../other"
    elif case == "unknown-tls":
        carrier["tls"] = {"mode": "insecure"}
    elif case == "wrong-project":
        doc["project_root"] = env["SKILLCTL_ARTIFACT_HOME"]
    elif case == "wrong-home":
        doc["artifact_home"] = env["SKILLCTL_PROJECT_ROOT"]
    raw = json.dumps(doc).encode()
    if case == "duplicate":
        raw = raw.replace(b'"schema":', b'"schema":"wrong","schema":')
    elif case == "nonfinite":
        raw = raw[:-1] + b',"extra":NaN}'
    elif case == "surrogate":
        raw = raw[:-1] + b',"extra":"\\ud800"}'
    elif case == "depth":
        raw = b"[" * 33 + b"0" + b"]" * 33
    elif case == "tokens":
        raw = b"[" + b"0," * 3000 + b"0]"
    elif case == "oversize":
        raw = b" " * 65537
    profile.write_bytes(raw)

    class Trapped(dict):
        def get(self, key, default=None):
            assert not key.startswith("ER1_")
            return super().get(key, default)

    captured = binding.capture_native_agent_binding(Trapped(env))
    assert captured.intent and not captured.enabled
    assert captured.error == binding.NATIVE_AGENT_BINDING_ERROR
    assert "native.invalid" not in captured.error


@pytest.mark.parametrize(
    "field",
    [
        "SKILLCTL_ENTERPRISE_PROFILE",
        "SKILLCTL_PROJECT_ROOT",
        "SKILLCTL_ARTIFACT_HOME",
        "SKILLCTL_BIN",
    ],
)
def test_native_agent_binding_requires_explicit_bounded_paths(tmp_path, field):
    env, _, _ = fixture(tmp_path)
    for value in (None, "", "relative", "x" * 4097):
        changed = dict(env)
        changed[field] = value
        assert not binding.capture_native_agent_binding(changed).enabled


@pytest.mark.parametrize("change", ["bytes", "replace", "delete", "directory"])
def test_native_agent_binding_profile_drift_invalidates(tmp_path, change):
    env, profile, _ = fixture(tmp_path)
    captured = binding.capture_native_agent_binding(env)
    assert captured.enabled
    raw = profile.read_bytes()
    if change == "bytes":
        profile.write_bytes(raw + b" ")
    elif change == "replace":
        profile.unlink()
        profile.write_bytes(raw)
    elif change == "delete":
        profile.unlink()
    else:
        profile.unlink()
        profile.mkdir()
    with pytest.raises(
        binding.NativeAgentBindingError, match="startup binding is unavailable"
    ):
        captured.recheck()


def test_native_agent_binding_binary_drift_invalidates_without_execution(tmp_path):
    env, _, _ = fixture(tmp_path)
    executable = tmp_path / ("synthetic.exe" if os.name == "nt" else "synthetic")
    executable.write_bytes(b"synthetic-not-executed")
    executable.chmod(0o700)
    env["SKILLCTL_BIN"] = str(executable)
    captured = binding.capture_native_agent_binding(env)
    assert captured.enabled
    executable.write_bytes(b"changed-not-executed")
    with pytest.raises(binding.NativeAgentBindingError):
        captured.recheck()


def test_native_agent_binding_close_error_invalidates(tmp_path):
    env, _, _ = fixture(tmp_path)
    real_close = binding.os.close

    def uncertain(fd):
        real_close(fd)
        raise OSError("synthetic-close-private-text")

    with patch.object(binding.os, "close", side_effect=uncertain):
        captured = binding.capture_native_agent_binding(env)
    assert not captured.enabled and captured.error == binding.NATIVE_AGENT_BINDING_ERROR


def test_native_agent_binding_file_caps_before_open_and_actual_boundary(tmp_path):
    env, profile, _ = fixture(tmp_path)
    original = profile.read_bytes()
    profile.write_bytes(original + b" " * (65536 - len(original)))
    assert binding.capture_native_agent_binding(env).enabled
    profile.write_bytes(profile.read_bytes() + b" ")
    with patch.object(
        binding.os, "open", side_effect=AssertionError("oversize opened")
    ):
        assert not binding.capture_native_agent_binding(env).enabled
    directory = tmp_path / "notfile"
    directory.mkdir()
    env["SKILLCTL_ENTERPRISE_PROFILE"] = str(directory)
    with patch.object(
        binding.os, "open", side_effect=AssertionError("directory opened")
    ):
        assert not binding.capture_native_agent_binding(env).enabled


def test_native_agent_binding_windows_names_and_environment_caps(tmp_path):
    home = str(tmp_path)
    assert (
        dict(binding._environment({"lang": "synthetic"}, home, None, windows=True))[
            "LANG"
        ]
        == "synthetic"
    )
    with pytest.raises(binding.NativeAgentBindingError):
        binding._environment({"LANG": "a", "lang": "b"}, home, None, windows=True)
    with pytest.raises(binding.NativeAgentBindingError):
        binding._environment({"LANG": "x" * 8193}, home, None, windows=False)
    with pytest.raises(binding.NativeAgentBindingError):
        binding._environment(
            {name: "x" * 8192 for name in binding._ENV_OPTIONAL},
            home,
            None,
            windows=False,
        )
    assert (
        dict(binding._environment({"LANG": "x" * 8192}, home, None, windows=False))[
            "LANG"
        ]
        == "x" * 8192
    )


def test_native_agent_binding_special_file_is_rejected_before_open(tmp_path):
    env, _, _ = fixture(tmp_path)
    special = tmp_path / "special"
    if hasattr(os, "mkfifo"):
        os.mkfifo(special)
    else:
        special.mkdir()  # Actual Windows ordinary-file refusal, not a skipped test.
    env["SKILLCTL_ENTERPRISE_PROFILE"] = str(special)
    with patch.object(
        binding.os, "open", side_effect=AssertionError("special file opened")
    ):
        assert not binding.capture_native_agent_binding(env).enabled


def test_native_agent_binding_binary_cap_and_cap_plus_one(tmp_path):
    env, _, _ = fixture(tmp_path)
    executable = tmp_path / ("synthetic.exe" if os.name == "nt" else "synthetic")
    executable.write_bytes(b"x" * 32)
    executable.chmod(0o700)
    env["SKILLCTL_BIN"] = str(executable)
    with patch.object(binding, "_MAX_BINARY", 32):
        captured = binding.capture_native_agent_binding(env)
        assert captured.enabled
        executable.write_bytes(b"x" * 33)
        opened = []
        original = binding.os.open

        def observe(path, flags):
            opened.append(path)
            return original(path, flags)

        with patch.object(binding.os, "open", side_effect=observe):
            assert not binding.capture_native_agent_binding(env).enabled
        assert str(executable) not in opened


def test_native_agent_binding_read_failure_closes_held_file(tmp_path):
    env, _, _ = fixture(tmp_path)
    real_close = binding.os.close
    closed = []

    def observe(fd):
        closed.append(fd)
        real_close(fd)

    with patch.object(
        binding.os, "read", side_effect=OSError("synthetic-private-read-error")
    ):
        with patch.object(binding.os, "close", side_effect=observe):
            captured = binding.capture_native_agent_binding(env)
    assert not captured.enabled and captured.error == binding.NATIVE_AGENT_BINDING_ERROR
    assert len(closed) == 1


def test_native_agent_binding_pinned_metadata_and_relative_declared_roots(tmp_path):
    env, profile, doc = fixture(tmp_path)
    doc["project_root"] = "."
    doc["artifact_home"] = os.path.relpath(
        env["SKILLCTL_ARTIFACT_HOME"], env["SKILLCTL_PROJECT_ROOT"]
    )
    doc["native"]["carrier"]["tls"] = {
        "mode": "pinned-pem",
        "ca": {"path": "not-opened.pem", "sha256": "a" * 64},
    }
    profile.write_text(json.dumps(doc))
    assert binding.capture_native_agent_binding(env).enabled


def test_native_agent_binding_critical_alias_before_secret_selection(tmp_path):
    env, profile, doc = fixture(tmp_path)
    doc["Schema"] = doc["schema"]
    profile.write_text(json.dumps(doc))
    assert not binding.capture_native_agent_binding(env).enabled


def stat_copy(info, **changes):
    from types import SimpleNamespace

    values = {
        name: getattr(info, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
        )
    }
    values["st_birthtime_ns"] = getattr(info, "st_birthtime_ns", info.st_ctime_ns)
    values.update(changes)
    return SimpleNamespace(**values)


def test_native_agent_binding_windows_path_handle_execute_bit_difference(tmp_path):
    env, _, _ = fixture(tmp_path)
    real_fstat, real_lstat = binding.os.fstat, binding.os.lstat

    def windows_handle(fd):
        observed = real_fstat(fd)
        return stat_copy(
            observed,
            st_mode=observed.st_mode & ~0o111,
            st_ctime_ns=observed.st_ctime_ns + 100,
        )

    # Model the documented Windows stat/fstat difference without claiming that
    # local execution establishes native Windows behavior.
    with patch.object(binding.sys, "platform", "win32"):
        with patch.object(binding.os, "fstat", side_effect=windows_handle):
            with patch.object(
                binding.os,
                "lstat",
                side_effect=lambda path: stat_copy(real_lstat(path)),
            ):
                captured = binding.capture_native_agent_binding(env)
                assert captured.enabled
                captured.recheck()
                assert (
                    captured._binary_observation.handle_ctime_ns
                    != captured._binary_observation.ctime_ns
                )
    assert captured._binary_observation.mode == os.lstat(captured.binary).st_mode


@pytest.mark.parametrize(
    "field",
    [
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_birthtime_ns",
        "permissions",
        "type",
    ],
)
def test_native_agent_binding_windows_identity_fields_still_strict(tmp_path, field):
    import stat

    env, _, _ = fixture(tmp_path)
    captured = binding.capture_native_agent_binding(env)
    assert captured.enabled
    original = stat_copy(os.lstat(captured.binary))
    held = stat_copy(original, st_mode=original.st_mode & ~0o111)
    if field == "permissions":
        held.st_mode ^= stat.S_IWUSR
    elif field == "type":
        held.st_mode = stat.S_IFIFO | 0o600
    else:
        setattr(held, field, getattr(held, field) + 1)
    with patch.object(binding.sys, "platform", "win32"):
        assert not binding._path_handle_same(original, held)


def test_native_agent_binding_posix_execute_bit_difference_still_denied(tmp_path):
    env, _, _ = fixture(tmp_path)
    original = os.lstat(str(Path(sys.executable).resolve()))
    held = stat_copy(original, st_mode=original.st_mode ^ 0o111)
    with patch.object(binding.sys, "platform", "linux"):
        assert not binding._path_handle_same(original, held)


@pytest.mark.parametrize("changed_side", ["path", "handle"])
def test_native_agent_binding_windows_same_api_mode_changes_still_denied(
    tmp_path, changed_side
):
    env, profile, _ = fixture(tmp_path)
    real_lstat, real_fstat = binding.os.lstat, binding.os.fstat
    calls = {"path": 0, "handle": 0}

    def path_stat(path):
        observed = real_lstat(path)
        calls["path"] += 1
        if changed_side == "path" and calls["path"] == 2:
            return stat_copy(observed, st_mode=observed.st_mode ^ 0o111)
        return stat_copy(observed)

    def held_stat(fd):
        observed = real_fstat(fd)
        calls["handle"] += 1
        mode = observed.st_mode & ~0o111
        if changed_side == "handle" and calls["handle"] == 2:
            mode ^= 0o111
        return stat_copy(observed, st_mode=mode)

    with patch.object(binding.sys, "platform", "win32"):
        with patch.object(binding.os, "lstat", side_effect=path_stat):
            with patch.object(binding.os, "fstat", side_effect=held_stat):
                with pytest.raises(binding.NativeAgentBindingError):
                    binding._observe(str(profile), 65536)


@pytest.mark.parametrize("changed_side", ["path", "handle"])
def test_native_agent_binding_windows_raw_ctime_changes_still_denied(
    tmp_path, changed_side
):
    _, profile, _ = fixture(tmp_path)
    real_lstat, real_fstat = binding.os.lstat, binding.os.fstat
    calls = {"path": 0, "handle": 0}

    def path_stat(path):
        observed = stat_copy(real_lstat(path))
        calls["path"] += 1
        if changed_side == "path" and calls["path"] == 2:
            observed.st_ctime_ns += 100
        return observed

    def held_stat(fd):
        observed = real_fstat(fd)
        calls["handle"] += 1
        delta = 200 if changed_side == "handle" and calls["handle"] == 2 else 100
        return stat_copy(
            observed,
            st_mode=observed.st_mode & ~0o111,
            st_ctime_ns=observed.st_ctime_ns + delta,
        )

    with patch.object(binding.sys, "platform", "win32"):
        with patch.object(binding.os, "lstat", side_effect=path_stat):
            with patch.object(binding.os, "fstat", side_effect=held_stat):
                with pytest.raises(binding.NativeAgentBindingError):
                    binding._observe(str(profile), 65536)


def test_native_agent_binding_windows_frozen_handle_ctime_rechecked(tmp_path):
    env, _, _ = fixture(tmp_path)
    real_lstat, real_fstat = binding.os.lstat, binding.os.fstat
    delta = [100]

    def held_stat(fd):
        observed = real_fstat(fd)
        return stat_copy(
            observed,
            st_mode=observed.st_mode & ~0o111,
            st_ctime_ns=observed.st_ctime_ns + delta[0],
        )

    with patch.object(binding.sys, "platform", "win32"):
        with patch.object(
            binding.os, "lstat", side_effect=lambda path: stat_copy(real_lstat(path))
        ):
            with patch.object(binding.os, "fstat", side_effect=held_stat):
                captured = binding.capture_native_agent_binding(env)
                assert captured.enabled
                captured.recheck()
                delta[0] += 100
                with pytest.raises(binding.NativeAgentBindingError):
                    captured.recheck()
