"""Kind/owner/process oracles; only the separate shipping Go bridge proves trust."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from native_agent_binding import capture_native_install_bindings
from native_agent_session import NativeAgentSessionHost
from native_agent_protocol import NativeAgentProtocolError
from native_skill_protocol import parse_plan_frame as parse_skill_plan
from test_native_agent_session import CHILD, DIGEST, TOKEN, WRONG, binding_fixture, checked_shutdown


def skill_bindings(tmp_path, agent=True, skill=True):
    _, env = binding_fixture(tmp_path)
    env.pop("SKILLCTL_NATIVE_AGENT_INSTALL")
    if agent:
        env["SKILLCTL_NATIVE_AGENT_INSTALL"] = "1"
    if skill:
        env["SKILLCTL_NATIVE_SKILL_INSTALL"] = "1"
    return capture_native_install_bindings(env), env


def skill_frames(binding):
    target = str(Path(binding.home) / ".claude" / "skills" / "fixture")
    plan = {"type": "native-skill-plan", "rows": [{"Name": "fixture", "Version": "1.0.0", "Kind": "skill",
            "Digest": DIGEST, "Target": target, "Operation": "create", "OldDigest": "", "BackupPath": ""}],
            "token": TOKEN, "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()}
    result = {"type": "native-skill-installed", "results": [{"SkillPath": target,
              "ProvenancePath": str(Path(target) / ".m3c-provenance.json"), "BackupPath": "",
              "CreatedFresh": True, "OverwroteOld": False, "OldDigest": ""}]}
    return json.dumps(plan).encode() + b"\n", json.dumps(result).encode() + b"\n"


def skill_host(bindings, mode="normal", change_plan=None):
    agent, skill = bindings
    host = NativeAgentSessionHost(agent, skill)
    host.GRACE_SECONDS = host.TERMINATE_SECONDS = host.KILL_SECONDS = 0.2
    host.READERS_SECONDS = host.DRAIN_SECONDS = 0.5
    children, calls = [], []

    async def spawn(*args, **kwargs):
        assert tuple(args) == skill.argv(DIGEST)
        assert kwargs["cwd"] == skill.project and kwargs["env"] == skill.child_environment()
        plan, result = skill_frames(skill)
        if change_plan:
            plan = change_plan(plan)
        calls.append((args, kwargs))
        child = await asyncio.create_subprocess_exec(
            sys.executable, "-u", "-c", CHILD, base64.b64encode(plan).decode(),
            base64.b64encode(result).decode(), mode, stdin=kwargs["stdin"],
            stdout=kwargs["stdout"], stderr=kwargs["stderr"], env=kwargs["env"],
        )
        children.append(child)
        return child

    host._spawn = spawn
    return host, children, calls


def test_native_skill_startup_binding(tmp_path, monkeypatch):
    for number, (agent_on, skill_on) in enumerate(((False, False), (True, False), (False, True), (True, True))):
        root = tmp_path / str(number)
        root.mkdir()
        (agent, skill), _ = skill_bindings(root, agent_on, skill_on)
        assert agent.enabled is agent_on and skill.enabled is skill_on
        if skill_on:
            assert skill.kind == "skill" and skill.argv(DIGEST)[skill.argv(DIGEST).index("--kind") + 1] == "skill"
        if agent_on and skill_on:
            assert agent.profile_sha256 == skill.profile_sha256
            assert agent.project == skill.project and agent.home == skill.home and agent.binary == skill.binary
            assert agent.child_environment() == skill.child_environment()
    root = tmp_path / "malformed"
    root.mkdir()
    _, env = skill_bindings(root)
    for flag in ("SKILLCTL_NATIVE_SKILL_INSTALL", "SKILLCTL_NATIVE_AGENT_INSTALL"):
        bad = dict(env, **{flag: "0"})
        agent, skill = capture_native_install_bindings(bad)
        assert agent.intent and skill.intent and not agent.enabled and not skill.enabled
        assert agent.error and skill.error
    agent, skill = capture_native_install_bindings(env)
    before = skill.child_environment()
    env.update(SKILLCTL_BIN="foreign", SKILLCTL_ENTERPRISE_PROFILE="foreign", ER1_API_KEY="foreign")
    assert skill.child_environment() == before
    assert agent.profile_sha256 == skill.profile_sha256

    # A real skill-only startup selection must survive later ambient selection removal.
    import server
    from unittest.mock import patch
    from contextlib import ExitStack
    for number, choice in enumerate(("valid", "malformed", "missing-profile")):
        current = tmp_path / ("generic-" + str(number))
        current.mkdir()
        bindings, startup = skill_bindings(current, False, True)
        if choice == "malformed":
            startup["SKILLCTL_NATIVE_SKILL_INSTALL"] = "0"
            bindings = capture_native_install_bindings(startup)
        elif choice == "missing-profile":
            for name in ("SKILLCTL_ENTERPRISE_PROFILE", "SKILLCTL_PROJECT_ROOT", "SKILLCTL_ARTIFACT_HOME"):
                startup.pop(name)
            bindings = capture_native_install_bindings(startup)
        agent, skill = bindings
        monkeypatch.setattr(server, "_NATIVE_AGENT_BINDING", agent)
        monkeypatch.setattr(server, "_NATIVE_SKILL_BINDING", skill)
        monkeypatch.setattr(server, "_NATIVE_INSTALL_INTENT", agent.intent or skill.intent)
        monkeypatch.setattr(server, "_NATIVE_INSTALL_BINDING", agent if agent.enabled else skill)
        for name in ("SKILLCTL_NATIVE_AGENT_INSTALL", "SKILLCTL_NATIVE_SKILL_INSTALL", "SKILLCTL_ENTERPRISE_PROFILE", "SKILLCTL_PROJECT_ROOT", "SKILLCTL_ARTIFACT_HOME"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("SKILLCTL_BIN", str(tmp_path / "ambient-binary-must-not-be-selected"))
        monkeypatch.setenv("PATH", str(tmp_path / "ambient-provider-decoy"))
        with ExitStack() as stack:
            traps = [stack.enter_context(patch.object(server, name, side_effect=AssertionError("native intent reached " + name)))
                     for name in ("_run_skillctl_blocking", "_api_get", "_api_post")]
            process = stack.enter_context(patch.object(server.subprocess, "run", side_effect=AssertionError("native intent ran a child")))
            generic = server._capture_enterprise_install_binding()
            assert generic.configured and generic.native_blocked and not generic.binary, choice
            monkeypatch.setattr(server, "_ENTERPRISE_INSTALL_BINDING", generic)
            async def denied_tools():
                return [await server.skill_install("unselected"),
                        await server.skill_attest(DIGEST, "green", "fixture", "reviewer", "/not-a-key"),
                        await server.skill_revoke(DIGEST, "author_request"),
                        await server.skill_awareness_sync(dry_run=False, confirm=True)]
            for result in asyncio.run(denied_tools()):
                assert result["ok"] is False and result["exit_code"] == 12
            binary, error = server._resolve_skillctl_bin()
            if choice == "valid":
                assert binary == skill.binary and error is None
            else:
                assert binary is None and error
            for trap in traps:
                trap.assert_not_called()
            process.assert_not_called()


def test_native_skill_session_lifecycle(tmp_path):
    bindings, _ = skill_bindings(tmp_path)

    async def run():
        # numeric-release/v1 is a bounded supported format, not loose SemVer normalization.
        for version in ("0", "1", "1.2", "1.2.3", "1.2.3.4", "18446744073709551615", ".".join(["18446744073709551615"] * 4)):
            raw, _ = skill_frames(bindings[1])
            frame = json.loads(raw)
            frame["rows"][0]["Version"] = version
            parsed = parse_skill_plan(json.dumps(frame).encode() + b"\n", bindings[1], DIGEST)
            assert parsed.public()["rows"][0]["Version"] == version
        for version in ("", "v1", "01", "+1", "-1", "1.", ".1", "1..0", "1.2.3.4.5", "1.0.0-rc", "1.0.0+build", " 1.0", "1.0 ", "18446744073709551616", "１.0", None, 1, False):
            raw, _ = skill_frames(bindings[1])
            frame = json.loads(raw)
            frame["rows"][0]["Version"] = version
            with pytest.raises(NativeAgentProtocolError):
                parse_skill_plan(json.dumps(frame).encode() + b"\n", bindings[1], DIGEST)
        for mode in ("normal", "wrong-token", "partial", "after-token"):
            host, children, calls = skill_host(bindings, "normal" if mode == "wrong-token" else mode)
            owner = object()
            try:
                plan = await asyncio.wait_for(host.plan(DIGEST, owner, kind="skill"), 5)
                if mode == "partial":
                    assert plan["ok"] is False and plan["possible_change"] is False
                    continue
                assert plan["ok"] and plan["type"] == "native-skill-plan"
                assert (await host.plan(DIGEST, owner, kind="agent"))["ok"] is False
                for operation in (host.confirm(TOKEN, owner, kind="agent"), host.close(owner, kind="agent"),
                                  host.confirm(TOKEN, object(), kind="skill")):
                    denied = await operation
                    assert denied["ok"] is False and denied["exit_code"] == 12
                if mode == "after-token":
                    task = asyncio.create_task(host.confirm(TOKEN, owner, kind="skill"))
                    for _ in range(200):
                        if host._session is not None and host._session.possible_change:
                            break
                        await asyncio.sleep(0.01)
                    assert host._session is not None and host._session.possible_change
                    outcome = await host.close(owner, kind="skill")
                    assert outcome["ok"] is False and outcome["exit_code"] == 1 and outcome["possible_change"]
                    await asyncio.wait_for(task, 5)
                else:
                    done = await asyncio.wait_for(host.confirm(WRONG if mode == "wrong-token" else TOKEN, owner, kind="skill"), 5)
                    if mode == "normal":
                        assert done["ok"] and done["type"] == "native-skill-installed"
                    else:
                        assert not done["ok"] and done["exit_code"] == 12 and done["possible_change"]
                assert len(calls) == 1
            finally:
                await checked_shutdown(host, children, uncertain=mode in {"wrong-token", "after-token"})

        # Portable-name parser must reject before any confirmation is written.
        for character in '<>"|?*':
            def invalid_name(raw, character=character):
                value = json.loads(raw)
                row = value["rows"][0]
                row["Name"] = "fixture" + character
                row["Target"] = str(Path(bindings[1].home) / ".claude" / "skills" / row["Name"])
                return json.dumps(value).encode() + b"\n"
            raw_plan, _ = skill_frames(bindings[1])
            with pytest.raises(NativeAgentProtocolError):
                parse_skill_plan(invalid_name(raw_plan), bindings[1], DIGEST)
            host, children, _ = skill_host(bindings, "plan-and-exit", invalid_name)
            try:
                result = await asyncio.wait_for(host.plan(DIGEST, object(), kind="skill"), 5)
                assert result["ok"] is False and result["exit_code"] == 12 and not result["possible_change"], character
            finally:
                await checked_shutdown(host, children)

        # Cross-kind STARTING exclusion is synchronized after actual binding observation.
        host, children, calls = skill_host(bindings)
        spawn = host._spawn
        entered, release = asyncio.Event(), asyncio.Event()

        async def delayed(*args, **kwargs):
            host.SPAWN_SECONDS = 0.1
            entered.set()
            await release.wait()
            return await spawn(*args, **kwargs)

        host._spawn = delayed
        owner = object()
        task = asyncio.create_task(host.plan(DIGEST, owner, kind="skill"))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            assert (await host.plan(DIGEST, owner, kind="agent"))["ok"] is False
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            assert (await host.plan(DIGEST, owner, kind="agent"))["ok"] is False
            assert calls == []
            release.set()
            for _ in range(200):
                if children and children[0].returncode is not None and host._session is None:
                    break
                await asyncio.sleep(0.01)
            assert children and children[0].returncode is not None and host._session is None
        finally:
            release.set()
            await checked_shutdown(host, children)
    asyncio.run(run())


def test_native_skill_retained_session_stdio(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path),
               M3C_MCP_TEST_PYTHON=str(Path(sys.executable).absolute()), M3C_REQUIRE_NATIVE_MCP_TESTS="1")
    result = subprocess.run(
        ["go", "test", "-json", "./cmd/skillctl", "-run", "^TestNativeSkillRetainedMCPSubprocess$", "-count=1", "-timeout=240s"],
        cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    terminal = [e for e in events if e.get("Test") == "TestNativeSkillRetainedMCPSubprocess"
                and e.get("Action") in {"pass", "fail", "skip"}]
    assert len(terminal) == 1 and terminal[0]["Action"] == "pass"
    assert not any(e.get("Action") in {"fail", "skip"} for e in events)
