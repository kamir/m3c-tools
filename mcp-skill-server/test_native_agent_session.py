"""Retained-process oracles; only the Go bridge establishes signed trust."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from native_agent_binding import capture_native_agent_binding
from native_agent_session import NativeAgentSessionHost

DIGEST = "sha256:" + "a" * 64
TOKEN = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
WRONG = base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip("=")


def binding_fixture(tmp_path):
    project, home = tmp_path / "project", tmp_path / "artifacts"
    project.mkdir()
    home.mkdir()
    profile = project / "profile.json"
    profile.write_text(json.dumps({"schema": "m3c.enterprise-project-profile/v4", "project_root": str(project.resolve()),
                                   "artifact_home": str(home.resolve()), "native": {
        "carrier": {"kind": "er1", "base_url": "https://example.invalid/bound", "context_id": "agents",
                    "auth": {"mode": "none"}, "tls": {"mode": "system"}}}}))
    env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"}}
    env.update(SKILLCTL_NATIVE_AGENT_INSTALL="1", SKILLCTL_BIN=str(Path(sys.executable).resolve()),
               SKILLCTL_ENTERPRISE_PROFILE=str(profile.resolve()), SKILLCTL_PROJECT_ROOT=str(project.resolve()),
               SKILLCTL_ARTIFACT_HOME=str(home.resolve()))
    binding = capture_native_agent_binding(env)
    assert binding.enabled and not binding.error
    return binding, env


def frames(binding):
    target = str(Path(binding.home) / ".claude" / "agents" / "fixture.md")
    plan = {"type": "native-agent-plan", "rows": [{"Name": "fixture", "Version": "1.0.0", "Kind": "agent",
            "Digest": DIGEST, "Target": target, "Operation": "create", "OldDigest": ""}], "token": TOKEN,
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()}
    result = {"type": "native-agent-installed", "results": [{"SkillPath": target,
              "ProvenancePath": str(Path(binding.home) / ".claude" / "agents" / ".provenance" / "fixture.json"),
              "BackupPath": "", "CreatedFresh": True, "OverwroteOld": False, "OldDigest": ""}]}
    return json.dumps(plan).encode() + b"\n", json.dumps(result).encode() + b"\n"


# This tiny real Python child is a wire/process fixture, never a trust authority.
CHILD = r'''
import base64,os,sys,time
plan,result,mode=(base64.b64decode(sys.argv[1]),base64.b64decode(sys.argv[2]),sys.argv[3])
if mode=='stderr-cap': sys.stderr.buffer.write(b'x'*16385);sys.stderr.flush()
if mode=='stderr-edge': sys.stderr.buffer.write(b'x'*16384);sys.stderr.flush()
if mode=='stdout-cap': plan=b'x'*65537
if mode=='partial': plan=plan.rstrip(b'\n')
if mode=='invalid-utf8': plan=b'\xff\n'
if mode=='before-plan': time.sleep(60)
sys.stdout.buffer.write(plan);sys.stdout.flush()
if mode in ('partial','plan-and-exit'): sys.exit(0)
if mode=='stdout-EOF': os.close(sys.stdout.fileno())
line=sys.stdin.buffer.readline()
if not line: sys.exit(0)
if mode=='after-token': time.sleep(60)
if line != base64.urlsafe_b64encode(bytes(range(32))).rstrip(b'=')+b'\n': sys.exit(12)
sys.stdout.buffer.write(result);sys.stdout.flush()
if mode=='extra-final': sys.stdout.buffer.write(result);sys.stdout.flush()
if mode=='nonzero-final': sys.exit(1)
'''


def child_host(binding, mode="normal", plan=None, result=None):
    host = NativeAgentSessionHost(binding)
    host.GRACE_SECONDS = host.TERMINATE_SECONDS = host.KILL_SECONDS = 0.2
    host.READERS_SECONDS = host.DRAIN_SECONDS = 0.5
    children, observations = [], []
    expected_plan, expected_result = frames(binding)

    async def spawn(*args, **kwargs):
        observations.append((args, kwargs))
        assert tuple(args) == binding.argv(DIGEST)
        assert kwargs["cwd"] == binding.project and kwargs["env"] == binding.child_environment()
        child = await asyncio.create_subprocess_exec(
            sys.executable, "-u", "-c", CHILD,
            base64.b64encode(expected_plan if plan is None else plan).decode(),
            base64.b64encode(expected_result if result is None else result).decode(), mode,
            stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], env=kwargs["env"],
        )
        children.append(child)
        return child

    host._spawn = spawn
    return host, children, observations


async def checked_shutdown(host, children, *, uncertain=False):
    try:
        outcome = await asyncio.wait_for(host.shutdown(), 5)
        if uncertain:
            assert outcome["ok"] is False and outcome["exit_code"] == 1 and outcome["possible_change"] is True
        else:
            assert outcome["ok"] and outcome["closed"]
        assert all(child.returncode is not None for child in children)
    finally:
        for child in children:
            if child.returncode is None:
                child.kill()
                await asyncio.wait_for(child.wait(), 2)


def test_native_agent_startup_binding(tmp_path):
    binding, env = binding_fixture(tmp_path)
    snapshot = binding.child_environment()
    env.update(SKILLCTL_BIN="foreign", SKILLCTL_ENTERPRISE_PROFILE="foreign", HTTPS_PROXY="foreign", ER1_API_KEY="foreign")
    assert binding.child_environment() == snapshot
    assert "PATH" not in snapshot and "HTTPS_PROXY" not in snapshot and "ER1_API_KEY" not in snapshot
    binding.recheck()
    original = Path(binding.profile).read_bytes()
    assert binding.profile_sha256 == hashlib.sha256(original).hexdigest()
    Path(binding.profile).write_bytes(original + b" ")

    async def run():
        host, children, calls = child_host(binding)
        try:
            result = await host.plan(DIGEST, object())
            assert result["ok"] is False and result["exit_code"] == 12
            assert calls == [] and children == []
        finally:
            await checked_shutdown(host, children)
    asyncio.run(run())


def test_native_agent_session_protocol(tmp_path):
    binding, _ = binding_fixture(tmp_path)

    async def run():
        for mode in ("normal", "stderr-edge", "stderr-cap", "stdout-cap", "partial", "invalid-utf8", "extra-final", "nonzero-final"):
            host, children, calls = child_host(binding, mode)
            owner = object()
            try:
                plan = await asyncio.wait_for(host.plan(DIGEST, owner), 5)
                if mode in {"stderr-cap", "stdout-cap", "partial", "invalid-utf8"}:
                    assert plan["ok"] is False, mode
                    assert not plan["possible_change"], mode
                    continue
                assert plan["ok"] is True and plan["token"] == TOKEN, mode
                denied = await host.confirm(TOKEN, object())
                assert denied["ok"] is False and denied["error_class"] == "owner"
                done = await asyncio.wait_for(host.confirm(TOKEN, owner), 5)
                if mode in {"extra-final", "nonzero-final"}:
                    assert done["ok"] is False and done["possible_change"] is True, mode
                else:
                    assert done["ok"] is True and done["type"] == "native-agent-installed", mode
                assert len(calls) == 1
                assert (await host.confirm(TOKEN, owner))["ok"] is False
            finally:
                await checked_shutdown(host, children, uncertain=mode in {"extra-final", "nonzero-final"})
        for token in (WRONG, "", TOKEN + "\n"):
            host, children, calls = child_host(binding)
            owner = object()
            try:
                assert (await host.plan(DIGEST, owner))["ok"] is True
                denied = await host.confirm(token, owner)
                assert denied["ok"] is False and denied["exit_code"] == 12
                assert len(calls) == 1
                assert denied["possible_change"] is (token == WRONG)
            finally:
                await checked_shutdown(host, children, uncertain=token == WRONG)

        # A valid buffered plan cannot resurrect a process already observed dead/EOF.
        for mode in ("plan-and-exit", "stdout-EOF"):
            host, children, _ = child_host(binding, mode)
            original_frame = host._frame

            async def observed_end(session, *args, **kwargs):
                raw = await original_frame(session, *args, **kwargs)
                if mode == "plan-and-exit":
                    await asyncio.wait_for(session.process.wait(), 2)
                await asyncio.wait_for(session.readers[0], 2)
                assert session.stdout_eof
                return raw

            host._frame = observed_end
            try:
                denied = await asyncio.wait_for(host.plan(DIGEST, object()), 5)
                assert denied["ok"] is False and denied["exit_code"] == 12
                assert denied["possible_change"] is False
            finally:
                await checked_shutdown(host, children)
    asyncio.run(run())


def test_native_agent_session_cleanup(tmp_path):
    binding, _ = binding_fixture(tmp_path)

    async def run():
        for mode in ("planned-close", "planned-shutdown", "starting-cancel", "confirm-cancel"):
            child_mode = "before-plan" if mode == "starting-cancel" else "after-token" if mode == "confirm-cancel" else "normal"
            host, children, calls = child_host(binding, child_mode)
            owner = object()
            try:
                plan_task = asyncio.create_task(host.plan(DIGEST, owner))
                if mode == "starting-cancel":
                    for _ in range(100):
                        if children:
                            break
                        await asyncio.sleep(0.01)
                    assert children and children[0].returncode is None
                    plan_task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(plan_task, 5)
                else:
                    assert (await asyncio.wait_for(plan_task, 5))["ok"] is True
                    assert (await host.plan(DIGEST, owner))["ok"] is False
                    if mode == "planned-close":
                        assert (await host.close(object()))["ok"] is False
                        assert children[0].returncode is None
                        assert (await host.close(owner))["closed"] is True
                    elif mode == "confirm-cancel":
                        task = asyncio.create_task(host.confirm(TOKEN, owner))
                        for _ in range(100):
                            if host._session is not None and host._session.possible_change:
                                break
                            await asyncio.sleep(0.01)
                        assert host._session is not None and host._session.possible_change
                        task.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await asyncio.wait_for(task, 5)
                assert len(calls) == 1
            finally:
                await checked_shutdown(host, children, uncertain=mode == "confirm-cancel")

        for action in ("close", "shutdown", "terminate"):
            host, children, _ = child_host(binding, "after-token")
            owner = object()
            entered = asyncio.Event()
            original_frame = host._frame

            async def confirm_wait(session, *args, **kwargs):
                if session.phase == "CONFIRM_SENT":
                    entered.set()
                return await original_frame(session, *args, **kwargs)

            host._frame = confirm_wait
            task = None
            try:
                assert (await host.plan(DIGEST, owner))["ok"] is True
                task = asyncio.create_task(host.confirm(TOKEN, owner))
                await asyncio.wait_for(entered.wait(), 2)
                assert children[0].returncode is None
                if action == "terminate":
                    children[0].terminate()
                else:
                    outcome = await (host.close(owner) if action == "close" else host.shutdown())
                    assert outcome["ok"] is False and outcome["exit_code"] == 1
                    assert outcome["possible_change"] is True and not outcome.get("closed", False)
                outcome = await asyncio.wait_for(task, 5)
                assert outcome["ok"] is False and outcome["exit_code"] == 1 and outcome["possible_change"] is True
                repeated = await host.close(owner)
                assert repeated["ok"] is False and repeated["exit_code"] == 1 and repeated["possible_change"] is True
                foreign = await host.close(object())
                assert foreign["ok"] is False and foreign["error_class"] == "owner"
                # Windows terminate() yields a positive OS code; negative mapping
                # is separately tested without pretending Windows emitted -15.
                signal_outcome = host._protocol_failure(SimpleNamespace(
                    process=SimpleNamespace(returncode=-15), possible_change=True))
                assert signal_outcome["exit_code"] == 1 and signal_outcome["possible_change"] is True
                assert signal_outcome["error_class"] == "io"
            finally:
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                await checked_shutdown(host, children, uncertain=True)

        # Cancelled spawn remains in custody until the late process is reaped.
        host, children, calls = child_host(binding)
        host.SPAWN_SECONDS = 0.1
        original_spawn = host._spawn
        entered, release = asyncio.Event(), asyncio.Event()

        async def delayed_spawn(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original_spawn(*args, **kwargs)

        host._spawn = delayed_spawn
        owner = object()
        task = asyncio.create_task(host.plan(DIGEST, owner))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            assert (await host.plan(DIGEST, owner))["ok"] is False
            assert calls == []
            release.set()
            for _ in range(200):
                if children and children[0].returncode is not None and host._session is None:
                    break
                await asyncio.sleep(0.01)
            assert len(children) == 1 and children[0].returncode is not None
            assert host._session is None
        finally:
            release.set()
            await checked_shutdown(host, children)
    asyncio.run(run())


def test_native_agent_retained_session_stdio(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path),
               M3C_MCP_TEST_PYTHON=str(Path(sys.executable).absolute()), M3C_REQUIRE_NATIVE_MCP_TESTS="1")
    result = subprocess.run(
        ["go", "test", "-json", "./cmd/skillctl", "-run", "^TestNativeAgentRetainedMCPSubprocess$", "-count=1", "-timeout=240s"],
        cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    terminals = [event for event in events if event.get("Test") == "TestNativeAgentRetainedMCPSubprocess"
                 and event.get("Action") in {"pass", "fail", "skip"}]
    assert len(terminals) == 1 and terminals[0]["Action"] == "pass"
    assert not any(event.get("Action") in {"skip", "fail"} for event in events)
