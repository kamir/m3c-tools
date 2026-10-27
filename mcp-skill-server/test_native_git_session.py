"""Git startup/process oracles; the separate shipping Go bridge proves signatures."""
import asyncio
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

from native_agent_binding import capture_native_install_bindings
from native_agent_session import NativeAgentSessionHost
from test_native_agent_session import CHILD, DIGEST, TOKEN, WRONG, binding_fixture, frames
from test_native_skill_session import skill_frames


def git_bindings(tmp_path, provider="github", auth=False):
    _, env = binding_fixture(tmp_path)
    env["SKILLCTL_NATIVE_SKILL_INSTALL"] = "1"
    profile = Path(env["SKILLCTL_ENTERPRISE_PROFILE"])
    doc = json.loads(profile.read_text())
    family = provider + "-read-token"
    carrier = {"kind": "git", "provider": provider, "api_base": "https://example.invalid/api", "repository": "owner/repository",
               "object_format": "sha1", "commit_oid": "a" * 40, "root_tree_oid": "b" * 40,
               "auth": {"mode": "none"}, "tls": {"mode": "system"}}
    if auth:
        carrier["auth"] = {"mode": "external-env", "family": family, "origin": "https://example.invalid:443"}
        # Runtime synthetic value; no native credential provider is consulted.
        env["M3C_" + provider.upper() + "_RO_TOKEN"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    doc["schema"] = "m3c.enterprise-project-profile/v5"
    doc["native"]["carrier"] = carrier
    profile.write_text(json.dumps(doc))
    return capture_native_install_bindings(env), env, profile


def test_native_git_startup_binding(tmp_path):
    for provider in ("github", "gitlab"):
        for auth in (False, True):
            root = tmp_path / (provider + str(auth))
            root.mkdir()
            (agent, skill), env, profile = git_bindings(root, provider, auth)
            assert agent.enabled and skill.enabled and not agent.error and not skill.error
            assert agent.profile_sha256 == skill.profile_sha256
            assert agent.child_environment() == skill.child_environment()
            selected = "M3C_" + provider.upper() + "_RO_TOKEN"
            foreign = "M3C_" + ("GITLAB" if provider == "github" else "GITHUB") + "_RO_TOKEN"
            child = agent.child_environment()
            assert foreign not in child
            if auth:
                assert child[selected] == env[selected]
            else:
                assert selected not in child
            env.update(SKILLCTL_BIN="foreign", SKILLCTL_ENTERPRISE_PROFILE="foreign", M3C_GITHUB_RO_TOKEN="foreign", M3C_GITLAB_RO_TOKEN="foreign")
            assert agent.child_environment() == child
            before = json.loads(profile.read_text())
            for field, bad in (("commit_oid", "main"), ("root_tree_oid", "short"), ("object_format", "sha256"), ("repository", "../foreign")):
                changed = json.loads(json.dumps(before))
                changed["native"]["carrier"][field] = bad
                profile.write_text(json.dumps(changed))
                # Restore the actual startup paths; malformed content must never enable either kind.
                startup = dict(env, SKILLCTL_BIN=agent.binary, SKILLCTL_ENTERPRISE_PROFILE=str(profile))
                denied = capture_native_install_bindings(startup)
                assert all(x.intent and not x.enabled and x.error for x in denied), field
            profile.write_text(json.dumps(before))


def test_native_git_session_lifecycle(tmp_path):
    (agent, skill), _, _ = git_bindings(tmp_path)
    assert agent.enabled and skill.enabled

    async def run():
        for kind in ("agent", "skill"):
            host = NativeAgentSessionHost(agent, skill)
            host.GRACE_SECONDS = host.TERMINATE_SECONDS = host.KILL_SECONDS = 0.2
            host.READERS_SECONDS = host.DRAIN_SECONDS = 0.5
            children, writes = [], []
            selected = skill if kind == "skill" else agent
            gate = asyncio.Event()

            async def spawn(*args, **kwargs):
                assert tuple(args) == selected.argv(DIGEST)
                assert kwargs["env"] == selected.child_environment() and kwargs["cwd"] == selected.project
                await gate.wait()
                plan, result = skill_frames(selected) if kind == "skill" else frames(selected)
                child = await asyncio.create_subprocess_exec(sys.executable, "-u", "-c", CHILD,
                    base64.b64encode(plan).decode(), base64.b64encode(result).decode(), "normal",
                    stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], env=kwargs["env"])
                children.append(child)
                original = child.stdin.write

                def observe(raw):
                    writes.append(raw)
                    return original(raw)

                child.stdin.write = observe
                return child

            host._spawn = spawn
            owner, foreign = object(), object()
            other = "agent" if kind == "skill" else "skill"
            try:
                pending = asyncio.create_task(host.plan(DIGEST, owner, kind=kind))
                # STARTING ownership is observed, not assumed from an arbitrary delay.
                for _ in range(1000):
                    if host._session is not None:
                        break
                    await asyncio.sleep(0)
                assert host._session is not None
                denied = await host.plan(DIGEST, foreign, kind=other)
                assert denied["ok"] is False and denied["exit_code"] == 12
                gate.set()
                plan = await asyncio.wait_for(pending, 5)
                assert plan["ok"] is True and plan["token"] == TOKEN and len(children) == 1
                for owner_arg, kind_arg in ((foreign, kind), (owner, other)):
                    refused = await host.confirm(TOKEN, owner_arg, kind=kind_arg)
                    assert refused["ok"] is False and refused["exit_code"] == 12
                assert writes == []
                result = await asyncio.wait_for(host.confirm(WRONG, owner, kind=kind), 5)
                assert writes == [(WRONG + "\n").encode()], "host replaced caller token with retained token"
                assert result["ok"] is False and result["exit_code"] == 12
            finally:
                gate.set()
                await asyncio.wait_for(host.shutdown(), 5)
                for child in children:
                    assert child.returncode is not None
    asyncio.run(run())


def test_native_git_retained_session_stdio(tmp_path):
    """Required producer wrapper proves the named shipping Go/TLS/stdio parent."""
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path),
               M3C_MCP_TEST_PYTHON=str(Path(sys.executable).absolute()), M3C_REQUIRE_NATIVE_MCP_TESTS="1")
    command = ["go", "test", "-json", "-count=1", "-timeout=240s", "-run=^TestNativeGitRetainedMCPSubprocess$", "./cmd/skillctl"]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    terminal = [event for event in events if event.get("Test") == "TestNativeGitRetainedMCPSubprocess"
                and event.get("Action") in {"pass", "fail", "skip"}]
    assert len(terminal) == 1 and terminal[0]["Action"] == "pass"
    assert not any(event.get("Action") in {"fail", "skip"} for event in events)
