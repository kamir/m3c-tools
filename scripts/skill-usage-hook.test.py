#!/usr/bin/env python3
"""Offline standalone hook contracts. All credentials and homes are synthetic."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts/skill-usage-hook.py"
POLICY = ROOT / "mcp-skill-server/api_connection.py"
KEY = "synthetic-hook-key"
EVENT = {"tool_input": {"skill": "synthetic-skill"}, "session_id": "synthetic-session", "cwd": "/synthetic/project"}
PROBE = r'''
import builtins, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("copied_hook", sys.argv[1])
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)
counts = {"key_reads": 0, "session_reads": 0, "opener_calls": 0}
get = os.environ.get
read = builtins.open
def getenv(name, *args):
    if name == "M3C_API_KEY": counts["key_reads"] += 1
    return get(name, *args)
def open_file(file, *args, **kwargs):
    if str(file).endswith("er1_session.json"): counts["session_reads"] += 1
    return read(file, *args, **kwargs)
def forbidden_opener(*args, **kwargs):
    counts["opener_calls"] += 1
    raise AssertionError("unexpected opener")
os.environ.get = getenv
builtins.open = open_file
hook.urllib.request.build_opener = forbidden_opener
hook.main()
print(json.dumps(counts))
'''


@contextlib.contextmanager
def server(handler):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


class HookContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sequence = 0

    def run_hook(self, values=None, session=None, helper=True, probe=True):
        self.sequence += 1
        case = self.root / str(self.sequence)
        install, home, cwd = (case / part for part in ("installed-hook", "home", "unrelated-cwd"))
        for path in (install, home, cwd):
            path.mkdir(parents=True)
        shutil.copyfile(HOOK, install / HOOK.name)
        if helper:
            shutil.copyfile(POLICY, install / POLICY.name)
        # Neither import search path is a legitimate helper source.
        (cwd / "api_connection.py").write_text('raise AssertionError("CWD/PYTHONPATH helper used")\n')
        if session is not None:
            directory = home / ".m3c-tools"
            directory.mkdir()
            (directory / "er1_session.json").write_text(session)
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "USERPROFILE": str(home),
               "USER": "synthetic-user", "PYTHONPATH": str(cwd), "PYTHONDONTWRITEBYTECODE": "1",
               "M3C_TOKEN_STORE": "file", "M3C_TEST_KEYCHAIN": "0", "M3C_ER1_KEYCHAIN": "off"}
        env.update(values or {})
        command = [sys.executable, "-c", PROBE, str(install / HOOK.name)] if probe else [sys.executable, str(install / HOOK.name)]
        process = subprocess.run(command, input=json.dumps(EVENT), text=True, capture_output=True,
                                 cwd=cwd, env=env, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        for secret in (KEY, "synthetic-legacy-key", "synthetic-env-key"):
            self.assertNotIn(secret, process.stdout + process.stderr)
        database = home / ".m3c-tools/skill-usage.db"
        with sqlite3.connect(database) as conn:
            rows = conn.execute("SELECT skill_id, synced FROM skill_usage").fetchall()
        counts = json.loads(process.stdout) if probe else None
        return rows, counts

    def assert_blocked(self, values, session=None, helper=True, expect_key_reads=0, expect_session_reads=0):
        rows, counts = self.run_hook(values, session, helper)
        self.assertEqual(rows, [("synthetic-skill", 0)])
        self.assertEqual(counts, {"key_reads": expect_key_reads, "session_reads": expect_session_reads, "opener_calls": 0})

    def test_missing_helper_does_not_search_cwd_or_read_key(self):
        self.assert_blocked({"M3C_API_KEY": KEY, "M3C_API_KEY_ORIGIN": "https://a.example"}, helper=False)

    def test_invalid_target_and_pin_precede_secret_read(self):
        for target, pin, allow in [
            ("https://a.example", "", ""), ("https://b.example", "https://a.example", ""),
            ("https://a.example:444", "https://a.example", ""),
            ("https://a.example.evil.example", "https://a.example", ""),
            ("http://a.example", "http://a.example", "1"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080", ""),
            ("https://user:synthetic@a.example", "https://a.example", ""),
            ("https://a.example?query", "https://a.example", ""),
            ("https://a.example", "https://a.example/path", ""),
            ("https://a.example", "http://a.example", ""),
        ]:
            with self.subTest(target=target, pin=pin):
                self.assert_blocked({"M3C_API_URL": target, "M3C_API_KEY_ORIGIN": pin,
                                     "M3C_ALLOW_LOOPBACK_HTTP": allow, "M3C_API_KEY": KEY},
                                    session='{"api_key":"synthetic-legacy-key"}')

    def test_invalid_selected_environment_key_does_not_fall_back(self):
        self.assert_blocked({"M3C_API_URL": "https://a.example", "M3C_API_KEY_ORIGIN": "https://a.example",
                             "M3C_API_KEY": "invalid\r\nheader"}, session='{"api_key":"synthetic-legacy-key"}',
                            expect_key_reads=1)

    def test_ambiguous_and_context_only_legacy_fail_closed(self):
        for raw in ['{"context_id":"context"}', '{"api_key":"first","api_key":"last"}',
                    '{"api_key":"first","api\\u005fkey":"last"}',
                    '{"api_key":"first","API_KEY":"last"}', '{"api_Key":"alias"}',
                    '{"api_key":"synthetic-legacy-key","nested":{"x":1,"x":2}}',
                    '{"api_key":null}', '{"api_key":123}', '{"api_key":"  "}',
                    '{"api_key":"synthetic-legacy-key"} {}']:
            with self.subTest(raw=raw):
                self.assert_blocked({"M3C_API_URL": "https://a.example", "M3C_API_KEY_ORIGIN": "https://a.example"},
                                    session=raw, expect_key_reads=1, expect_session_reads=1)

    def test_copied_pair_uses_canonical_policy_with_equivalent_default_origin(self):
        # A validated source reaches our forbidden opener exactly once, never another helper.
        rows, counts = self.run_hook({"M3C_API_URL": "https://A.example:00443/prefix/", "M3C_API_KEY_ORIGIN": "https://a.example", "M3C_API_KEY": KEY},
                                    session='{"api_key":"synthetic-legacy-key"}')
        self.assertEqual(rows, [("synthetic-skill", 0)])
        self.assertEqual(counts, {"key_reads": 1, "session_reads": 0, "opener_calls": 1})

    def test_missing_pin_precedes_legacy_and_environment_with_default_target(self):
        self.assert_blocked({"M3C_API_KEY": KEY}, session='{"api_key":"synthetic-legacy-key"}')

    def test_real_delivery_environment_and_legacy_priority(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, self.headers.get("X-API-KEY"), self.headers.get("X-User-ID"), json.loads(body)["skill_id"]))
                self.send_response(202)
                self.end_headers()

            def log_message(self, *args):
                pass

        with server(Handler) as origin:
            for env_key, expected in [("synthetic-env-key", "synthetic-env-key"), ("", "synthetic-legacy-key")]:
                with self.subTest(source="env" if env_key else "legacy"):
                    rows, _ = self.run_hook({"M3C_API_URL": origin + "/prefix/", "M3C_API_KEY_ORIGIN": origin,
                                             "M3C_ALLOW_LOOPBACK_HTTP": "1", "M3C_API_KEY": env_key},
                                            session='{"api_key":"synthetic-legacy-key"}', probe=False)
                    self.assertEqual(rows, [("synthetic-skill", 1)])
                    self.assertEqual(received[-1], ("/prefix/api/v2/skills/usage", expected, "synthetic-user", "synthetic-skill"))
            self.assertEqual(len(received), 2)

    def test_loopback_delivery_bypasses_ambient_http_proxy(self):
        origin_requests, proxy_requests = [], []

        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                proxy_requests.append((dict(self.headers), self.rfile.read(int(self.headers.get("Content-Length", "0")))))
                self.send_response(202)
                self.end_headers()

            def log_message(self, *args):
                pass

        class Origin(Proxy):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                origin_requests.append((self.path, self.headers.get("X-API-KEY"), json.loads(body)["skill_id"]))
                self.send_response(202)
                self.end_headers()

        with server(Proxy) as proxy, server(Origin) as origin:
            for variable in ("http_proxy", "HTTP_PROXY"):
                with self.subTest(variable=variable):
                    environment = {"M3C_API_URL": origin, "M3C_API_KEY_ORIGIN": origin, "M3C_API_KEY": KEY,
                                   "M3C_ALLOW_LOOPBACK_HTTP": "1", variable: proxy, "no_proxy": "", "NO_PROXY": ""}
                    before = len(origin_requests)
                    rows, _ = self.run_hook(environment, probe=False)
                    self.assertEqual(rows, [("synthetic-skill", 1)])
                    self.assertEqual(len(origin_requests), before + 1)
                    self.assertEqual(origin_requests[-1], ("/api/v2/skills/usage", KEY, "synthetic-skill"))
                    self.assertEqual(proxy_requests, [])
                    # A bad pin still refuses before reaching either listener.
                    environment["M3C_API_KEY_ORIGIN"] = proxy
                    rows, _ = self.run_hook(environment, probe=False)
                    self.assertEqual(rows, [("synthetic-skill", 0)])
                    self.assertEqual(len(origin_requests), before + 1)
                    self.assertEqual(proxy_requests, [])

    def test_http_refusal_records_unsynced_without_response_reflection(self):
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append(self.path)
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"remote body synthetic-hook-key")

            def log_message(self, *args):
                pass

        with server(Handler) as origin:
            rows, _ = self.run_hook({"M3C_API_URL": origin, "M3C_API_KEY_ORIGIN": origin,
                                     "M3C_API_KEY": KEY, "M3C_ALLOW_LOOPBACK_HTTP": "1"}, probe=False)
            self.assertEqual(rows, [("synthetic-skill", 0)])
            self.assertEqual(calls, ["/api/v2/skills/usage"])

    def test_all_redirects_refuse_foreign_and_same_origin_without_replay(self):
        a_requests, b_requests = [], []
        target = [""]
        status = [302]

        class B(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                b_requests.append((self.command, dict(self.headers), self.rfile.read(int(self.headers.get("Content-Length", "0")))))
                self.send_response(200)
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *args):
                pass

        class A(B):
            def do_POST(self):
                a_requests.append((self.path, self.headers.get("X-API-KEY"), self.rfile.read(int(self.headers.get("Content-Length", "0")))))
                self.send_response(status[0])
                self.send_header("Location", target[0])
                self.end_headers()

            do_GET = do_POST

        with server(B) as foreign, server(A) as origin:
            for code in (302, 303, 307, 308):
                for redirect in (foreign + "/sink", origin + "/sink"):
                    with self.subTest(code=code, same_origin=redirect.startswith(origin)):
                        status[0], target[0] = code, redirect
                        before = len(a_requests)
                        rows, _ = self.run_hook({"M3C_API_URL": origin, "M3C_API_KEY_ORIGIN": origin,
                                                 "M3C_API_KEY": KEY, "M3C_ALLOW_LOOPBACK_HTTP": "1"}, probe=False)
                        self.assertEqual(rows, [("synthetic-skill", 0)])
                        self.assertEqual(len(a_requests), before + 1)
                        self.assertEqual(a_requests[-1][0], "/api/v2/skills/usage")
                        self.assertEqual(a_requests[-1][1], KEY)
                        self.assertIn(b"synthetic-skill", a_requests[-1][2])
                        self.assertEqual(b_requests, [])



if __name__ == "__main__":
    unittest.main()
