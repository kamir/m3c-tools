"""Actual local API traffic must not escape through an ambient HTTP proxy."""
import contextlib
import http.server
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest

SOURCE = Path(__file__).resolve().parent
CHILD = '''
import asyncio, json, sys
sys.path.insert(0, sys.argv[1])
import server
operation = sys.argv[2]
if operation == "get": result = asyncio.run(server._api_get("/api/test"))
elif operation == "post": result = asyncio.run(server._api_post("/api/test", {"private":"fixture"}))
else: result = asyncio.run(server.skill_data_source_query("ds:fixture"))
print(json.dumps({"ok": isinstance(result,dict) and result.get("ok",True)}))
'''


@contextlib.contextmanager
def serve(handler):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


@pytest.mark.parametrize("variable", ["http_proxy", "HTTP_PROXY"])
@pytest.mark.parametrize("operation", ["get", "post", "data_source"])
def test_loopback_api_ignores_ambient_proxy(variable, operation, tmp_path):
    origin_requests, proxy_requests = [], []

    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            proxy_requests.append((self.command, dict(self.headers), body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"id":"ds:fixture"}')

        do_POST = do_GET

        def log_message(self, *args):
            pass

    class Origin(Proxy):
        def do_GET(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            origin_requests.append((self.command, self.path, self.headers.get("X-API-KEY"), self.headers.get("X-User-ID"), body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"id":"ds:fixture"}')

        do_POST = do_GET

    with serve(Proxy) as proxy, serve(Origin) as origin:
        env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "USER": "synthetic-user",
               "M3C_USER_ID": "synthetic-user", "PYTHONDONTWRITEBYTECODE": "1",
               "M3C_TOKEN_STORE": "file", "M3C_TEST_KEYCHAIN": "0", "M3C_ER1_KEYCHAIN": "off",
               "M3C_API_URL": origin + "/prefix", "M3C_API_KEY_ORIGIN": origin,
               "M3C_API_KEY": "synthetic-proxy-key", "M3C_ALLOW_LOOPBACK_HTTP": "1",
               variable: proxy, "no_proxy": "", "NO_PROXY": ""}

        def child(expected):
            run = subprocess.run([sys.executable, "-c", CHILD, str(SOURCE), operation],
                                 env=env, cwd=tmp_path, text=True, capture_output=True, timeout=15)
            assert run.returncode == 0, run.stderr
            assert "synthetic-proxy-key" not in run.stdout + run.stderr
            assert json.loads(run.stdout) == {"ok": expected}

        child(True)
        assert len(origin_requests) == 1 and proxy_requests == []
        method, path, key, user, body = origin_requests[0]
        assert key == "synthetic-proxy-key" and user == "synthetic-user"
        assert method == ("POST" if operation == "post" else "GET")
        assert path == ("/prefix/api/skills/data-sources/ds:fixture" if operation == "data_source" else "/prefix/api/test")
        assert json.loads(body) == {"private": "fixture"} if operation == "post" else body == b""
        env["M3C_API_KEY_ORIGIN"] = proxy
        child(False)
        assert len(origin_requests) == 1 and proxy_requests == []
