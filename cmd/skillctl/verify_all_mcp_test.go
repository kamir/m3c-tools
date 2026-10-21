package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestSweepContractMCPSubprocess exercises the built CLI, public tool and MCP stdio.
func TestSweepContractMCPSubprocess(t *testing.T) {
	python := os.Getenv("M3C_MCP_TEST_PYTHON")
	if python == "" {
		t.Skip("run through the MCP pytest suite for its interpreter")
	}
	// Build before changing HOME: Go's read-only module cache must not be
	// created inside the fixture home that testing.TempDir later removes.
	binary := skillctlBin(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	f := newFixture(t)
	srv := httptest.NewServer(f.happyMux(t, map[string]any{"depends_on": []any{}}, "green", nil))
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeSelfTrustRootsKey(t, home, pub)
	other := headTestDigest('f')
	installSignedHead(t, home, priv, 1, time.Now().UTC(), []string{other})
	writeRevokedCache(home, map[string]struct{}{other: {}})
	if !graceAuthenticated(home, map[string]struct{}{other: {}}) {
		t.Fatal("synthetic revocation grace is not authenticated")
	}
	moduleDir, err := filepath.Abs(filepath.Join("..", "..", "mcp-skill-server"))
	if err != nil {
		t.Fatal(err)
	}
	probe := `import asyncio, hashlib, json, os, pathlib, shutil, subprocess, sys
sys.path.insert(0, sys.argv[1])
import server
registry, digest = sys.argv[2:4]
home = pathlib.Path.home()
cli = os.environ['SKILLCTL_BIN']
def direct():
    ran = subprocess.run([cli, 'verify', '--json', '--all', '--budget', '60s', '--registry', registry], capture_output=True, text=True, timeout=90)
    data = json.loads(ran.stdout)
    assert data['exit_code'] == ran.returncode, (ran.returncode, data, ran.stderr)
    return data
async def probe():
    empty = await server.skill_verify_all(registry=registry)
    assert empty == direct(), empty
    assert empty['ok'] and empty['total'] == 0 and empty['entries'] == [], empty
    installed = await server.skill_install('fetch-contract', version='1.0.0', registry=registry)
    assert installed['ok'], installed
    clean = await server.skill_verify_all(registry=registry)
    assert clean == direct() and clean['ok'] and clean['verified'] == 1, clean
    entry = clean['entries'][0]
    assert entry['digest'] == digest and entry['digest_verified'], entry
    assert entry['revocation_source'] == 'cached', entry
    assert entry['governance_verified'] is False and entry['self_attested'] is None, entry
    installed_path = pathlib.Path(installed['install_path'])
    tampered = installed_path.parent / 'tampered-contract'
    shutil.copytree(installed_path, tampered)
    (tampered / 'SKILL.md').write_text('tampered synthetic body')
    (installed_path / '.m3c-provenance.json').write_text(json.dumps({'bundle_digest': 'sha256:' + 'b'*64}))
    manual = installed_path.parent / 'manual-contract'
    manual.mkdir()
    (manual / 'SKILL.md').write_text('unmanaged synthetic skill')
    mixed = await server.skill_verify_all(registry=registry)
    assert mixed == direct(), (mixed, direct())
    assert not mixed['ok'] and not mixed['complete'] and mixed['exit_code'] == 1 and mixed['total'] == 3, mixed
    entries = {row['skill']: row for row in mixed['entries']}
    assert entries['fetch-contract']['status'] == 'valid' and entries['fetch-contract']['digest'] == digest, mixed
    bad = entries['tampered-contract']
    assert bad['status'] == 'invalid' and bad['exit'] == 10 and bad['disposition'] == 'would_quarantine', bad
    assert not bad['digest_verified'] and bad['digest'] == digest, bad
    assert entries['manual-contract']['status'] == 'skipped' and mixed['quarantined'] == 0, mixed
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(sys.argv[1], 'server.py')], env=dict(os.environ))
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert 'skill_verify_all' in [tool.name for tool in tools.tools], tools
            called = await session.call_tool('skill_verify_all', {'registry': registry})
            assert not called.isError and len(called.content) == 1, called
            assert json.loads(called.content[0].text) == mixed, called
    moved = await server.skill_verify_all(registry=registry, quarantine=True)
    assert not moved['ok'] and moved['quarantined'] == 1 and moved['invalid'] == 1, moved
    bad = next(row for row in moved['entries'] if row['skill'] == 'tampered-contract')
    assert bad['disposition'] == 'quarantined' and pathlib.Path(bad['quarantine_path']).is_dir(), bad
    assert not tampered.exists() and manual.is_dir(), moved
    (home / '.claude' / 'trust-roots.yaml').unlink()
    limited = await server.skill_verify_all(registry=registry)
    assert limited == direct() and not limited['ok'], limited
    remaining = next(row for row in limited['entries'] if row['skill'] == 'fetch-contract')
    assert remaining['status'] == 'incomplete' and remaining['revocation_source'] == 'unconfirmed', remaining
    assert remaining['digest'] == digest and remaining['digest_verified'], remaining
asyncio.run(probe())`
	cmd := exec.Command(python, "-c", probe, moduleDir, srv.URL+"/api/skills", f.digestStr)
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off",
		"M3C_REGISTRY_TOKEN=", "M3C_REGISTRY_RO_TOKEN=", "M3C_REGISTRY_TOKEN_ORIGIN=", "ER1_API_URL="+srv.URL, "ER1_API_KEY=synthetic-local-only",
		"SKILLCTL_BIN="+binary)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real sweep CLI/MCP contract failed: %v\n%s", err, output)
	}
}
