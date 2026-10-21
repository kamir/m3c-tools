package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func TestTrustResultEarlyFailures(t *testing.T) {
	for _, op := range []string{"install", "verify"} {
		t.Run(op, func(t *testing.T) {
			for _, args := range [][]string{{"--json"}, {"--json", "--unknown"}, {"--json", "--bundle", filepath.Join(t.TempDir(), "missing.skb")}} {
				var stdout, stderr bytes.Buffer
				runner := runInstall
				if op == "verify" {
					runner = runVerify
				}
				code := runner(args, &stdout, &stderr)
				var result bundleVerifyResult
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
					t.Fatalf("invalid JSON: %v: %s", err, &stdout)
				}
				if code == 0 || result.OK || result.ExitCode != code || result.Schema != trustResultSchema || result.Operation != op || result.Error == "" {
					t.Fatalf("invalid failure: %+v code %d", result, code)
				}
			}
		})
	}
}

type rejectedTrustWriter struct{}

func (rejectedTrustWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestTrustResultOutputFailure(t *testing.T) {
	enabled := true
	code := exitUsage
	var stderr bytes.Buffer
	// The renderer must not silently succeed when its machine result cannot be delivered.
	var textDiagnostic strings.Builder
	renderTrustResult(&enabled, &bundleVerifyResult{}, "verify", &code, &textDiagnostic, rejectedTrustWriter{}, &stderr)
	if code != exitGeneric || stderr.Len() == 0 {
		t.Fatalf("code %d, stderr %s", code, &stderr)
	}
}

// TestTrustContractMCPSubprocess bridges the real public MCP tools to a shipping CLI.
// Pytest supplies its interpreter so this test uses the same installed MCP dependencies.
func TestTrustContractMCPSubprocess(t *testing.T) {
	python := os.Getenv("M3C_MCP_TEST_PYTHON")
	if python == "" {
		t.Skip("run through the MCP pytest suite for the Python interpreter")
	}
	home := t.TempDir()
	f := newFixture(t)
	srv := httptest.NewServer(f.happyMux(t, map[string]any{"depends_on": []any{}}, "green", nil))
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")
	moduleDir, err := filepath.Abs(filepath.Join("..", "..", "mcp-skill-server"))
	if err != nil {
		t.Fatal(err)
	}
	probe := `import asyncio, json, os, sys
sys.path.insert(0, sys.argv[1])
import server
async def probe():
    installed = await server.skill_install("fetch-contract", version="1.0.0", registry=sys.argv[2], governance_min="green")
    assert installed["ok"], installed
    assert installed["install_path"] and installed["digest"] == sys.argv[3], installed
    assert installed["governance_verified"] is False, installed
    assert installed["self_attested"] is None, installed
    verified = await server.skill_verify("fetch-contract", registry=sys.argv[2], governance_min="green")
    assert verified["ok"] and verified["digest"] == installed["digest"], verified
    assert verified["governance_verified"] is False, verified
    refused = await server.skill_verify("missing-contract", registry=sys.argv[2])
    assert refused["ok"] is False and refused["exit_code"] != 0, refused
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(sys.argv[1], "server.py")], env=dict(os.environ))
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            assert initialized.protocolVersion, initialized
            tools = await session.list_tools()
            assert "skill_verify" in [tool.name for tool in tools.tools], tools
            called = await session.call_tool("skill_verify", {"name": "fetch-contract", "registry": sys.argv[2], "governance_min": "green"})
            assert not called.isError, called
            assert len(called.content) == 1 and called.content[0].type == "text", called
            payload = json.loads(called.content[0].text)
            assert isinstance(payload, dict) and payload["ok"] is True, called
            assert payload["digest"] == installed["digest"], payload
            assert payload["governance_verified"] is False and payload["self_attested"] is None, payload
asyncio.run(probe())`
	cmd := exec.Command(python, "-c", probe, moduleDir, srv.URL+"/api/skills", f.digestStr)
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off", "SKILLCTL_BIN="+skillctlBin(t))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("public MCP tools failed: %v\n%s", err, output)
	}
}

func TestTrustResultBundleSuccessAndFailure(t *testing.T) {
	f := buildBundleFixture(t)
	for _, tc := range []struct {
		name   string
		mutate bool
		want   int
	}{{"advisory", false, 0}, {"tampered", true, 10}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mutate {
				if err := os.WriteFile(f.skbPath, []byte("altered synthetic bundle"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			code := runVerify([]string{"--json", "--bundle", f.skbPath, "--trust-roots", f.trPath}, &stdout, &stderr)
			var out bundleVerifyResult
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if code != tc.want || out.ExitCode != code || out.OK != (code == 0) {
				t.Fatalf("code %d: %+v stderr %s", code, out, &stderr)
			}
			if code == 0 && (out.GovernanceVerified || out.SelfAttested != nil || out.Digest != f.digest || out.Author == "" || out.RegistryKeyID == "") {
				t.Fatalf("advisory result: %+v", out)
			}
		})
	}
}

func TestTrustResultInstallBundleAndOffline(t *testing.T) {
	f := buildInstallableFixture(t)
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home)
	data, err := os.ReadFile(f.trPath)
	if err != nil {
		t.Fatal(err)
	}
	writeTrustRoots(t, f.home, string(data))
	for _, tc := range []struct {
		operation string
		args      []string
		runner    func([]string, io.Writer, io.Writer) int
	}{
		{"install", []string{"--json", "--bundle", f.skbPath, "--trust-roots", f.trPath, "--home", f.home}, runInstall},
		{"verify", []string{"--json", "--offline", "--home", f.home, "revo-demo"}, runVerify},
	} {
		var stdout, stderr bytes.Buffer
		code := tc.runner(tc.args, &stdout, &stderr)
		var out bundleVerifyResult
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("%s invalid JSON: %v: %s", tc.operation, err, &stdout)
		}
		if code != 0 || !out.OK || out.Digest != f.digest || out.Operation != tc.operation {
			t.Fatalf("%s code %d: %+v stderr %s", tc.operation, code, out, &stderr)
		}
		if tc.operation == "install" && out.InstallPath != filepath.Join(f.home, ".claude", "skills", "revo-demo") {
			t.Fatalf("incorrect install_path: %s", out.InstallPath)
		}
	}
}

func TestTrustResultInstallFreshness(t *testing.T) {
	for _, tc := range []struct {
		name    string
		age     time.Duration
		want    int
		allowed bool
	}{
		{"fresh-allow", time.Hour, 0, true},
		{"stale-deny", 48 * time.Hour, verify.ExitRevocationStale, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := buildInstallableFixture(t)
			writePinnedTrustRootsFresh(t, f.trPath, f.regURL, f.regPubB64, f.authorID, f.authorPubB64, "24h", "closed")
			list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(tc.age), 1, nil, f.regPriv)
			if err != nil {
				t.Fatal(err)
			}
			revPath := writeRevocations(t, f.dir, list)
			var stdout, stderr bytes.Buffer
			code := runInstall([]string{"--json", "--bundle", f.skbPath, "--trust-roots", f.trPath, "--home", f.home, "--revocations", revPath}, &stdout, &stderr)
			var out bundleVerifyResult
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("invalid JSON: %v: %s", err, &stdout)
			}
			if code != tc.want || out.OK != (code == 0) || out.Freshness == nil || out.Freshness.Allowed != tc.allowed {
				t.Fatalf("code %d, result %+v, freshness %+v, stderr %s", code, out, out.Freshness, &stderr)
			}
		})
	}
}
