package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAttestReceiptActualSignedMessage(t *testing.T) {
	private, _, public := makeReviewerKeys(t, t.TempDir())
	fr, srv := newFakeRegistry(t, public)
	var stdout, stderr bytes.Buffer
	now := func() time.Time { return time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC) }
	// A digest-shaped rationale must remain a flag value, not become a second positional.
	code := runAttestWithClient([]string{"--json", "--level", "green", "--rationale", validDigestForTest, "--reviewer-id", "id:fixture", "--key", private, "--registry", srv.URL, "--", validDigestForTest}, &stdout, &stderr, now, srv.Client())
	var receipt attestReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if code != 0 || !receipt.OK || receipt.Schema != attestReceiptSchema || receipt.AttestationID != "att_test_001" || receipt.BundleDigest != fr.lastRequest.BundleDigest || receipt.GovernanceLevel != fr.lastRequest.GovernanceLevel || receipt.ReviewerID != fr.lastRequest.ReviewerID || receipt.AttestedAt != fr.lastRequest.AttestedAt {
		t.Fatalf("code %d receipt %+v stderr %s", code, receipt, &stderr)
	}
}

func TestAttestReceiptFailures(t *testing.T) {
	private, _, _ := makeReviewerKeys(t, t.TempDir())
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden", 403, `{"error":"synthetic-bearer-response"}`}, {"bad-request", 400, `{"error":"synthetic-bearer-response"}`}, {"empty", 201, `{}`},
		{"malformed", 201, `not JSON`}, {"duplicate", 201, `{"attestation_id":"one","attestation_id":"two"}`},
		{"whitespace", 201, `{"attestation_id":" "}`}, {"control", 201, `{"attestation_id":"line\nforged"}`},
		{"trailing", 201, `{"attestation_id":"one"} {}`}, {"oversized", 201, strings.Repeat(" ", (1<<20)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			var stdout, stderr bytes.Buffer
			code := runAttest([]string{"--json", "--level", "green", "--rationale", "synthetic", "--reviewer-id", "id:fixture", "--key", private, "--registry", srv.URL, validDigestForTest}, &stdout, &stderr)
			var receipt attestReceipt
			if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(stdout.String()+stderr.String(), "synthetic-bearer-response") {
				t.Fatal("reflected server body")
			}
			if code == 0 || receipt.OK || receipt.ExitCode != code || receipt.Error == "" || receipt.AttestationID != "" {
				t.Fatalf("code%d receipt%+v stderr%s", code, receipt, &stderr)
			}
		})
	}
}

func TestAttestReceiptUsageAndOutputFailure(t *testing.T) {
	for _, args := range [][]string{{"--json"}, {"--json", "--unknown"}} {
		var stdout, stderr bytes.Buffer
		code := runAttest(args, &stdout, &stderr)
		var receipt attestReceipt
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if code != 2 || receipt.OK || receipt.ExitCode != 2 || receipt.Error == "" {
			t.Fatalf("code%d receipt%+v", code, receipt)
		}
	}
	private, _, public := makeReviewerKeys(t, t.TempDir())
	_, srv := newFakeRegistry(t, public)
	for _, jsonFlag := range []bool{true, false} {
		args := []string{"--level", "green", "--rationale", "fixture", "--reviewer-id", "id:fixture", "--key", private, "--registry", srv.URL, validDigestForTest}
		if jsonFlag {
			args = append([]string{"--json"}, args...)
		}
		var stderr bytes.Buffer
		if code := runAttest(args, rejectedTrustWriter{}, &stderr); code != 1 || stderr.Len() == 0 {
			t.Fatalf("code%d stderr%s", code, &stderr)
		}
	}
}

func TestAttestReceiptMCPSubprocess(t *testing.T) {
	python := os.Getenv("M3C_MCP_TEST_PYTHON")
	if python == "" {
		t.Skip("run through MCP pytest for the Python interpreter")
	}
	home := t.TempDir()
	private, _, public := makeReviewerKeys(t, home)
	_, srv := newFakeRegistry(t, public)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(bad.Close)
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(empty.Close)
	moduleDir, err := filepath.Abs(filepath.Join("..", "..", "mcp-skill-server"))
	if err != nil {
		t.Fatal(err)
	}
	probe := `import asyncio,json,os,sys
sys.path.insert(0,sys.argv[1])
import server
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def probe():
    args={"digest":sys.argv[3],"level":"green","rationale":"synthetic receipt fixture","reviewer_id":"id:fixture","key":sys.argv[4],"registry":sys.argv[2]}
    posted=await server.skill_attest(**args)
    assert posted["ok"] and posted["attestation_id"]=="att_test_001" and posted["attested_at"],posted
    assert posted["reviewer_id"]==args["reviewer_id"] and posted["bundle_digest"]==args["digest"],posted
    assert "governance_verified" not in posted and "self_attested" not in posted,posted
    for registry in sys.argv[5:7]:
        refused=await server.skill_attest(**dict(args,registry=registry))
        assert refused["ok"] is False and refused["exit_code"]==1,refused
    params=StdioServerParameters(command=sys.executable,args=[os.path.join(sys.argv[1],"server.py")],env=dict(os.environ))
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            tools=await session.list_tools()
            assert "skill_attest" in [tool.name for tool in tools.tools],tools
            called=await session.call_tool("skill_attest",args)
            assert not called.isError and len(called.content)==1,called
            payload=json.loads(called.content[0].text)
            assert payload["ok"] and payload["attestation_id"]==posted["attestation_id"],payload
            assert payload["bundle_digest"]==args["digest"] and payload["reviewer_id"]==args["reviewer_id"],payload
asyncio.run(probe())`
	cmd := exec.Command(python, "-c", probe, moduleDir, srv.URL, validDigestForTest, private, bad.URL, empty.URL)
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_ER1_KEYCHAIN=off", "M3C_TEST_KEYCHAIN=0", "SKILLCTL_BIN="+skillctlBin(t))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("attest public tools/stdio: %v\n%s", err, output)
	}
}

func TestAttestReceiptRedirectsRefused(t *testing.T) {
	private, _, _ := makeReviewerKeys(t, t.TempDir())
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var forwarded atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"attestation_id":"foreign-receipt"}`))
			}))
			t.Cleanup(target.Close)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			t.Cleanup(origin.Close)
			client := origin.Client()
			client.Timeout = 7 * time.Second
			sentinel := errors.New("original redirect policy")
			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return sentinel }
			var stdout, stderr bytes.Buffer
			code := runAttestWithClient([]string{"--json", "--level", "green", "--rationale", "synthetic", "--reviewer-id", "id:fixture", "--key", private, "--registry", origin.URL, validDigestForTest}, &stdout, &stderr, time.Now, client)
			var receipt attestReceipt
			if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
				t.Fatal(err)
			}
			if code != 1 || receipt.OK || forwarded.Load() != 0 {
				t.Fatalf("code%d receipt%+v forwarded%d", code, receipt, forwarded.Load())
			}
			if client.Timeout != 7*time.Second || client.CheckRedirect(nil, nil) != sentinel {
				t.Fatal("injected client policy mutated")
			}
		})
	}
}

func TestAttestReceiptRejectsCredentialURLsBeforeKeyAccess(t *testing.T) {
	for _, registry := range []string{"https://user:synthetic-password@example.invalid/api/skills", "https://example.invalid/api/skills?token=synthetic-password", "https://example.invalid/api/skills#synthetic-password", "https://example.invalid/api/skills?"} {
		var stdout, stderr bytes.Buffer
		code := runAttest([]string{"--json", "--level", "green", "--rationale", "fixture", "--reviewer-id", "id:fixture", "--key", filepath.Join(t.TempDir(), "missing.private"), "--registry", registry, validDigestForTest}, &stdout, &stderr)
		var receipt attestReceipt
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if code != 2 || receipt.OK || strings.Contains(stdout.String()+stderr.String(), "synthetic-password") {
			t.Fatalf("code%d receipt%+v stderr%s", code, receipt, &stderr)
		}
	}
}

func TestAttestReceiptRejectsCredentialInReturnedID(t *testing.T) {
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-receipt-bearer")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")
	private, _, _ := makeReviewerKeys(t, t.TempDir())
	for _, id := range []string{"synthetic-receipt-bearer", "receipt-synthetic-receipt-bearer-suffix"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"attestation_id": id})
		}))
		t.Cleanup(server.Close)
		t.Setenv("M3C_REGISTRY_TOKEN_ORIGIN", server.URL)
		for _, machine := range []bool{true, false} {
			args := []string{"--level", "green", "--rationale", "fixture", "--reviewer-id", "id:fixture", "--key", private, "--registry", server.URL, validDigestForTest}
			if machine {
				args = append([]string{"--json"}, args...)
			}
			var stdout, stderr bytes.Buffer
			code := runAttest(args, &stdout, &stderr)
			if code != 1 || strings.Contains(stdout.String()+stderr.String(), "synthetic-receipt-bearer") {
				t.Fatalf("credential reflection was not refused safely: code%d", code)
			}
			if machine {
				var receipt attestReceipt
				if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
					t.Fatal(err)
				}
				if receipt.OK || receipt.AttestationID != "" {
					t.Fatal("reflected credential accepted as receipt ID")
				}
			}
		}
	}
}
