package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

func TestImportCredentialPriorityAndBinding(t *testing.T) {
	for _, tc := range []struct {
		name, explicit, bearer, api, pin, bearerPin, want string
		wantKind                                          httpsafe.CredentialKind
		deny                                              bool
	}{
		{name: "flag wins foreign bearer", explicit: "flag-key", bearer: "foreign-bearer", api: "env-key", pin: "https://a.example", bearerPin: "https://b.example", want: "flag-key", wantKind: httpsafe.CredentialAPIKey},
		{name: "bearer before ambient API", bearer: "bearer-key", api: "env-key", pin: "https://b.example", bearerPin: "https://a.example", want: "bearer-key", wantKind: httpsafe.CredentialDeviceBearer},
		{name: "API environment", api: "env-key", pin: "https://a.example", want: "env-key", wantKind: httpsafe.CredentialAPIKey},
		{name: "legacy after origin", pin: "https://a.example", want: "legacy-key", wantKind: httpsafe.CredentialAPIKey},
		{name: "bearer cannot use API pin", bearer: "bearer-key", api: "env-key", pin: "https://a.example", deny: true},
		{name: "foreign bearer no fallback", bearer: "bearer-key", api: "env-key", pin: "https://a.example", bearerPin: "https://b.example", deny: true},
		{name: "flag mismatch no fallback", explicit: "flag-key", bearer: "bearer-key", pin: "https://b.example", bearerPin: "https://a.example", deny: true},
		{name: "legacy missing pin", deny: true},
		{name: "legacy wrong pin", pin: "https://b.example", deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"ER1_DEVICE_TOKEN": tc.bearer, "ER1_DEVICE_TOKEN_ORIGIN": tc.bearerPin, "M3C_API_KEY": tc.api, "M3C_API_KEY_ORIGIN": tc.pin}
			reads := 0
			selected, err := selectImportCredential(importOptions{target: "https://a.example/prefix", apiKey: tc.explicit}, func(name string) string { return env[name] }, func() string { reads++; return "legacy-key" })
			if err != nil {
				t.Fatal(err)
			}
			result, err := httpsafe.ResolveCredential("https://a.example/prefix", false, selected)
			if tc.deny {
				if err == nil || reads != 0 {
					t.Fatalf("invalid selected source allowed or legacy read: %v reads=%d", err, reads)
				}
				return
			}
			if err != nil || string(result.Secret) != tc.want || result.Binding.Kind != tc.wantKind {
				t.Fatalf("wrong selected source: %v", err)
			}
			if (tc.name == "legacy after origin") != (reads == 1) {
				t.Fatalf("legacy reads=%d", reads)
			}
		})
	}
}

func TestImportRejectsInvalidTargetBeforeEnvironment(t *testing.T) {
	for _, target := range []string{"https://synthetic:secret@a.example", "http://remote.example", "https://a.example?query", "https://a.example:0"} {
		_, err := selectImportCredential(importOptions{target: target}, func(string) string { t.Fatal("environment read before target validation"); return "" }, func() string { t.Fatal("session read before target validation"); return "" })
		if err == nil {
			t.Fatal("invalid target accepted")
		}
	}
}

func TestImportDryRunAvoidsSecretReaders(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	inventory := filepath.Join(home, "scan.json")
	if err := os.WriteFile(inventory, []byte(`{"skills":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	forbiddenEnv := func(string) string { t.Fatal("dryrun read credential environment or identity"); return "" }
	forbiddenSession := func() string { t.Fatal("dryrun read session"); return "" }
	if rc := runImportWithReaders([]string{"--target", "https://a.example/prefix", "--input", inventory, "--dry-run"}, forbiddenEnv, forbiddenSession, io.Discard, io.Discard); rc != 0 {
		t.Fatalf("dryrun exit=%d", rc)
	}
	if rc := runImportWithReaders([]string{"--target", "http://remote.example", "--input", inventory, "--dry-run"}, forbiddenEnv, forbiddenSession, io.Discard, io.Discard); rc != 1 {
		t.Fatalf("unsafe dryrun target exit=%d", rc)
	}
}

func TestLegacySessionAPIKeyStrict(t *testing.T) {
	for _, raw := range []string{`{}`, `{"context_id":"context"}`, `{"api_key":null}`, `{"api_key":true}`, `{"api_key":123}`, `{"api_key":{}}`, `{"api_key":[]}`, `{"api_key":""}`, `{"api_key":"  "}`, `{"api_key":"first","api_key":"last"}`, `{"api_key":"first","api\u005fkey":"last"}`, `{"API_KEY":"alias"}`, `{"api_key":"first","API_KEY":"last"}`, `{"api_Key":"alias"}`, `{"api_key":"key"} {}`, `null`, `[]`} {
		if key, err := decodeLegacySessionAPIKey([]byte(raw)); err == nil || key != "" {
			t.Fatalf("ambiguous/missing key accepted: %s", raw)
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "er1_session.json"), []byte(`{"context_id":"context","api_key":"legacy-key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readAPIKeyFromSession(); got != "legacy-key" {
		t.Fatal("valid legacy source rejected")
	}
	selected, err := resolveUsageConnection(usageConnectionOptions{Target: "https://a.example", KeyOrigin: "https://a.example"}, func(string) string { return "" }, readAPIKeyFromSession)
	if err != nil || string(selected.Secret) != "legacy-key" {
		t.Fatalf("shared sync-usage reader regressed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "er1_session.json"), []byte(`{"api_key":"first","api\u005fkey":"last"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readAPIKeyFromSession(); got != "" {
		t.Fatal("duplicate legacy source accepted")
	}
	if _, err := resolveUsageConnection(usageConnectionOptions{Target: "https://a.example", KeyOrigin: "https://a.example"}, func(string) string { return "" }, readAPIKeyFromSession); err == nil {
		t.Fatal("sync-usage accepted duplicate legacy API key")
	}
}

func TestImportArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"--target"}, {"--target", "--api-key"}, {"--target", "https://a.example", "--api-key-origin"}, {"--target", "https://a.example", "--unknown"}} {
		if _, err := parseImportArgs(args); err == nil {
			t.Fatalf("invalid import args accepted: %v", args)
		}
	}
}

func TestImportBoundCLIEntryPoint(t *testing.T) {
	binary := skillctlBin(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_API_KEY", "environment-key")
	t.Setenv("M3C_API_KEY_ORIGIN", "")
	t.Setenv("ER1_DEVICE_TOKEN", "foreign-bearer")
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "")
	var gotA, gotB atomic.Int32
	var phase atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA.Add(1)
		if r.URL.Path != "/prefix/health" && r.URL.Path != "/prefix/api/v2/skills/profile/import" {
			t.Error("prefix lost")
		}
		mode := phase.Load()
		if mode == 2 {
			if r.Header.Get("Authorization") != "Bearer foreign-bearer" || r.Header.Get("X-API-KEY") != "" {
				t.Error("Bearer precedence lost")
			}
		} else if r.Header.Get("X-API-KEY") != "explicit-key" || r.Header.Get("Authorization") != "" {
			t.Error("explicit API key overridden")
		}
		if mode == 3 {
			http.Error(w, "reflected explicit-key", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "synthetic-skill") {
				t.Error("inventory not posted")
			}
			if mode == 4 {
				io.WriteString(w, `{"message":"reflected explicit-key"}`)
				return
			}
			io.WriteString(w, `{"imported":1,"message":"safe"}`)
		}
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotB.Add(1)
		t.Error("mismatched origin received a request or inventory")
	}))
	defer b.Close()
	inventory := filepath.Join(home, "scan.json")
	if err := os.WriteFile(inventory, []byte(`{"skills":[{"name":"synthetic-skill"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) int {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"import", "--input", inventory}, args...)...)
		out, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil {
			t.Fatalf("start CLI: %v", err)
		}
		for _, key := range []string{"explicit-key", "foreign-bearer", "environment-key"} {
			if strings.Contains(string(out), key) {
				t.Fatalf("credential leaked: %s", key)
			}
		}
		return cmd.ProcessState.ExitCode()
	}
	if rc := run("--target", b.URL, "--api-key", "explicit-key", "--api-key-origin", a.URL, "--allow-loopback-http"); rc != 1 {
		t.Fatalf("mismatch exit=%d", rc)
	}
	if rc := run("--target", a.URL, "--api-key", "explicit-key", "--api-key-origin", a.URL); rc != 1 {
		t.Fatalf("implicit HTTP exit=%d", rc)
	}
	t.Setenv("M3C_API_KEY_ORIGIN", a.URL)
	if rc := run("--target", a.URL, "--allow-loopback-http"); rc != 1 {
		t.Fatalf("Bearer used API-key pin: %d", rc)
	}
	if gotA.Load() != 0 || gotB.Load() != 0 {
		t.Fatal("denied selection caused request")
	}
	// A preview ignores all credentials and pins and makes no health call.
	if rc := run("--target", a.URL+"/prefix", "--allow-loopback-http", "--dry-run"); rc != 0 {
		t.Fatalf("dryrun exit=%d", rc)
	}
	if gotA.Load() != 0 || gotB.Load() != 0 {
		t.Fatal("dryrun sent request")
	}
	if rc := run("--target", a.URL+"/prefix/", "--api-key", "explicit-key", "--api-key-origin", a.URL, "--allow-loopback-http"); rc != 0 {
		t.Fatalf("explicit key exit=%d", rc)
	}
	phase.Store(2)
	t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", a.URL)
	if rc := run("--target", a.URL+"/prefix", "--allow-loopback-http"); rc != 0 {
		t.Fatalf("bound Bearer exit=%d", rc)
	}
	phase.Store(3)
	if rc := run("--target", a.URL+"/prefix", "--api-key", "explicit-key", "--api-key-origin", a.URL, "--allow-loopback-http"); rc != 1 {
		t.Fatalf("HTTP401 exit=%d", rc)
	}
	phase.Store(4)
	if rc := run("--target", a.URL+"/prefix", "--api-key", "explicit-key", "--api-key-origin", a.URL, "--allow-loopback-http"); rc != 1 {
		t.Fatalf("reflected success exit=%d", rc)
	}
	phase.Store(0)
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("M3C_API_KEY", "")
	sessionDir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(sessionDir, "er1_session.json")
	if err := os.WriteFile(sessionPath, []byte(`{"api_key":"first","api\u005fkey":"explicit-key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if rc := run("--target", a.URL+"/prefix", "--allow-loopback-http"); rc != 1 {
		t.Fatalf("duplicate legacy key exit=%d", rc)
	}
	if gotA.Load() != 7 {
		t.Fatal("duplicate session key caused network request")
	}
	if err := os.WriteFile(sessionPath, []byte(`{"context_id":"context","api_key":"explicit-key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if rc := run("--target", a.URL+"/prefix", "--allow-loopback-http"); rc != 0 {
		t.Fatalf("bound legacy key exit=%d", rc)
	}
	if gotB.Load() != 0 || gotA.Load() != 9 {
		t.Fatalf("requests A=%d B=%d", gotA.Load(), gotB.Load())
	}
}
