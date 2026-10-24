package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/internal/dbdriver"
)

func TestUsageConnectionRejectsBeforeSecretRead(t *testing.T) {
	for _, tc := range []struct{ target, origin string }{
		{"https://b.example", "https://a.example"},
		{"https://a.example:444", "https://a.example"},
		{"http://a.example", "http://a.example"},
		{"https://a.example", ""},
		{"https://a.example", "https://a.example/api"},
		{"https://user:secret@a.example", "https://a.example"},
	} {
		t.Run(tc.target+"|"+tc.origin, func(t *testing.T) {
			reads := 0
			_, err := resolveUsageConnection(usageConnectionOptions{Target: tc.target, KeyOrigin: tc.origin}, func(k string) string {
				if k == "M3C_API_KEY" {
					reads++
				}
				return ""
			}, func() string { reads++; return "synthetic-secret" })
			if err == nil || reads != 0 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid connection: error=%v reads=%d", err, reads)
			}
		})
	}
}

func TestUsageConnectionPriority(t *testing.T) {
	for _, source := range []string{"flag", "environment", "session"} {
		t.Run(source, func(t *testing.T) {
			env := map[string]string{"M3C_API_URL": "https://env.example", "M3C_API_KEY_ORIGIN": "https://env.example"}
			opts := usageConnectionOptions{}
			switch source {
			case "flag":
				opts = usageConnectionOptions{Target: "https://flag.example/prefix", KeyOrigin: "https://FLAG.example:443", APIKey: "flag-key"}
				env["M3C_API_KEY"] = "wrong-key"
			case "environment":
				env["M3C_API_KEY"] = "environment-key"
			}
			reads := 0
			got, err := resolveUsageConnection(opts, func(k string) string { return env[k] }, func() string { reads++; return "session-key" })
			if err != nil || string(got.Secret) != source+"-key" {
				t.Fatalf("selected %s: %v", source, err)
			}
			if (source == "session") != (reads == 1) {
				t.Fatalf("unexpected session reads: %d", reads)
			}
			if source == "flag" && got.Base.URL != "https://flag.example:443/prefix" {
				t.Fatalf("target/prefix precedence lost: %s", got.Base.URL)
			}
		})
	}
}

func TestUsageConnectionArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{"--api-key"}, {"--target", "--api-key"}, {"--unknown"}, {"--api-key-origin", ""}} {
		if _, err := parseUsageConnectionArgs(args); err == nil {
			t.Fatalf("accepted invalid arguments %v", args)
		}
	}
}

func TestSyncUsageConnectionEntryPoint(t *testing.T) {
	binary := skillctlBin(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_API_URL", "")
	t.Setenv("M3C_API_KEY_ORIGIN", "")
	t.Setenv("M3C_API_KEY", "synthetic-key")
	var requests atomic.Int32
	var reject atomic.Bool
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/prefix/api/v2/skills/usage" || r.Header.Get("X-API-KEY") != "synthetic-key" || !strings.Contains(string(body), "synthetic-skill") {
			t.Error("invalid allowed request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if reject.Load() {
			http.Error(w, "reflected synthetic-key", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer a.Close()
	var deniedRequests atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deniedRequests.Add(1)
		t.Error("denied origin received a request or payload")
	}))
	defer b.Close()
	run := func(args []string) int {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"sync-usage"}, args...)...)
		out, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil {
			t.Fatalf("start CLI: %v", err)
		}
		if strings.Contains(string(out), "synthetic-key") {
			t.Fatal("CLI exposed credential")
		}
		return cmd.ProcessState.ExitCode()
	}
	if rc := run([]string{"--target", b.URL, "--api-key-origin", a.URL, "--allow-loopback-http"}); rc != 1 {
		t.Fatalf("changed server accepted: %d", rc)
	}
	dir := filepath.Join(home, ".m3c-tools")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("denied connection accessed database directory: %v", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(dbdriver.DriverName(), filepath.Join(dir, "skill-usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		"CREATE TABLE skill_usage (id INTEGER PRIMARY KEY, skill_id TEXT, user_id TEXT, timestamp TEXT, project TEXT, session_id TEXT, synced INTEGER DEFAULT 0, synced_at TEXT)",
		"INSERT INTO skill_usage (skill_id,user_id,timestamp,project,session_id) VALUES ('synthetic-skill','test-user','2026-01-01T00:00:00Z','test-project','test-session')",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--target", a.URL + "/prefix", "--api-key-origin", a.URL}
	if rc := run(args); rc != 1 {
		t.Fatalf("implicit HTTP accepted: %d", rc)
	}
	if rc := run(append(args, "--allow-loopback-http")); rc != 0 {
		t.Fatalf("allowed pair failed: %d", rc)
	}
	var synced int
	if err := db.QueryRow("SELECT synced FROM skill_usage WHERE id=1").Scan(&synced); err != nil || synced != 1 {
		t.Fatalf("successful usage not acknowledged: %d %v", synced, err)
	}
	if deniedRequests.Load() != 0 || requests.Load() != 1 {
		t.Fatalf("requests: allowed=%d denied=%d", requests.Load(), deniedRequests.Load())
	}
	if _, err := db.Exec("UPDATE skill_usage SET synced=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	if rc := run(append(args, "--allow-loopback-http")); rc != 1 {
		t.Fatalf("server refusal reported success: %d", rc)
	}
	if err := db.QueryRow("SELECT synced FROM skill_usage WHERE id=1").Scan(&synced); err != nil || synced != 0 {
		t.Fatalf("rejected usage acknowledged: %d %v", synced, err)
	}
	if deniedRequests.Load() != 0 || requests.Load() != 2 {
		t.Fatalf("requests after refusal: allowed=%d denied=%d", requests.Load(), deniedRequests.Load())
	}
}
