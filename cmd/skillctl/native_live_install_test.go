package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type c33CLILive struct {
	source            *qaNativeSourceCLI
	carrier           *httptest.Server
	archive, markdown []byte
	digest            string
	admit             map[string]any
	attest            []map[string]any
	requests          atomic.Int32
	mu                sync.Mutex
	rows              []map[string]any
}

func c33CLINew(t *testing.T) *c33CLILive {
	t.Helper()
	f := &c33CLILive{source: qaNativeSourceCLIFixture(t)}
	manifest := []byte(`{"schema":"m3c-skill-bundle/v2","kind":"agent","name":"live-cli-agent","version":"1.0.0","depends_on":[]}`)
	f.markdown = []byte("---\nname: live-cli-agent\n---\n\nActual held CLI agent fixture.\n")
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		raw  []byte
	}{{"bundle.json", manifest}, {"live-cli-agent.md", f.markdown}} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.raw)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	f.archive = archive.Bytes()
	sum := sha256.Sum256(f.archive)
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	key := f.source.base.artifactKey
	fp := sha256.Sum256(key.Public().(ed25519.PublicKey))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, sum[:]))
	var err error
	f.admit, err = registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{BundleDigest: f.digest, Name: "live-cli-agent", Version: "1.0.0", AuthorIntent: "green", AdmittedByIdentity: "cli-live-author", AdmittedAt: time.Now().UTC().Add(-time.Minute), Signatures: []registry.SignatureRef{{Role: "author", IdentityID: "cli-live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}, {Role: "registry", IdentityID: "cli-live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.SignEnvelopeSignature(key, f.admit); err != nil {
		t.Fatal(err)
	}
	roots := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + "\ngovernance_minimum: green\ngovernance_quorum: 2\nsigners:\n"
	for _, id := range []string{"cli-live-reviewer-a", "cli-live-reviewer-b"} {
		pk, sk, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		roots += fmt.Sprintf(" - reviewer_id: %s\n   pubkey_b64: %s\n", id, base64.StdEncoding.EncodeToString(pk))
		event, e := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{BundleDigest: f.digest, ReviewerID: id, GovernanceLevel: "green", Rationale: "actual CLI independent fixture", OccurredAt: time.Now().UTC().Add(-time.Minute)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = registry.SignEnvelopeSignature(sk, event); e != nil {
			t.Fatal(e)
		}
		f.attest = append(f.attest, event)
	}
	ref := f.source.doc["native"].(map[string]any)["artifact_trust"].(map[string]any)
	path := ref["path"].(string)
	if err = os.WriteFile(path, []byte(roots), 0600); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256([]byte(roots))
	ref["sha256"] = hex.EncodeToString(sum[:])
	for i, event := range append([]map[string]any{f.admit}, f.attest...) {
		raw, e := json.Marshal(event)
		if e != nil {
			t.Fatal(e)
		}
		body := "```json\n" + string(raw) + "\n```\n"
		if i == 0 {
			body += "```skb-base64\n" + base64.StdEncoding.EncodeToString(f.archive) + "\n```\n"
		}
		f.rows = append(f.rows, map[string]any{"doc_id": fmt.Sprintf("cli-live-%d", i), "transcript": body})
	}
	var ca []byte
	f.carrier, ca = qaNativeSourceCLITLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != "GET" || r.ProtoMajor != 1 || r.URL.EscapedPath() != "/bound/base/memory/cli___agents" || r.URL.Query().Get("limit") != "500" || r.URL.Query().Get("range") != "year" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("actual CLI live carrier escaped explicit public TLS selection")
		}
		f.mu.Lock()
		rows := f.rows
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"items": rows}); err != nil {
			t.Error(err)
		}
	}))
	caPath := filepath.Join(f.source.base.project, "live-ca.pem")
	if err = os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(ca)
	f.source.doc["schema"] = "m3c.enterprise-project-profile/v4"
	f.source.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "er1", "base_url": f.carrier.URL + "/bound/base", "context_id": "cli___agents", "auth": map[string]any{"mode": "none"}, "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]any{"path": caPath, "sha256": hex.EncodeToString(sum[:])}}}
	f.source.save(t)
	return f
}
func (f *c33CLILive) args() []string {
	return []string{"pull", "--enterprise-profile", f.source.base.path, "--enterprise-profile-sha256", f.source.base.pin, "--home", f.source.base.home, "--kind", "agent", "--digest", f.digest, "--install", "--trust-mode", "--native-session"}
}
func (f *c33CLILive) enroll(t *testing.T, binary, flags string) {
	t.Helper()
	path, _ := c33EnrollEvidence(t, f.source)
	if code, out := qaNativeSourceRun(t, binary, flags, f.source, c33EnrollArgs(f.source, path)); code != 0 {
		t.Fatalf("actual local enrollment prerequisite failed: %d %s", code, out)
	}
}
func c33CLIFrame(t *testing.T, f *c33CLILive) {
	t.Helper()
	base := filepath.Join(f.source.base.home, ".claude", "agents")
	raw, err := os.ReadFile(filepath.Join(base, ".skillctl-evidence", "live-cli-agent.record"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 12 || string(raw[:8]) != "M3CAGT1\n" {
		t.Fatal("CLI did not publish framed proof")
	}
	n := int(binary.BigEndian.Uint32(raw[8:12]))
	if n < 1 || n > 8192 || 12+n > len(raw) {
		t.Fatal("CLI record header invalid")
	}
	var h map[string]any
	if err = json.Unmarshal(raw[12:12+n], &h); err != nil {
		t.Fatal(err)
	}
	archiveBytes := int(h["archive_bytes"].(float64))
	contextBytes := int(h["context_bytes"].(float64))
	start := 12 + n
	if start+archiveBytes+contextBytes != len(raw) || !bytes.Equal(raw[start:start+archiveBytes], f.archive) || h["bundle_digest"] != f.digest {
		t.Fatal("CLI record not exact original signed archive")
	}
	ctxRaw := raw[start+archiveBytes:]
	sum := sha256.Sum256(ctxRaw)
	if h["context_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatal("CLI context hash mismatch")
	}
	var ctx registry.AttestationContext
	if err = json.Unmarshal(ctxRaw, &ctx); err != nil {
		t.Fatal(err)
	}
	if len(ctx.GovernanceAttestations) != 2 {
		t.Fatal("CLI proof lost full quorum")
	}
	want, _ := json.Marshal(f.admit)
	got, _ := json.Marshal(ctx.AdmitEvent)
	if !bytes.Equal(want, got) {
		t.Fatal("CLI retained different admission")
	}
	for i, event := range ctx.GovernanceAttestations {
		want, _ = json.Marshal(f.attest[i])
		got, _ = json.Marshal(event)
		if !bytes.Equal(want, got) {
			t.Fatal("CLI retained different signed reviewer event")
		}
	}
	md, err := os.ReadFile(filepath.Join(base, "live-cli-agent.md"))
	if err != nil || !bytes.Equal(md, f.markdown) {
		t.Fatal("CLI active bytes changed", err)
	}
}

type c33CLIOutput struct {
	mode      string
	calls     int
	input     bytes.Buffer
	afterPlan func()
}

func (w *c33CLIOutput) Write(p []byte) (int, error) {
	w.calls++
	fail := w.calls == 1 && strings.HasPrefix(w.mode, "plan-") || w.calls == 2 && strings.HasPrefix(w.mode, "final-")
	if fail {
		if strings.HasSuffix(w.mode, "short") {
			return len(p) - 1, nil
		}
		return 0, errors.New("synthetic output writer failure")
	}
	if w.calls == 1 {
		var plan struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(p, &plan); err != nil {
			return 0, err
		}
		if len(plan.Token) != 43 {
			return 0, errors.New("plan did not contain bounded consent token")
		}
		if w.afterPlan != nil {
			w.afterPlan()
		} else if _, err := w.input.WriteString(plan.Token + "\n"); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

type c33WaitingReader struct {
	reader  *io.PipeReader
	entered chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (r *c33WaitingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	defer close(r.done)
	return r.reader.Read(p)
}

func TestNativeLiveInstallActualCLI(t *testing.T) {
	if mode := os.Getenv("M3C_C33_LIVE_OUTPUT_CHILD"); mode != "" {
		var params struct{ Profile, Pin, Home, Digest string }
		if err := json.Unmarshal([]byte(os.Getenv("M3C_C33_LIVE_OUTPUT_ARGS")), &params); err != nil {
			t.Fatal(err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		p, err := projectpolicy.LoadNativePinned(params.Profile, params.Pin, cwd, params.Home)
		if err != nil {
			t.Fatal(err)
		}
		writer := &c33CLIOutput{mode: mode}
		var diagnostic bytes.Buffer
		ctx := context.Background()
		var input io.Reader = &writer.input
		var waiting *c33WaitingReader
		var workerDone chan error
		var closeWait func()
		if mode == "cancel-wait" || mode == "deadline-wait" {
			reader, pipeWriter := io.Pipe()
			waiting = &c33WaitingReader{reader: reader, entered: make(chan struct{}), done: make(chan struct{})}
			input = waiting
			var cancel context.CancelFunc
			if mode == "cancel-wait" {
				ctx, cancel = context.WithCancel(ctx)
			} else {
				ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
			}
			writer.afterPlan = func() {} // Successful Plan output returns without supplying consent.
			closeWait = func() {
				cancel()
				_ = reader.Close()
				_ = pipeWriter.Close()
			}
			defer closeWait()
			workerDone = make(chan error, 1)
			go func() {
				select {
				case <-waiting.entered:
					if mode == "cancel-wait" {
						cancel()
					} else {
						deadline, ok := ctx.Deadline()
						if !ok || time.Until(deadline) < time.Second {
							workerDone <- errors.New("stdin read left insufficient deadline headroom")
							cancel()
							return
						}
						<-ctx.Done()
					}
					workerDone <- nil
				case <-ctx.Done():
					workerDone <- errors.New("context ended before stdin reader entry")
				}
			}()
		}
		code := runNativeAgentPull(ctx, input, writer, &diagnostic, p, params.Digest)
		if mode == "cancel-wait" || mode == "deadline-wait" {
			closeWait()
			select {
			case err := <-workerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("stdin cancellation worker did not finish")
			}
			select {
			case <-waiting.done:
			case <-time.After(time.Second):
				t.Fatal("blocked stdin reader did not finish after pipe cleanup")
			}
			want := context.Canceled
			if mode == "deadline-wait" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(ctx.Err(), want) || writer.calls != 1 {
				t.Fatalf("wait fault did not follow exactly one successful plan: %v, writes=%d", ctx.Err(), writer.calls)
			}
		}
		if code != 1 {
			t.Fatalf("output fault reported success: %d %s", code, diagnostic.String())
		}
		if strings.HasPrefix(mode, "final-") && !strings.Contains(diagnostic.String(), "may already have changed") {
			t.Fatal("postpublication uncertainty hidden", diagnostic.String())
		}
		return
	}
	t.Run("source-IO-over-selection", func(t *testing.T) {
		var diagnostic bytes.Buffer
		if code := nativePullFailure(&diagnostic, errors.Join(registry.ErrNativeLiveSourceIO, projectpolicy.ErrSelection)); code != 1 {
			t.Fatalf("source I/O lost precedence over selection: %d %s", code, diagnostic.String())
		}
	})
	binary, flags, faultChild := qaNativeSourceBinary(t)
	for _, mode := range []string{"LF", "CRLF", "later-input-ignored", "wrong-token", "blank", "EOF", "missing-newline", "extra-before-newline", "target-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := c33CLINew(t)
			f.enroll(t, binary, flags)
			before := qaNativeSourceArtifactInventory(t, f.source.base.home)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, f.args()...)
			cmd.WaitDelay = time.Second
			cmd.Dir = f.source.base.project
			cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.source.base.home), "GOFLAGS", flags)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var diagnostic bytes.Buffer
			cmd.Stderr = &diagnostic
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			reader := bufio.NewReader(output)
			line, err := reader.ReadString('\n')
			if err != nil {
				_ = cmd.Wait()
				t.Fatalf("actual native CLI produced no plan: %v %s", err, diagnostic.String())
			}
			var plan struct {
				Type    string                          `json:"type"`
				Rows    []registry.NativeInstallPlanRow `json:"rows"`
				Token   string                          `json:"token"`
				Expires time.Time                       `json:"expires_at"`
			}
			if err = json.Unmarshal([]byte(line), &plan); err != nil || plan.Type != "native-agent-plan" || len(plan.Rows) != 1 || plan.Rows[0].Digest != f.digest || len(plan.Token) != 43 {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("actual plan unbound: %s %v", line, err)
			}
			if !reflect.DeepEqual(before, qaNativeSourceArtifactInventory(t, f.source.base.home)) {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("plan/acquisition published before stdin confirmation")
			}
			busy, cancelBusy := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, busyErr := f.source.journal(t).Status(busy)
			cancelBusy()
			if !errors.Is(busyErr, context.DeadlineExceeded) {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("actual child did not hold native lease while awaiting consent", busyErr)
			}
			send := plan.Token + "\n"
			want := 0
			switch mode {
			case "CRLF":
				send = plan.Token + "\r\n"
			case "later-input-ignored":
				send = plan.Token + "\nnot-a-second-confirmation\n"
			case "wrong-token":
				send = strings.Repeat("A", 43) + "\n"
				want = 12
			case "blank":
				send = "\n"
				want = 12
			case "EOF":
				send = ""
				want = 12
			case "missing-newline":
				send = plan.Token
				want = 12
			case "extra-before-newline":
				send = plan.Token + "x\n"
				want = 12
			case "target-drift":
				dir := filepath.Join(f.source.base.home, ".claude", "agents")
				if err = os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "live-cli-agent.md"), []byte("separate actor state"), 0600); err != nil {
					t.Fatal(err)
				}
				before = qaNativeSourceArtifactInventory(t, f.source.base.home)
				want = 12
			}
			if send != "" {
				if _, err = io.WriteString(input, send); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "EOF" || mode == "missing-newline" {
				if err = input.Close(); err != nil {
					t.Fatal(err)
				}
			}
			rest, readErr := io.ReadAll(reader)
			err = cmd.Wait()
			if readErr != nil || ctx.Err() != nil {
				t.Fatal("bounded live child did not complete", readErr, ctx.Err())
			}
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != want {
				t.Fatalf("actual consent %s code=%d want=%d stderr=%s", mode, code, want, diagnostic.String())
			}
			if want == 0 {
				var result struct {
					Type string `json:"type"`
				}
				if err = json.Unmarshal(rest, &result); err != nil || result.Type != "native-agent-installed" {
					t.Fatal("missing checked final installation output", err)
				}
				c33CLIFrame(t, f)
			} else if len(rest) != 0 || !reflect.DeepEqual(before, qaNativeSourceArtifactInventory(t, f.source.base.home)) {
				t.Fatal("refused first-line consent published or reported installed")
			}
			released, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err = f.source.journal(t).Status(released); err != nil {
				t.Fatal("actual child did not checked-release journal", err)
			}
			if f.requests.Load() != 1 || f.source.requests.Load() != 0 || f.source.base.requests.Load() != 0 {
				t.Fatal("actual live CLI fetched legacy/source/unreviewed snapshot")
			}
		})
	}
	for _, mode := range []string{"missing-history", "legacy-false-flag", "v3-offline", "foreign-registry", "empty-pin"} {
		t.Run(mode, func(t *testing.T) {
			f := c33CLINew(t)
			if mode != "missing-history" {
				f.enroll(t, binary, flags)
			}
			args := f.args()
			want := 12
			switch mode {
			case "missing-history":
				want = 22
			case "legacy-false-flag":
				args = append(args, "--allow-downgrade=false")
				want = 2
			case "v3-offline":
				f.source.doc["schema"] = "m3c.enterprise-project-profile/v3"
				f.source.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "git", "locator": "github://example.invalid/owner/repo"}
				f.source.save(t)
				args = f.args()
			case "foreign-registry":
				args = append(args, "--registry", "foreign")
			case "empty-pin":
				args[4] = ""
			}
			before := nativeCLIQAInventory(t, f.source.base.home)
			code, out := qaNativeSourceRun(t, binary, flags, f.source, args)
			if code != want || f.requests.Load() != 0 || !reflect.DeepEqual(before, nativeCLIQAInventory(t, f.source.base.home)) {
				t.Fatalf("early native selection %s did not refuse before I/O: %d %s", mode, code, out)
			}
		})
	}
	for _, mode := range []string{"plan-error", "plan-short", "final-error", "final-short", "cancel-wait", "deadline-wait"} {
		t.Run(mode, func(t *testing.T) {
			f := c33CLINew(t)
			f.enroll(t, binary, flags)
			before := qaNativeSourceArtifactInventory(t, f.source.base.home)
			raw, err := json.Marshal(struct{ Profile, Pin, Home, Digest string }{f.source.base.path, f.source.base.pin, f.source.base.home, f.digest})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, faultChild, "-test.run=^TestNativeLiveInstallActualCLI$")
			cmd.WaitDelay = time.Second
			cmd.Dir = f.source.base.project
			cmd.Env = qaNativeSourceEnv(nativeCLIQAEnv(f.source.base.home), "GOFLAGS", flags)
			cmd.Env = qaNativeSourceEnv(cmd.Env, "M3C_C33_LIVE_OUTPUT_CHILD", mode)
			cmd.Env = qaNativeSourceEnv(cmd.Env, "M3C_C33_LIVE_OUTPUT_ARGS", string(raw))
			out, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil {
				t.Fatalf("active-provider fault child assertion failed: %v %s", err, out)
			}
			if strings.HasPrefix(mode, "plan-") || strings.HasSuffix(mode, "-wait") {
				if !reflect.DeepEqual(before, qaNativeSourceArtifactInventory(t, f.source.base.home)) {
					t.Fatal("failed plan output published")
				}
			} else {
				c33CLIFrame(t, f)
			}
			released, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err = f.source.journal(t).Status(released); err != nil {
				t.Fatal("fault helper left native lease held", err)
			}
		})
	}
}
