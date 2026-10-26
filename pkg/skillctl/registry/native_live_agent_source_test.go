package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

func nativeLiveTestItems(t *testing.T, f *nativeSessionQAFixture) []any {
	t.Helper()
	items := []any{f.agent.admit}
	for i, event := range f.agent.staged.Attestation.GovernanceAttestations {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, map[string]any{"id": string(rune('a' + i)), "tags": "skill-event:revoked", "transcript": "# signed attestation\n\n```json\n" + string(raw) + "\n```\n"})
	}
	return items
}

func nativeLiveTestWire(t *testing.T, items []any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nativeLiveTestSource(t *testing.T, mode, family string, handler http.Handler) *NativeLiveAgentSource {
	t.Helper()
	caRaw, ca, key := nativeSourceTestCA(t, 701)
	server := nativeSourceTestServer(t, ca, key, handler, nil)
	base, err := httpsafe.ParseAPIBase(server.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	origin := ""
	if mode == "external-env" {
		origin = base.Origin.String()
	}
	source, err := NewNativeLiveAgentSource(NativeLiveAgentSourceOptions{BaseURL: server.URL + "/selected", ContextID: "tenant___context", AuthMode: mode, AuthFamily: family, AuthOrigin: origin, TLSMode: "pinned-pem", CAPEM: caRaw})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func nativeLiveTestSecret(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw[:])
}

func nativeLiveProxyChild(t *testing.T) {
	t.Helper()
	var proxyCalls, sourceCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(502)
	}))
	t.Cleanup(proxy.Close)
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	f := nativeSessionQANew(t, nil)
	wire := nativeLiveTestWire(t, nativeLiveTestItems(t, f))
	caRaw, ca, key := nativeSourceTestCA(t, 702)
	server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceCalls.Add(1)
		if r.ProtoMajor != 1 || r.URL.RequestURI() != "/selected/memory/tenant___context?limit=500&range=year" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			t.Error("public source endpoint/protocol/auth drift")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wire)
	}), nil)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	selected := net.JoinHostPort("evidence.synthetic.invalid", u.Port())
	source, err := NewNativeLiveAgentSource(NativeLiveAgentSourceOptions{BaseURL: "https://" + selected + "/selected", ContextID: "tenant___context", AuthMode: "none", TLSMode: "pinned-pem", CAPEM: caRaw})
	if err != nil {
		t.Fatal(err)
	}
	source.readEnv = func(string) (string, bool) { t.Error("public mode read a credential"); return "", false }
	dial := &net.Dialer{Timeout: time.Second}
	source.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == selected {
			address = u.Host
		}
		return dial.DialContext(ctx, network, address)
	}
	candidate, err := source.Fetch(context.Background(), f.begin(t))
	if err != nil || candidate == nil || !bytes.Equal(candidate.Archive, f.agent.blob) || sourceCalls.Load() != 1 || proxyCalls.Load() != 0 {
		t.Fatalf("real nonloopback TLS source/proxy contract: %v source=%d proxy=%d", err, sourceCalls.Load(), proxyCalls.Load())
	}
}

func TestNativeLiveAgentSourceContract(t *testing.T) {
	if os.Getenv("M3C_NATIVE_LIVE_SOURCE_PROXY_CHILD") == "1" {
		nativeLiveProxyChild(t)
		return
	}
	t.Run("fresh-child-no-proxy", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, executable, "-test.run=^TestNativeLiveAgentSourceContract$")
		child.WaitDelay = time.Second
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "M3C_NATIVE_LIVE_SOURCE_PROXY_CHILD=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "M3C_NATIVE_LIVE_SOURCE_PROXY_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil || ctx.Err() != nil {
			t.Fatalf("proxy child failed: %v %s", err, output)
		}
	})
	for _, family := range []string{"none", "api-key", "bearer"} {
		t.Run("exact-family-"+family, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			wire := nativeLiveTestWire(t, nativeLiveTestItems(t, f))
			selected, unselected := nativeLiveTestSecret(t), nativeLiveTestSecret(t)
			t.Setenv("ER1_API_KEY", selected)
			t.Setenv("ER1_DEVICE_TOKEN", unselected)
			mode, kind := "external-env", family
			if family == "none" {
				mode, kind = "none", ""
			}
			var calls atomic.Int32
			source := nativeLiveTestSource(t, mode, kind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.URL.RequestURI() != "/selected/memory/tenant___context?limit=500&range=year" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("unexpected request shape")
				}
				wantBearer, wantKey := "", ""
				if family == "api-key" {
					wantKey = selected
				}
				if family == "bearer" {
					wantBearer = "Bearer " + unselected
				}
				if r.Header.Get("Authorization") != wantBearer || r.Header.Get("X-API-Key") != wantKey {
					t.Error("selected exactly-one credential family changed")
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write(wire)
			}))
			reads := 0
			source.readEnv = func(name string) (string, bool) {
				reads++
				want := "ER1_API_KEY"
				if family == "bearer" {
					want = "ER1_DEVICE_TOKEN"
				}
				if family == "none" || name != want {
					t.Error("unselected credential reader")
				}
				return os.LookupEnv(name)
			}
			candidate, err := source.Fetch(context.Background(), f.begin(t))
			if err != nil || candidate == nil || !bytes.Equal(candidate.Archive, f.agent.blob) || candidate.Bundle.Digest != f.agent.staged.Digest || candidate.Bundle.Kind != "agent" || candidate.Bundle.StagedSkbPath != "" || candidate.Bundle.ProvenancePath != "" || len(candidate.Bundle.Attestation.GovernanceAttestations) != len(f.agent.attest) || candidate.workBytes < 1 || candidate.workBytes > nativeLiveWorkMax || calls.Load() != 1 {
				t.Fatalf("genuine retained candidate failed: %v", err)
			}
			if (family == "none" && reads != 0) || (family != "none" && reads != 1) {
				t.Fatal("credential reread or fallback")
			}
		})
	}
	for _, excess := range []int{0, 1} {
		t.Run("body-boundary-"+string(rune('0'+excess)), func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			wire := nativeLiveTestWire(t, nativeLiveTestItems(t, f))
			limit := len(wire) + 64
			body := append(append([]byte(nil), wire...), bytes.Repeat([]byte(" "), 64+excess)...)
			source := nativeLiveTestSource(t, "none", "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.(http.Flusher).Flush() // unknown Content-Length reaches the cap+1 reader
				_, _ = w.Write(body)
			}))
			source.responseMax = limit // same cap logic, smaller per-instance test ceiling
			got, err := source.Fetch(context.Background(), f.begin(t))
			if excess == 0 {
				if err != nil || got == nil || !bytes.Equal(got.Archive, f.agent.blob) {
					t.Fatal("exact actual wire cap denied", err)
				}
			} else if got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("actual wire cap+1 supplied candidate", err)
			}
		})
	}
	t.Run("tokens-context-events-and-busy-bounds", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		items := nativeLiveTestItems(t, f)
		for len(items)-1 < 256 {
			items = append(items, items[1])
		}
		s := f.begin(t)
		candidate, err := nativeLiveParse(nativeLiveTestWire(t, items), "", s, &nativeLiveWork{})
		if err != nil || candidate == nil || len(candidate.Bundle.Attestation.GovernanceAttestations) != 256 {
			t.Fatal("exact supplied event cap denied", err)
		}
		items = append(items, items[1])
		if got, err := nativeLiveParse(nativeLiveTestWire(t, items), "", s, &nativeLiveWork{}); got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("event cap+1 supplied candidate", err)
		}
		for _, text := range []string{`"` + strings.Repeat("x", nativeLiveContextMax) + `"`, `[` + strings.Repeat("0,", nativeLiveTokenMax) + `0]`} {
			if _, err := nativeLiveJSON([]byte(text), nativeLiveContextMax, "", &nativeLiveWork{}); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("context/token ceiling accepted")
			}
		}
		source, err := NewNativeLiveAgentSource(NativeLiveAgentSourceOptions{BaseURL: "https://source.invalid", ContextID: "ctx", AuthMode: "none", TLSMode: "system"})
		if err != nil {
			t.Fatal(err)
		}
		source.readEnv = func(string) (string, bool) { t.Error("busy session read secret"); return "", false }
		s.mu.Lock()
		got, err := source.Fetch(context.Background(), s)
		s.mu.Unlock()
		if got != nil || !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatal("busy session did not fail closed", err)
		}
	})
	t.Run("complete-wrapper-only", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		items := nativeLiveTestItems(t, f)
		array, err := json.Marshal(items)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := nativeLiveParse(array, "", s, &nativeLiveWork{}); err != nil || got == nil {
			t.Fatal("canonical top-level array must really succeed", err)
		}
		for _, key := range []string{"next", "cursor", "has_more", "total"} {
			// Real signed candidate/quorum remain valid. Only the continuation or
			// unknown wrapper field differs, so a missing guard would grant it.
			raw, err := json.Marshal(map[string]any{"items": items, key: "partial"})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := nativeLiveParse(raw, "", s, &nativeLiveWork{}); got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("partial/unknown wrapper supplied candidate", key, err)
			}
		}
	})
	t.Run("session-before-credential-and-network", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		var calls atomic.Int32
		source := nativeLiveTestSource(t, "external-env", "bearer", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		source.readEnv = func(string) (string, bool) { t.Error("unavailable session read credential"); return "", false }
		for _, s := range []*NativeInstallSession{nil, {}} {
			if got, err := source.Fetch(context.Background(), s); got != nil || !errors.Is(err, ErrNativeSessionUnavailable) {
				t.Fatal("invalid session accepted", err)
			}
		}
		s := f.begin(t)
		f.now = f.now.Add(25 * time.Hour)
		if got, err := source.Fetch(context.Background(), s); got != nil || !errors.Is(err, ErrNativeHistoryStale) {
			t.Fatal("stale held journal accepted", err)
		}
		if calls.Load() != 0 {
			t.Fatal("preflight reached network")
		}
	})
	t.Run("missing-selected-value-never-falls-back", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		var calls atomic.Int32
		source := nativeLiveTestSource(t, "external-env", "api-key", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		reads := 0
		source.readEnv = func(name string) (string, bool) {
			reads++
			if name != "ER1_API_KEY" {
				t.Error("fallback reader")
			}
			return "", false
		}
		if got, err := source.Fetch(context.Background(), f.begin(t)); got != nil || !errors.Is(err, ErrNativeLiveSourceIO) || err.Error() != ErrNativeLiveSourceIO.Error() || reads != 1 || calls.Load() != 0 {
			t.Fatal("selected empty value escaped", err)
		}
	})
	t.Run("failed-fetch-terminal-before-second-secret-or-request", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		var requests atomic.Int32
		source := nativeLiveTestSource(t, "external-env", "api-key", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":null}`))
		}))
		reads := 0
		selected := nativeLiveTestSecret(t)
		source.readEnv = func(string) (string, bool) { reads++; return selected, true }
		s := f.begin(t)
		if got, err := source.Fetch(context.Background(), s); got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || reads != 1 || requests.Load() != 1 {
			t.Fatal("first genuine failing fetch did not reach selected source", err)
		}
		if got, err := source.Fetch(context.Background(), s); got != nil || !errors.Is(err, ErrNativeSessionUnavailable) || reads != 1 || requests.Load() != 1 {
			t.Fatal("failed session retried credential/network with fresh budget", err)
		}
	})
	t.Run("secret-reflection-plain-and-json-escaped", func(t *testing.T) {
		for _, escaped := range []bool{false, true} {
			f := nativeSessionQANew(t, nil)
			secret := "a" + nativeLiveTestSecret(t)
			t.Setenv("ER1_API_KEY", secret)
			wire := nativeLiveTestWire(t, nativeLiveTestItems(t, f))
			value := secret
			if escaped {
				value = `\u0061` + secret[1:]
			}
			// Inject a real JSON-escaped reflection, not a string containing a
			// literal backslash; both decoded and raw forms must be refused.
			wire = append([]byte(`{"reflection":"`+value+`",`), wire[1:]...)
			source := nativeLiveTestSource(t, "external-env", "api-key", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(wire)
			}))
			got, err := source.Fetch(context.Background(), f.begin(t))
			if got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) || strings.Contains(err.Error(), secret) {
				t.Fatal("reflected credential escaped constant refusal")
			}
		}
	})
	for _, failure := range []string{"duplicate-json", "body-alias", "conflicting-id", "map-id", "duplicate-admit", "two-event-fences", "two-archive-fences", "offload", "wrong-digest", "red-attestation", "revoked-tagged-attested", "mixed-signed-shape", "cap-hit", "unsupported-wrapper", "root-null", "invalid-utf8", "critical-alias"} {
		t.Run("wire-"+failure, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			items := nativeLiveTestItems(t, f)
			first := map[string]any{}
			for k, v := range items[0].(map[string]any) {
				first[k] = v
			}
			items[0] = first
			wire := []byte(nil)
			switch failure {
			case "body-alias":
				first["body"] = first["transcript"]
			case "conflicting-id":
				first["id"] = "different"
			case "map-id":
				first["id"], first["doc_id"] = map[string]any{}, map[string]any{}
			case "duplicate-admit":
				items = append(items, first)
			case "two-event-fences":
				first["transcript"] = first["transcript"].(string) + "```json\n{}\n```\n"
			case "two-archive-fences":
				first["transcript"] = first["transcript"].(string) + "```skb-base64\neA==\n```\n"
			case "offload":
				first["transcript"] = strings.ReplaceAll(first["transcript"].(string), "```skb-base64", "```unsupported-offload")
			case "wrong-digest":
				first["transcript"] = strings.ReplaceAll(first["transcript"].(string), f.agent.staged.Digest, "sha256:"+strings.Repeat("0", 64))
			case "red-attestation":
				red := signedAttest(t, f.agent.signerKeys[0], f.agent.roots.Signers[0].ReviewerID, f.agent.staged.Digest, " RED ", f.now.Add(-2*time.Minute).Format(time.RFC3339), nil)
				witnesses := append(append([]map[string]any(nil), f.agent.attest...), red)
				context := &AttestationContext{AdmitEvent: f.agent.staged.Attestation.AdmitEvent, GovernanceAttestation: f.agent.attest[0], GovernanceAttestations: witnesses}
				if err := verifyAgentContext(f.journal.selection.artifactRoots, context, f.agent.staged.Digest, f.agent.name, "1.0.0", f.now); err != nil {
					t.Fatal("red counterweight must retain genuine latest-green quorum", err)
				}
				raw, err := json.Marshal(red)
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, map[string]any{"id": "older-red", "transcript": "```json\n" + string(raw) + "\n```\n"})
			case "revoked-tagged-attested":
				revoked, err := BuildBundleRevokedEvent(RevokedEventInput{BundleDigest: f.agent.staged.Digest, ReasonCode: "author_request", RevokedBy: "fixture", OccurredAt: f.now})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = SignEnvelopeSignature(f.agent.registryKey, revoked); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(revoked)
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, map[string]any{"id": "retagged-revoke", "tags": "skill-event:attested", "transcript": "```json\n" + string(raw) + "\n```\n"})
			case "mixed-signed-shape":
				body := first["transcript"].(string)
				old, err := nativeLiveFence(body, "json")
				if err != nil {
					t.Fatal(err)
				}
				var event map[string]any
				if err = json.Unmarshal([]byte(old), &event); err != nil {
					t.Fatal(err)
				}
				event["reviewer_id"], event["governance_level"] = "fixture", "green"
				if _, err = SignEnvelopeSignature(f.agent.registryKey, event); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				first["transcript"] = strings.Replace(body, old, string(raw), 1)
			case "cap-hit":
				for len(items) < 500 {
					items = append(items, map[string]any{"id": "ordinary", "transcript": "ordinary memory"})
				}
			case "unsupported-wrapper":
				wire = []byte(`{"results":[]}`)
			case "root-null":
				wire = []byte(`null`)
			case "invalid-utf8":
				wire = []byte{'[', '"', 0xff, '"', ']'}
			case "duplicate-json":
				wire = []byte(`{"items":[],"items":[]}`)
			case "critical-alias":
				first["Transcript"] = first["transcript"]
			}
			if wire == nil {
				wire = nativeLiveTestWire(t, items)
			}
			source := nativeLiveTestSource(t, "none", "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(wire)
			}))
			if got, err := source.Fetch(context.Background(), f.begin(t)); got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("malformed wire supplied candidate", err)
			}
		})
	}
	for _, failure := range []string{"redirect", "duplicate-media", "duplicate-encoding", "encoding", "oversize-length", "header-limit", "truncated-body", "close", "late-cancel"} {
		t.Run("response-"+failure, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			wire := nativeLiveTestWire(t, nativeLiveTestItems(t, f))
			var redirected atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
			t.Cleanup(other.Close)
			source := nativeLiveTestSource(t, "none", "", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch failure {
				case "redirect":
					w.Header().Set("Location", other.URL)
					w.WriteHeader(302)
				case "duplicate-media":
					w.Header().Add("Content-Type", "application/json")
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "duplicate-encoding":
					w.Header()["Content-Encoding"] = []string{"identity", "identity"}
				case "oversize-length":
					w.Header().Set("Content-Length", "33554433")
				case "header-limit":
					w.Header().Set("X-Large", strings.Repeat("h", 17<<10))
				case "truncated-body":
					w.Header().Set("Content-Length", strconv.Itoa(len(wire)+1))
				}
				_, _ = w.Write(wire)
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fault := errors.New("synthetic hidden Close detail")
			closed := false
			source.closeBody = func(body io.ReadCloser) error {
				closed = true
				err := body.Close()
				if failure == "close" {
					return errors.Join(err, fault)
				}
				if failure == "late-cancel" {
					cancel()
				}
				return err
			}
			got, err := source.Fetch(ctx, f.begin(t))
			if got != nil || err == nil || (!closed && failure != "header-limit") || redirected.Load() != 0 || strings.Contains(err.Error(), "hidden") {
				t.Fatal("response/Close failure supplied candidate", err)
			}
			want := ErrNativeEvidenceInvalid
			if failure == "redirect" || failure == "close" || failure == "late-cancel" || failure == "header-limit" || failure == "truncated-body" {
				want = ErrNativeLiveSourceIO
			}
			if !errors.Is(err, want) || (failure == "close" && !errors.Is(err, fault)) || (failure == "late-cancel" && !errors.Is(err, context.Canceled)) {
				t.Fatal("response typed error lost", err)
			}
		})
	}
	t.Run("metadata-and-allocation-bounds", func(t *testing.T) {
		valid := NativeLiveAgentSourceOptions{BaseURL: "https://source.invalid/prefix", ContextID: "tenant___ctx", AuthMode: "none", TLSMode: "system"}
		for _, failure := range []string{"http", "userinfo", "dots", "separator", "context", "native", "none-family", "origin", "implicit-port", "tls", "system-ca", "origin-overcap", "base-overcap", "context-overcap", "mode-overcap", "family-overcap", "tls-overcap", "CA-overcap"} {
			o := valid
			switch failure {
			case "http":
				o.BaseURL = "http://127.0.0.1"
			case "userinfo":
				o.BaseURL = "https://user@source.invalid"
			case "dots":
				o.BaseURL = "https://source.invalid/a/../"
			case "separator":
				o.BaseURL = "https://source.invalid/%2f"
			case "context":
				o.ContextID = "../ctx"
			case "native":
				o.AuthMode = "native-device"
			case "none-family":
				o.AuthFamily = "bearer"
			case "origin":
				o.AuthMode, o.AuthFamily, o.AuthOrigin = "external-env", "bearer", "https://foreign.invalid:443"
			case "implicit-port":
				o.AuthMode, o.AuthFamily, o.AuthOrigin = "external-env", "bearer", "https://source.invalid"
			case "tls":
				o.TLSMode = "insecure"
			case "system-ca":
				o.CAPEM = []byte("not-selected")
			case "origin-overcap":
				o.AuthMode, o.AuthFamily, o.AuthOrigin = "external-env", "bearer", strings.Repeat("a", 8193)
			case "base-overcap":
				o.BaseURL = strings.Repeat("a", 8193)
			case "context-overcap":
				o.ContextID = strings.Repeat("a", 8193)
			case "mode-overcap":
				o.AuthMode = strings.Repeat("a", 65)
			case "family-overcap":
				o.AuthFamily = strings.Repeat("a", 65)
			case "tls-overcap":
				o.TLSMode = strings.Repeat("a", 65)
			case "CA-overcap":
				o.TLSMode, o.CAPEM = "pinned-pem", bytes.Repeat([]byte("x"), nativeEvidenceCAMax+1)
			}
			if got, err := NewNativeLiveAgentSource(o); got != nil || !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("invalid source metadata accepted", failure, err)
			}
		}
		a, err := NewNativeLiveAgentSource(valid)
		if err != nil {
			t.Fatal(err)
		}
		valid.ContextID = "other"
		b, err := NewNativeLiveAgentSource(valid)
		if err != nil || a.bindingID() == b.bindingID() || !nativeSHA(a.bindingID()) {
			t.Fatal("source consent binding missing", err)
		}
		budget := &nativeLiveWork{bytes: nativeLiveWorkMax}
		if _, err = nativeLiveJSON([]byte(`{}`), 2, "", budget); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("budget exhausted after allocation")
		}
		for _, raw := range []string{strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129), `{"tenantScope":null}`, `{"x":1,"x":2}`} {
			if _, err = nativeLiveJSON([]byte(raw), len(raw), "", &nativeLiveWork{}); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("strict JSON budget/alias accepted")
			}
		}
	})
}
