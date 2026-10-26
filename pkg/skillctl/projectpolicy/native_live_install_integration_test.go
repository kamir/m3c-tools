package projectpolicy

import (
	"archive/tar"
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
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type c33LiveFixture struct {
	base              *qaEvidenceFixture
	server            *httptest.Server
	caPath            string
	archive, markdown []byte
	digest            string
	admit             map[string]any
	attest            []map[string]any
	reviewers         []ed25519.PrivateKey
	mu                sync.Mutex
	rows              []map[string]any
	status            int
	location          string
	family, secret    string
	requests          atomic.Int32
	issued            time.Time
}

func c33LiveRandom(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func c33LiveArchive(t *testing.T, fields map[string]any) ([]byte, []byte) {
	t.Helper()
	manifest := map[string]any{"schema": "m3c-skill-bundle/v2", "kind": "agent", "name": "live-agent", "version": "1.0.0", "depends_on": []any{}}
	for k, v := range fields {
		manifest[k] = v
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	md := []byte("---\nname: live-agent\n---\n\nGenuine retained live agent fixture.\n")
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"bundle.json", raw}, {"live-agent.md", md}} {
		if err = tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), md
}
func c33LiveRows(t *testing.T, f *c33LiveFixture) []map[string]any {
	t.Helper()
	events := append([]map[string]any{f.admit}, f.attest...)
	rows := make([]map[string]any, 0, len(events))
	for i, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		body := "```json\n" + string(raw) + "\n```\n"
		if i == 0 {
			body += "```skb-base64\n" + base64.StdEncoding.EncodeToString(f.archive) + "\n```\n"
		}
		rows = append(rows, map[string]any{"doc_id": fmt.Sprintf("live-doc-%d", i), "transcript": body, "tags": "unsigned-selector-only"})
	}
	return rows
}
func c33LiveNew(t *testing.T, fields map[string]any) *c33LiveFixture {
	t.Helper()
	f := &c33LiveFixture{base: qaNewEvidenceFixture(t), status: 200}
	f.archive, f.markdown = c33LiveArchive(t, fields)
	sum := sha256.Sum256(f.archive)
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	fp := sha256.Sum256(f.base.artifact.Public().(ed25519.PublicKey))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(f.base.artifact, sum[:]))
	var err error
	f.admit, err = registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{BundleDigest: f.digest, Name: "live-agent", Version: "1.0.0", AuthorIntent: "green", AdmittedByIdentity: "live-author", AdmittedAt: time.Now().UTC().Add(-time.Minute), Signatures: []registry.SignatureRef{{Role: "author", IdentityID: "live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}, {Role: "registry", IdentityID: "live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.SignEnvelopeSignature(f.base.artifact, f.admit); err != nil {
		t.Fatal(err)
	}
	roots := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(f.base.artifact.Public().(ed25519.PublicKey)) + "\ngovernance_minimum: green\ngovernance_quorum: 2\nsigners:\n"
	for _, id := range []string{"live-reviewer-a", "live-reviewer-b"} {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		f.reviewers = append(f.reviewers, key)
		roots += fmt.Sprintf(" - reviewer_id: %s\n   pubkey_b64: %s\n", id, base64.StdEncoding.EncodeToString(pub))
		event, e := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{BundleDigest: f.digest, ReviewerID: id, GovernanceLevel: "green", Rationale: "independent signed live fixture", OccurredAt: time.Now().UTC().Add(-time.Minute)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = registry.SignEnvelopeSignature(key, event); e != nil {
			t.Fatal(e)
		}
		f.attest = append(f.attest, event)
	}
	ref := f.base.doc["native"].(map[string]any)["artifact_trust"].(map[string]string)
	if err = os.WriteFile(ref["path"], []byte(roots), 0600); err != nil {
		t.Fatal(err)
	}
	rootsSHA := sha256.Sum256([]byte(roots))
	ref["sha256"] = hex.EncodeToString(rootsSHA[:])
	f.rows = c33LiveRows(t, f)
	f.server, _ = qaEvidenceTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		f.mu.Lock()
		rows := f.rows
		status := f.status
		location := f.location
		family, secret := f.family, f.secret
		f.mu.Unlock()
		wantBearer, wantKey := "", ""
		if family == "bearer" {
			wantBearer = "Bearer " + secret
		}
		if family == "api-key" {
			wantKey = secret
		}
		if r.Method != "GET" || r.ProtoMajor != 1 || r.URL.EscapedPath() != "/tenant/base/memory/qa___agents" || r.URL.Query().Get("limit") != "500" || r.URL.Query().Get("range") != "year" || len(r.URL.Query()) != 2 || r.Header.Get("Authorization") != wantBearer || r.Header.Get("X-API-Key") != wantKey || r.Header.Get("Cookie") != "" {
			t.Error("live carrier changed endpoint/protocol or authentication family")
		}
		w.Header().Set("Content-Type", "application/json")
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]any{"items": rows}); err != nil {
			t.Error(err)
		}
	}))
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.TLS.Certificates[0].Certificate[1]})
	f.caPath = filepath.Join(f.base.project, "carrier-ca.pem")
	if err = os.WriteFile(f.caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	caSHA := sha256.Sum256(ca)
	f.base.refs = append(f.base.refs, f.caPath)
	f.base.doc["schema"] = "m3c.enterprise-project-profile/v4"
	f.base.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "er1", "base_url": f.server.URL + "/tenant/base", "context_id": "qa___agents", "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]string{"path": f.caPath, "sha256": hex.EncodeToString(caSHA[:])}}, "auth": map[string]any{"mode": "none"}}
	return f
}
func (f *c33LiveFixture) load(t *testing.T) *NativePolicy { return f.base.load(t) }
func (f *c33LiveFixture) enroll(t *testing.T, p *NativePolicy) *registry.NativeJournal {
	t.Helper()
	j := qaEvidenceJournal(t, p)
	f.issued = time.Now().UTC().Truncate(time.Second)
	if _, err := j.Enroll(context.Background(), qaEvidenceBytes(t, f.base.revocation, 1, f.issued, []string{}, []string{}, nil)); err != nil {
		t.Fatal(err)
	}
	return j
}
func c33LiveFrame(t *testing.T, f *c33LiveFixture) {
	t.Helper()
	path := filepath.Join(f.base.home, ".claude", "agents", ".skillctl-evidence", "live-agent.record")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 12 || string(raw[:8]) != "M3CAGT1\n" {
		t.Fatal("live record framing invalid")
	}
	n := int(binary.BigEndian.Uint32(raw[8:12]))
	if n < 1 || n > 8192 || 12+n > len(raw) {
		t.Fatal("live frame header cap")
	}
	var header map[string]any
	if err = json.Unmarshal(raw[12:12+n], &header); err != nil {
		t.Fatal(err)
	}
	start := 12 + n
	archiveSize := int(header["archive_bytes"].(float64))
	contextSize := int(header["context_bytes"].(float64))
	if start+archiveSize+contextSize != len(raw) || !bytes.Equal(raw[start:start+archiveSize], f.archive) || header["bundle_digest"] != f.digest {
		t.Fatal("live publication lost original archive/digest")
	}
	contextRaw := raw[start+archiveSize:]
	contextSHA := sha256.Sum256(contextRaw)
	if header["context_sha256"] != hex.EncodeToString(contextSHA[:]) {
		t.Fatal("live complete context hash not bound")
	}
	var retained registry.AttestationContext
	if err = json.Unmarshal(contextRaw, &retained); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(f.admit)
	got, _ := json.Marshal(retained.AdmitEvent)
	if !bytes.Equal(want, got) || len(retained.GovernanceAttestations) != 2 {
		t.Fatal("live record dropped admission or full quorum context")
	}
	for i, event := range retained.GovernanceAttestations {
		want, _ = json.Marshal(f.attest[i])
		got, _ = json.Marshal(event)
		if !bytes.Equal(want, got) {
			t.Fatal("retained reviewer event changed")
		}
	}
	md, err := os.ReadFile(filepath.Join(f.base.home, ".claude", "agents", "live-agent.md"))
	if err != nil || !bytes.Equal(md, f.markdown) {
		t.Fatal("published agent body changed", err)
	}
}
func c33LivePlan(t *testing.T, p *NativePolicy, digest string) (*registry.NativeLiveAgentSession, *registry.NativeInstallPlan) {
	t.Helper()
	s, err := p.BeginER1AgentInstall(context.Background(), digest)
	if err != nil {
		t.Fatal("genuine live Begin failed", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error("checked live cleanup", err)
		}
	})
	plan, err := s.Plan(context.Background())
	if err != nil {
		t.Fatal("genuine live Plan failed", err)
	}
	if len(plan.Rows) != 1 || plan.Rows[0].Digest != digest || plan.Rows[0].Kind != "agent" || len(plan.Token) != 43 {
		t.Fatal("plan did not bind exact agent/opaque consent")
	}
	return s, plan
}

func TestNativeLiveProfileBinding(t *testing.T) {
	for _, history := range []string{"missing", "stale"} {
		t.Run("history-precedes-invalid-selected-env-"+history, func(t *testing.T) {
			f := c33LiveNew(t, nil)
			f.base.doc["native"].(map[string]any)["carrier"].(map[string]any)["auth"] = map[string]any{"mode": "external-env", "family": "api-key", "origin": f.server.URL}
			if history == "stale" {
				f.base.doc["native"].(map[string]any)["revocation_policy"].(map[string]any)["max_age_seconds"] = 3
			}
			p := f.load(t)
			t.Setenv("ER1_API_KEY", "")
			expected := registry.ErrNativeHistoryRequired
			if history == "stale" {
				f.enroll(t, p)
				time.Sleep(time.Until(f.issued.Add(3100 * time.Millisecond)))
				expected = registry.ErrNativeHistoryStale
			}
			before := qaEvidenceInventory(t, f.base.home, true)
			if s, err := p.BeginER1AgentInstall(context.Background(), f.digest); s != nil || !errors.Is(err, expected) || errors.Is(err, registry.ErrNativeLiveSourceIO) {
				t.Fatal("selected credential failure displaced prior authenticated history denial", err)
			}
			if f.requests.Load() != 0 || !reflect.DeepEqual(before, qaEvidenceInventory(t, f.base.home, true)) {
				t.Fatal("missing/stale history contacted carrier or published artifacts")
			}
		})
	}
	t.Run("retained-pinned-role-carrier-and-source-selection", func(t *testing.T) {
		f := c33LiveNew(t, nil)
		p := f.load(t)
		f.enroll(t, p)
		before := qaEvidenceInventory(t, f.base.home, true)
		for _, path := range append(append([]string(nil), f.base.refs...), f.base.path) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("ER1_API_URL", "https://foreign.invalid")
		t.Setenv("ER1_API_KEY", c33LiveRandom(t))
		t.Setenv("ER1_DEVICE_TOKEN", c33LiveRandom(t))
		s, plan := c33LivePlan(t, p, f.digest)
		if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.base.home, true)) {
			t.Fatal("live acquisition/plan published active artifacts")
		}
		if _, err := s.Confirm(context.Background(), plan.Token); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		c33LiveFrame(t, f)
		if f.requests.Load() != 1 || f.base.requests.Load() != 0 {
			t.Fatal("live install fetched unexpected source or reread carrier")
		}
		if !errors.Is(artifact.RejectNativeEnterpriseMutation(p.Intent()), artifact.ErrNativeMutationUnavailable) {
			t.Fatal("v4 profile granted legacy native mutation")
		}
	})
	t.Run("carrier-choice-changes-consent-not-history", func(t *testing.T) {
		f := c33LiveNew(t, nil)
		first := f.load(t)
		f.base.doc["native"].(map[string]any)["carrier"].(map[string]any)["context_id"] = "other-explicit-context"
		second := f.load(t)
		if first.SelectionID() == second.SelectionID() || first.ProfileDigest() == second.ProfileDigest() || first.HistoryAuthorityID() != second.HistoryAuthorityID() || f.requests.Load() != 0 {
			t.Fatal("carrier selection did not separate consent from history")
		}
	})
	for _, version := range []string{NativeSchema, NativeEvidenceSchema} {
		t.Run("offline-schema-"+version, func(t *testing.T) {
			f := qaNewEvidenceFixture(t)
			if version == NativeSchema {
				f.doc["schema"] = NativeSchema
				delete(f.doc["native"].(map[string]any), "revocation_source")
			}
			p := f.load(t)
			if s, err := p.BeginER1AgentInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); s != nil || !errors.Is(err, ErrUnsupported) || f.requests.Load() != 0 {
				t.Fatal("offline schema acquired live carrier", err)
			}
		})
	}
	for _, invalid := range []string{"foreign-origin", "http", "native-device", "tls-insecure", "auth-none-family", "extra-key"} {
		t.Run("strict-"+invalid, func(t *testing.T) {
			f := c33LiveNew(t, nil)
			c := f.base.doc["native"].(map[string]any)["carrier"].(map[string]any)
			switch invalid {
			case "foreign-origin":
				c["auth"] = map[string]any{"mode": "external-env", "family": "api-key", "origin": "https://foreign.invalid:443"}
			case "http":
				c["base_url"] = "http://127.0.0.1/tenant/base"
			case "native-device":
				c["auth"] = map[string]any{"mode": "native-device"}
			case "tls-insecure":
				c["tls"] = map[string]any{"mode": "insecure"}
			case "auth-none-family":
				c["auth"] = map[string]any{"mode": "none", "family": "api-key"}
			case "extra-key":
				c["Base_URL"] = c["base_url"]
			}
			raw, err := json.Marshal(f.base.doc)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.base.path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			p, err := LoadNativePinned(f.base.path, hex.EncodeToString(sum[:]), f.base.project, f.base.home)
			if p != nil || (!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrUnsupported)) || f.requests.Load() != 0 {
				t.Fatal("strict profile silently selected live source", err)
			}
		})
	}
}

func TestNativeLiveAgentAcquisition(t *testing.T) {
	for _, invalid := range []string{"empty", "CRLF", "leading-space"} {
		t.Run("selected-external-value-"+invalid, func(t *testing.T) {
			f := c33LiveNew(t, nil)
			f.base.doc["native"].(map[string]any)["carrier"].(map[string]any)["auth"] = map[string]any{"mode": "external-env", "family": "api-key", "origin": f.server.URL}
			p := f.load(t)
			f.enroll(t, p)
			value := ""
			switch invalid {
			case "CRLF":
				value = c33LiveRandom(t) + "\r\n"
			case "leading-space":
				value = " " + c33LiveRandom(t)
			}
			t.Setenv("ER1_API_KEY", value)
			t.Setenv("ER1_DEVICE_TOKEN", c33LiveRandom(t))
			if s, err := p.BeginER1AgentInstall(context.Background(), f.digest); s != nil || !errors.Is(err, registry.ErrNativeLiveSourceIO) || f.requests.Load() != 0 {
				t.Fatal("invalid selected external value fell back or reached wire", err)
			}
		})
	}
	for _, family := range []string{"none", "api-key", "bearer"} {
		t.Run("genuine-signed-TLS-"+family, func(t *testing.T) {
			f := c33LiveNew(t, nil)
			if family != "none" {
				secret := make([]byte, 32)
				if _, err := rand.Read(secret); err != nil {
					t.Fatal(err)
				}
				f.family, f.secret = family, hex.EncodeToString(secret)
				key := "ER1_API_KEY"
				if family == "bearer" {
					key = "ER1_DEVICE_TOKEN"
				}
				t.Setenv(key, f.secret)
				f.base.doc["native"].(map[string]any)["carrier"].(map[string]any)["auth"] = map[string]any{"mode": "external-env", "family": family, "origin": f.server.URL}
			}
			p := f.load(t)
			f.enroll(t, p)
			s, plan := c33LivePlan(t, p, f.digest)
			t.Setenv("ER1_API_KEY", c33LiveRandom(t))
			t.Setenv("ER1_DEVICE_TOKEN", c33LiveRandom(t))
			f.mu.Lock()
			f.rows = nil
			f.mu.Unlock()
			if _, err := s.Confirm(context.Background(), plan.Token); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			c33LiveFrame(t, f)
			if f.requests.Load() != 1 {
				t.Fatal("confirmation fetched a new unreviewed snapshot")
			}
		})
	}
	for _, mode := range []string{"missing-history", "revoked-root", "missing-quorum", "forged-admit", "foreign-tenant", "dependencies", "manifest-alias", "ambiguous-root", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			fields := map[string]any{}
			if mode == "dependencies" {
				fields["depends_on"] = []any{map[string]any{"kind": "skill", "name": "missing", "version": "1"}}
			}
			if mode == "manifest-alias" {
				fields["Name"] = "alias"
			}
			f := c33LiveNew(t, fields)
			p := f.load(t)
			if mode != "missing-history" {
				j := qaEvidenceJournal(t, p)
				set := []string{}
				if mode == "revoked-root" {
					set = []string{f.digest}
				}
				if _, err := j.Enroll(context.Background(), qaEvidenceBytes(t, f.base.revocation, 1, time.Now().UTC(), set, []string{}, nil)); err != nil {
					t.Fatal(err)
				}
			}
			f.mu.Lock()
			switch mode {
			case "missing-quorum":
				f.attest = f.attest[:1]
				f.rows = c33LiveRows(t, f)
			case "forged-admit":
				f.admit["name"] = "forged-after-signature"
				f.rows = c33LiveRows(t, f)
			case "foreign-tenant":
				f.admit["tenant_scope"] = "foreign"
				if _, err := registry.SignEnvelopeSignature(f.base.artifact, f.admit); err != nil {
					t.Fatal(err)
				}
				f.rows = c33LiveRows(t, f)
			case "ambiguous-root":
				row := map[string]any{}
				for k, v := range f.rows[0] {
					row[k] = v
				}
				row["transcript"] = row["transcript"].(string) + "```json\n{}\n```\n"
				f.rows = append(f.rows, row)
			case "redirect":
				f.status = 302
				f.location = f.base.server.URL + "/unselected"
			}
			f.mu.Unlock()
			before := qaEvidenceInventory(t, f.base.home, true)
			s, err := p.BeginER1AgentInstall(context.Background(), f.digest)
			if s != nil {
				_, err = s.Plan(context.Background())
				if closeErr := s.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			expected := registry.ErrNativeEvidenceInvalid
			if mode == "missing-history" {
				expected = registry.ErrNativeHistoryRequired
			}
			if mode == "revoked-root" {
				expected = registry.ErrNativeSubjectRevoked
			}
			if mode == "dependencies" {
				expected = registry.ErrNativeDependenciesUnavailable
			}
			if mode == "manifest-alias" {
				expected = registry.ErrAgentEvidenceInvalid
			}
			if mode == "redirect" {
				expected = registry.ErrNativeLiveSourceIO
			}
			if !errors.Is(err, expected) {
				t.Fatalf("signed live negative %s did not deny exact cause: %v", mode, err)
			}
			if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.base.home, true)) || f.base.requests.Load() != 0 {
				t.Fatal("refused live acquisition published or followed source redirect")
			}
			if (mode == "missing-history" || mode == "revoked-root") && f.requests.Load() != 0 {
				t.Fatal("history/subject gate happened after carrier I/O")
			}
		})
	}
}

func TestNativeLiveInstallConsentBoundary(t *testing.T) {
	for _, mode := range []string{"wrong-token", "replan-old-token", "replay", "target-drift", "freshness-expires", "closed"} {
		t.Run(mode, func(t *testing.T) {
			f := c33LiveNew(t, nil)
			if mode == "freshness-expires" {
				f.base.doc["native"].(map[string]any)["revocation_policy"].(map[string]any)["max_age_seconds"] = 3
			}
			p := f.load(t)
			f.enroll(t, p)
			s, plan := c33LivePlan(t, p, f.digest)
			token := plan.Token
			before := qaEvidenceInventory(t, f.base.home, true)
			switch mode {
			case "wrong-token":
				token = strings.Repeat("A", 43)
			case "replan-old-token":
				if _, err := s.Plan(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			case "freshness-expires":
				if time.Until(f.issued.Add(3*time.Second)) < 500*time.Millisecond {
					t.Fatal("signed fixture reached Plan without sufficient freshness headroom")
				}
				time.Sleep(time.Until(f.issued.Add(3100 * time.Millisecond)))
			case "target-drift":
				dir := filepath.Join(f.base.home, ".claude", "agents")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "live-agent.md"), []byte("other actor content"), 0600); err != nil {
					t.Fatal(err)
				}
				before = qaEvidenceInventory(t, f.base.home, true)
			case "replay":
				if _, err := s.Confirm(context.Background(), token); err != nil {
					t.Fatal(err)
				}
				c33LiveFrame(t, f)
				before = qaEvidenceInventory(t, f.base.home, true)
			}
			results, err := s.Confirm(context.Background(), token)
			expected := registry.ErrNativeConsentInvalid
			if mode == "closed" || mode == "replay" {
				expected = registry.ErrNativeSessionUnavailable
			}
			if mode == "freshness-expires" {
				expected = registry.ErrNativeHistoryStale
			}
			if mode == "target-drift" {
				expected = registry.ErrPlanDrift
			}
			if !errors.Is(err, expected) || len(results) != 0 {
				t.Fatalf("consent %s returned wrong result/cause: %v", mode, err)
			}
			if mode == "wrong-token" {
				if again, retryErr := s.Confirm(context.Background(), plan.Token); len(again) != 0 || !errors.Is(retryErr, registry.ErrNativeConsentInvalid) {
					t.Fatal("failed confirmation did not consume original token", retryErr)
				}
			}
			if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.base.home, true)) {
				t.Fatal("refused consent changed active artifacts")
			}
		})
	}
}
