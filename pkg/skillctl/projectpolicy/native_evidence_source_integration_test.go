package projectpolicy

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
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

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type qaEvidenceFixture struct {
	project, home, path string
	doc                 map[string]any
	refs                []string
	revocation          ed25519.PrivateKey
	artifact            ed25519.PrivateKey
	reviewer            ed25519.PrivateKey
	server              *httptest.Server
	requests            atomic.Int32
	mu                  sync.Mutex
	response            []byte
	hook                func()
}

func qaEvidenceBytes(t *testing.T, key ed25519.PrivateKey, epoch int, issued time.Time, set, emergency []string, modify func(map[string]any)) []byte {
	t.Helper()
	head, err := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: epoch, IssuedAt: issued, Digests: set, Emergency: emergency})
	if err != nil {
		t.Fatal(err)
	}
	if modify != nil {
		modify(head)
	}
	if _, err = registry.SignEnvelopeSignature(key, head); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": set})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func qaEvidenceTLS(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local evidence fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Evidence endpoint"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}}, NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func qaNewEvidenceFixture(t *testing.T) *qaEvidenceFixture {
	t.Helper()
	f := &qaEvidenceFixture{project: t.TempDir(), home: t.TempDir()}
	var err error
	f.project, err = filepath.EvalSymlinks(f.project)
	if err != nil {
		t.Fatal(err)
	}
	f.home, err = filepath.EvalSymlinks(f.home)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home)
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return p, k
	}
	artifactPub, artifactKey := key()
	revocationPub, revocationKey := key()
	reviewerPub, reviewerKey := key()
	f.artifact = artifactKey
	f.revocation = revocationKey
	f.reviewer = reviewerKey
	f.server, _ = qaEvidenceTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.RequestURI() != "/selected/full-evidence" || r.Method != http.MethodGet || r.ProtoMajor != 1 || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("source request changed exact endpoint/protocol or supplied credentials")
		}
		f.mu.Lock()
		hook := f.hook
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		f.mu.Lock()
		raw := append([]byte(nil), f.response...)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if _, e := w.Write(raw); e != nil {
			t.Error(e)
		}
	}))
	// Recover the exact CA certificate from the fixture's transmitted chain.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.TLS.Certificates[0].Certificate[1]})
	ref := func(name string, raw []byte) map[string]string {
		path := filepath.Join(f.project, name)
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		f.refs = append(f.refs, path)
		return map[string]string{"path": path, "sha256": hex.EncodeToString(sum[:])}
	}
	roots := func(pub ed25519.PublicKey) []byte {
		return []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\ngovernance_quorum: 1\nsigners:\n - reviewer_id: independent-reviewer\n   pubkey_b64: " + base64.StdEncoding.EncodeToString(reviewerPub) + "\n")
	}
	f.path = filepath.Join(f.project, "source-profile.json")
	f.doc = map[string]any{"schema": "m3c.enterprise-project-profile/v3", "project_root": f.project, "artifact_home": f.home, "runtime": ref("runtime.json", []byte(`{"schema":"m3c.skillctl.runtime-profile/v1","project_root":`+fmt.Sprintf("%q", f.project)+`,"tools":[]}`)), "native": map[string]any{"logical_registry": "self", "authority_scope": "key-and-tenant", "tenant_scope": nil, "artifact_trust": ref("artifact.yaml", roots(artifactPub)), "revocation_trust": ref("revocation.yaml", roots(revocationPub)), "revocation_policy": map[string]any{"minimum_epoch": 1, "max_age_seconds": 86400}, "carrier": map[string]any{"kind": "git", "locator": "github://example.invalid/owner/repository"}, "revocation_source": map[string]any{"kind": "https-native-evidence", "url": f.server.URL + "/selected/full-evidence", "auth": "none", "tls": map[string]any{"mode": "pinned-pem", "ca": ref("source-ca.pem", caPEM)}}}}
	f.setResponse(qaEvidenceBytes(t, f.revocation, 2, time.Now().UTC(), []string{}, []string{}, nil))
	return f
}
func (f *qaEvidenceFixture) setResponse(raw []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.response = append([]byte(nil), raw...)
}
func (f *qaEvidenceFixture) load(t *testing.T) *NativePolicy {
	t.Helper()
	raw, e := json.Marshal(f.doc)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(f.path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	p, e := LoadNativePinned(f.path, hex.EncodeToString(sum[:]), f.project, f.home)
	if e != nil {
		t.Fatalf("genuine signed-source profile invalid: %v", e)
	}
	return p
}
func qaEvidenceJournal(t *testing.T, p *NativePolicy) *registry.NativeJournal {
	t.Helper()
	s, e := p.OfflineInstallSelection()
	if e != nil {
		t.Fatal(e)
	}
	j, e := registry.OpenNativeJournal(s)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func qaEvidenceInventory(t *testing.T, root string, excludeJournal bool) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if excludeJournal && rel == filepath.Join(".claude", "native-mutation-state") {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			out[rel] = "directory"
		} else {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			h := sha256.Sum256(b)
			out[rel] = hex.EncodeToString(h[:])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNativeEvidenceProfileSourceBinding(t *testing.T) {
	t.Run("retained-source-roots-and-CA-after-path-deletion", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		p := f.load(t)
		j := qaEvidenceJournal(t, p)
		if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 1, time.Now().UTC().Add(-time.Minute), []string{}, []string{}, nil)); e != nil {
			t.Fatal(e)
		}
		for _, path := range append(append([]string{}, f.refs...), f.path) {
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
		}
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		t.Setenv("ER1_API_URL", "https://foreign.invalid")
		t.Setenv("SKILLCTL_ENTERPRISE_PROFILE", "/foreign/profile.json")
		before := qaEvidenceInventory(t, f.home, true)
		status, e := p.AdoptFromSource(context.Background())
		if e != nil || status.Epoch != 2 || status.HistoryAuthorityID != p.HistoryAuthorityID() {
			t.Fatalf("retained authority/source TLS failed: %#v %v", status, e)
		}
		if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.home, true)) {
			t.Fatal("source update changed artifact inventory")
		}
		reopened, e := qaEvidenceJournal(t, p).Status(context.Background())
		if e != nil || reopened != status {
			t.Fatal("updated status did not survive reopening", e)
		}
		if f.requests.Load() != 1 {
			t.Fatal("retained source request count", f.requests.Load())
		}
	})
	t.Run("source-selection-changes-not-history-authority", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		p := f.load(t)
		source := f.doc["native"].(map[string]any)["revocation_source"].(map[string]any)
		source["url"] = f.server.URL + "/other-source"
		q := f.load(t)
		if p.SelectionID() == q.SelectionID() || p.ProfileDigest() == q.ProfileDigest() || p.HistoryAuthorityID() != q.HistoryAuthorityID() {
			t.Fatal("source metadata not bound independently of history")
		}
		if f.requests.Load() != 0 {
			t.Fatal("source constructor connected")
		}
	})
	t.Run("native-v2-remains-offline-no-source-fallback", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		delete(f.doc["native"].(map[string]any), "revocation_source")
		f.doc["schema"] = NativeSchema
		p := f.load(t)
		if _, e := p.AdoptFromSource(context.Background()); !errors.Is(e, ErrUnsupported) {
			t.Fatal("offline v2 source operation not refused", e)
		}
		if f.requests.Load() != 0 {
			t.Fatal("v2 invented endpoint")
		}
	})
	t.Run("TLS-mode-binds-selection-not-history", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		p := f.load(t)
		source := f.doc["native"].(map[string]any)["revocation_source"].(map[string]any)
		source["tls"] = map[string]any{"mode": "system"}
		q := f.load(t)
		if p.ProfileDigest() == q.ProfileDigest() || p.SelectionID() == q.SelectionID() || p.HistoryAuthorityID() != q.HistoryAuthorityID() {
			t.Fatal("TLS configuration not bound independently of history")
		}
		if f.requests.Load() != 0 {
			t.Fatal("system trust selection connected")
		}
	})
	t.Run("full-advertised-revoked-and-emergency-bounds", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		p := f.load(t)
		j := qaEvidenceJournal(t, p)
		if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 1, time.Now().UTC().Add(-time.Minute), []string{}, []string{}, nil)); e != nil {
			t.Fatal(e)
		}
		set := make([]string, 8192)
		for i := range set {
			set[i] = fmt.Sprintf("sha256:%064x", i)
		}
		raw := qaEvidenceBytes(t, f.revocation, 2, time.Now().UTC(), set, append([]string{}, set[:512]...), nil)
		if len(raw) > 1<<20 {
			t.Fatal("bounded fixture exceeds envelope cap")
		}
		f.setResponse(raw)
		status, e := p.AdoptFromSource(context.Background())
		if e != nil || status.Epoch != 2 {
			t.Fatal("advertised signed fullset bounds rejected", e)
		}
		h := sha256.Sum256(raw)
		if status.EvidenceDigest != hex.EncodeToString(h[:]) {
			t.Fatal("adopted evidence is not the exact source bytes")
		}
	})
}

func TestNativeEvidenceExplicitAdopt(t *testing.T) {
	t.Run("authentic-stale-history-refresh", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		f.doc["native"].(map[string]any)["revocation_policy"].(map[string]any)["max_age_seconds"] = 1
		p := f.load(t)
		j := qaEvidenceJournal(t, p)
		issued := time.Now().UTC()
		if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 1, issued, []string{}, []string{}, nil)); e != nil {
			t.Fatal(e)
		}
		time.Sleep(time.Until(issued.Add(1100 * time.Millisecond)))
		if _, e := j.BeginOfflineInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(e, registry.ErrNativeHistoryStale) {
			t.Fatal("old authenticated state must actually be stale", e)
		}
		f.mu.Lock()
		f.hook = func() {
			f.setResponse(qaEvidenceBytes(t, f.revocation, 2, time.Now().UTC(), []string{}, []string{}, nil))
		}
		f.mu.Unlock()
		// Supply fresh proof before the request; the earlier fixed response is older
		// than this deliberately short policy after waiting for genuine staleness.
		f.setResponse(qaEvidenceBytes(t, f.revocation, 2, time.Now().UTC(), []string{}, []string{}, nil))
		before := qaEvidenceInventory(t, f.home, true)
		status, e := p.AdoptFromSource(context.Background())
		if e != nil || status.Epoch != 2 || status.LastSeen.Before(issued) {
			t.Fatal("explicit refresh did not recover stale history", e)
		}
		if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.home, true)) {
			t.Fatal("refresh touched artifacts")
		}
	})
	t.Run("same-epoch-canonical-refresh", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		p := f.load(t)
		j := qaEvidenceJournal(t, p)
		set := []string{"sha256:" + strings.Repeat("7", 64)}
		if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 7, time.Now().UTC().Add(-time.Minute), set, []string{}, nil)); e != nil {
			t.Fatal(e)
		}
		f.setResponse(qaEvidenceBytes(t, f.revocation, 7, time.Now().UTC(), set, []string{}, nil))
		status, e := p.AdoptFromSource(context.Background())
		if e != nil || status.Epoch != 7 {
			t.Fatal("same epoch unchanged canonical set refresh failed", e)
		}
	})
	for _, name := range []string{"missing", "corrupt"} {
		t.Run(name+"-history-before-fetch", func(t *testing.T) {
			f := qaNewEvidenceFixture(t)
			p := f.load(t)
			j := qaEvidenceJournal(t, p)
			if name == "corrupt" {
				if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 1, time.Now().UTC(), []string{}, []string{}, nil)); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(f.home, ".claude", "native-mutation-state", p.HistoryAuthorityID(), "state.record")
				if e := os.WriteFile(path, []byte("invalid retained history"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := qaEvidenceInventory(t, f.home, false)
			_, e := p.AdoptFromSource(context.Background())
			want := registry.ErrNativeHistoryRequired
			if name == "corrupt" {
				want = registry.ErrNativeHistoryInvalid
			}
			if !errors.Is(e, want) {
				t.Fatal("wrong preflight refusal", e)
			}
			if f.requests.Load() != 0 || !reflect.DeepEqual(before, qaEvidenceInventory(t, f.home, false)) {
				t.Fatal("preflight fetched or rewrote unavailable history")
			}
		})
	}
	for _, name := range []string{"wrong-role-key", "foreign-tenant", "same-count-substitution", "lower-epoch", "same-epoch-changed-set", "future", "stale"} {
		t.Run(name, func(t *testing.T) {
			f := qaNewEvidenceFixture(t)
			p := f.load(t)
			j := qaEvidenceJournal(t, p)
			set := []string{"sha256:" + strings.Repeat("1", 64)}
			issued := time.Now().UTC().Add(-time.Minute)
			if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 7, issued, set, []string{}, nil)); e != nil {
				t.Fatal(e)
			}
			key := f.revocation
			epoch := 8
			at := time.Now().UTC()
			candidateSet := append([]string{}, set...)
			var modify func(map[string]any)
			want := registry.ErrNativeEvidenceInvalid
			switch name {
			case "wrong-role-key":
				key = f.artifact
			case "foreign-tenant":
				modify = func(h map[string]any) { h["tenant_scope"] = "foreign" }
			case "same-count-substitution":
				candidateSet = []string{"sha256:" + strings.Repeat("2", 64)}
			case "lower-epoch":
				epoch = 6
				want = registry.ErrNativeHistoryStale
			case "same-epoch-changed-set":
				epoch = 7
				candidateSet = []string{"sha256:" + strings.Repeat("2", 64)}
				want = registry.ErrNativeHistoryStale
			case "future":
				at = at.Add(time.Hour)
				want = registry.ErrNativeHistoryStale
			case "stale":
				at = at.Add(-25 * time.Hour)
				want = registry.ErrNativeHistoryStale
			}
			raw := qaEvidenceBytes(t, key, epoch, at, candidateSet, []string{}, modify)
			if name == "same-count-substitution" {
				var env map[string]any
				if e := json.Unmarshal(raw, &env); e != nil {
					t.Fatal(e)
				}
				env["revoked_digests"] = set
				var e error
				raw, e = json.Marshal(env)
				if e != nil {
					t.Fatal(e)
				}
			}
			f.setResponse(raw)
			before := qaEvidenceInventory(t, f.home, false)
			status, e := p.AdoptFromSource(context.Background())
			if !errors.Is(e, want) || status.Epoch != 0 {
				t.Fatalf("%s accepted invalid proof or wrong classification: %#v %v", name, status, e)
			}
			if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.home, false)) {
				t.Fatal("invalid proof changed retained history")
			}
		})
	}
	t.Run("concurrent-update-rechecked-under-adopt-lock", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		p := f.load(t)
		j := qaEvidenceJournal(t, p)
		if _, e := j.Enroll(context.Background(), qaEvidenceBytes(t, f.revocation, 1, time.Now().UTC().Add(-time.Minute), []string{}, []string{}, nil)); e != nil {
			t.Fatal(e)
		}
		var once sync.Once
		f.mu.Lock()
		f.hook = func() {
			once.Do(func() {
				if _, e := j.Adopt(context.Background(), qaEvidenceBytes(t, f.revocation, 9, time.Now().UTC(), []string{}, []string{}, nil)); e != nil {
					t.Error("competing adopt failed", e)
				}
			})
		}
		f.mu.Unlock()
		status, e := p.AdoptFromSource(context.Background())
		if !errors.Is(e, registry.ErrNativeHistoryStale) || status.Epoch != 0 {
			t.Fatal("candidate overwrote newer concurrent floor", e)
		}
		s, e := j.Status(context.Background())
		if e != nil || s.Epoch != 9 {
			t.Fatal("competing floor not retained", e)
		}
	})
}
