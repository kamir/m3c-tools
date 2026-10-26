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

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type qaNativeSkillLiveFixture struct {
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

func qaNativeSkillLiveArchive(t *testing.T, fields map[string]any) ([]byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	md := []byte("---\nname: live-skill\n---\n\nGenuine canonical native skill.\n")
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), md, 0600); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if err := os.Mkdir(filepath.Join(dir, "references"), 0700); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if err := os.WriteFile(filepath.Join(dir, "references", "inert.txt"), []byte("retained nested bytes\n"), 0600); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	var packed bytes.Buffer
	_, err := skillbundle.PackToWriter(dir, &packed, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: "live-skill", Version: "1.0.0", DependsOn: []skillbundle.Dependency{}}})
	if err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if len(fields) == 0 {
		return packed.Bytes(), md
	}
	entries, err := skillbundle.Unpack(packed.Bytes(), skillbundle.UnpackOptions{})
	if err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		raw := e.Content
		if e.Rel == "bundle.json" {
			var m map[string]any
			if err = json.Unmarshal(raw, &m); err != nil {
				t.Fatal(qaNativeSkillPolicyCauses(err))
			}
			for k, v := range fields {
				m[k] = v
			}
			raw, err = json.Marshal(m)
			if err != nil {
				t.Fatal(qaNativeSkillPolicyCauses(err))
			}
		}
		if err = tw.WriteHeader(&tar.Header{Name: e.Rel, Mode: 0644, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
		if _, err = tw.Write(raw); err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if err = gz.Close(); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	return out.Bytes(), md
}
func qaNativeSkillLiveRows(t *testing.T, f *qaNativeSkillLiveFixture) []map[string]any {
	t.Helper()
	events := append([]map[string]any{f.admit}, f.attest...)
	rows := make([]map[string]any, 0, len(events))
	for i, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
		body := "```json\n" + string(raw) + "\n```\n"
		if i == 0 {
			body += "```skb-base64\n" + base64.StdEncoding.EncodeToString(f.archive) + "\n```\n"
		}
		rows = append(rows, map[string]any{"doc_id": fmt.Sprintf("live-doc-%d", i), "transcript": body, "tags": "unsigned-selector-only"})
	}
	return rows
}
func qaNativeSkillLiveNew(t *testing.T, fields map[string]any) *qaNativeSkillLiveFixture {
	t.Helper()
	f := &qaNativeSkillLiveFixture{base: qaNewEvidenceFixture(t), status: 200}
	if err := os.MkdirAll(filepath.Join(f.base.home, ".claude", "skills"), 0700); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	f.archive, f.markdown = qaNativeSkillLiveArchive(t, fields)
	sum := sha256.Sum256(f.archive)
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	fp := sha256.Sum256(f.base.artifact.Public().(ed25519.PublicKey))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(f.base.artifact, sum[:]))
	var err error
	f.admit, err = registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{BundleDigest: f.digest, Name: "live-skill", Version: "1.0.0", AuthorIntent: "green", AdmittedByIdentity: "live-author", AdmittedAt: time.Now().UTC().Add(-time.Minute), Signatures: []registry.SignatureRef{{Role: "author", IdentityID: "live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}, {Role: "registry", IdentityID: "live-author", SignatureB64: sig, PubKeyFingerprint: "sha256:" + hex.EncodeToString(fp[:])}}})
	if err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if _, err = registry.SignEnvelopeSignature(f.base.artifact, f.admit); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
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
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	rootsSHA := sha256.Sum256([]byte(roots))
	ref["sha256"] = hex.EncodeToString(rootsSHA[:])
	f.rows = qaNativeSkillLiveRows(t, f)
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
		if r.Method != "GET" || r.ProtoMajor != 1 || r.URL.EscapedPath() != "/tenant/base/memory/qa___skills" || r.URL.Query().Get("limit") != "500" || r.URL.Query().Get("range") != "year" || len(r.URL.Query()) != 2 || r.Header.Get("Authorization") != wantBearer || r.Header.Get("X-API-Key") != wantKey || r.Header.Get("Cookie") != "" {
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
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	caSHA := sha256.Sum256(ca)
	f.base.refs = append(f.base.refs, f.caPath)
	f.base.doc["schema"] = "m3c.enterprise-project-profile/v4"
	f.base.doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "er1", "base_url": f.server.URL + "/tenant/base", "context_id": "qa___skills", "tls": map[string]any{"mode": "pinned-pem", "ca": map[string]string{"path": f.caPath, "sha256": hex.EncodeToString(caSHA[:])}}, "auth": map[string]any{"mode": "none"}}
	return f
}
func (f *qaNativeSkillLiveFixture) load(t *testing.T) *NativePolicy { return f.base.load(t) }
func (f *qaNativeSkillLiveFixture) enroll(t *testing.T, p *NativePolicy) *registry.NativeJournal {
	t.Helper()
	j := qaEvidenceJournal(t, p)
	f.issued = time.Now().UTC().Truncate(time.Second)
	if _, err := j.Enroll(context.Background(), qaEvidenceBytes(t, f.base.revocation, 1, f.issued, []string{}, []string{}, nil)); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	return j
}

func qaNativeSkillLiveProof(t *testing.T, f *qaNativeSkillLiveFixture, target string) {
	t.Helper()
	archive, err := os.ReadFile(filepath.Join(target, "live-skill.skb"))
	if err != nil || !bytes.Equal(archive, f.archive) {
		t.Fatal("retained skill archive differs from selected signed bytes", err)
	}
	body, err := os.ReadFile(filepath.Join(target, "SKILL.md"))
	if err != nil || !bytes.Equal(body, f.markdown) {
		t.Fatal("skill body changed", err)
	}
	raw, err := os.ReadFile(filepath.Join(target, registry.AttestationStashName))
	if err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	var ctx registry.AttestationContext
	if err = json.Unmarshal(raw, &ctx); err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if !reflect.DeepEqual(ctx.AdmitEvent, f.admit) || len(ctx.GovernanceAttestations) != len(f.attest) {
		t.Fatal("retained full signed context lost")
	}
	for i, e := range ctx.GovernanceAttestations {
		if !reflect.DeepEqual(e, f.attest[i]) {
			t.Fatal("retained reviewer event changed")
		}
	}
}
func qaNativeSkillLivePlan(t *testing.T, p *NativePolicy, digest string) (*registry.NativeLiveSkillSession, *registry.NativeSkillInstallPlan) {
	t.Helper()
	s, err := p.BeginER1SkillInstall(context.Background(), digest)
	if err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	t.Cleanup(func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	})
	plan, err := s.Plan(context.Background())
	if err != nil {
		t.Fatal(qaNativeSkillPolicyCauses(err))
	}
	if len(plan.Rows) != 1 || plan.Rows[0].Kind != "skill" || plan.Rows[0].Digest != digest || len(plan.Token) != 43 {
		t.Fatal("skill plan lost exact subject or consent")
	}
	return s, plan
}
func TestNativeLiveSkillAcquisition(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]any
		want   error
	}{{"raw-Pack-v1", nil, nil}, {"explicit-skill", map[string]any{"kind": "skill"}, nil}, {"signed-agent", map[string]any{"kind": "agent"}, registry.ErrNativeEvidenceInvalid}, {"identity-case-alias", map[string]any{"Name": "foreign"}, registry.ErrNativeEvidenceInvalid}, {"null-dependencies", map[string]any{"depends_on": nil}, registry.ErrNativeDependenciesUnavailable}, {"dependency-alias", map[string]any{"Depends_On": []any{}}, registry.ErrNativeDependenciesUnavailable}, {"nonempty-dependencies", map[string]any{"depends_on": []any{map[string]any{"kind": "skill", "name": "missing", "constraint": "*"}}}, registry.ErrNativeDependenciesUnavailable}, {"package-even-empty", map[string]any{"package_dependencies": []any{}}, registry.ErrNativeDependenciesUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			f := qaNativeSkillLiveNew(t, tc.fields)
			p := f.load(t)
			f.enroll(t, p)
			before := qaEvidenceInventory(t, f.base.home, true)
			s, err := p.BeginER1SkillInstall(context.Background(), f.digest)
			if err != nil {
				t.Fatal("fresh journal/source Begin", err)
			}
			defer func() {
				if e := s.Close(); e != nil {
					t.Error(e)
				}
			}()
			plan, err := s.Plan(context.Background())
			if tc.want != nil {
				if !errors.Is(err, tc.want) || plan != nil {
					t.Fatal("wrong signed input refusal cause", tc.name, err)
				}
				if !reflect.DeepEqual(before, qaEvidenceInventory(t, f.base.home, true)) {
					t.Fatal("rejected skill published artifacts")
				}
				return
			}
			if err != nil || len(plan.Rows) != 1 {
				t.Fatal("genuine signed canonical skill failed", err)
			}
			if _, err = s.Confirm(context.Background(), plan.Token); err != nil {
				t.Fatal(qaNativeSkillPolicyCauses(err))
			}
			qaNativeSkillLiveProof(t, f, plan.Rows[0].Target)
		})
	}
	t.Run("unsigned-carrier-bytes-do-not-replace-signed-digest", func(t *testing.T) {
		f := qaNativeSkillLiveNew(t, nil)
		p := f.load(t)
		f.enroll(t, p)
		f.archive[len(f.archive)/2] ^= 1
		f.mu.Lock()
		f.rows = qaNativeSkillLiveRows(t, f)
		f.mu.Unlock()
		s, err := p.BeginER1SkillInstall(context.Background(), f.digest)
		if s != nil || !errors.Is(err, registry.ErrNativeEvidenceInvalid) {
			t.Fatal("corrupted source bytes were not rejected during acquisition", qaNativeSkillPolicyCauses(err))
		}
	})
}
func TestNativeLiveSkillConsentBoundary(t *testing.T) {
	t.Run("create-overwrite-backup-and-replay", func(t *testing.T) {
		f := qaNativeSkillLiveNew(t, nil)
		p := f.load(t)
		f.enroll(t, p)
		s, plan := qaNativeSkillLivePlan(t, p, f.digest)
		if plan.Rows[0].Operation != "create" || plan.Rows[0].BackupPath != "" {
			t.Fatal("fresh skill plan is not create")
		}
		if _, err := s.Confirm(context.Background(), plan.Token); err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
		if err := s.Close(); err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
		qaNativeSkillLiveProof(t, f, plan.Rows[0].Target)
		s2, p2 := qaNativeSkillLivePlan(t, p, f.digest)
		if p2.Rows[0].Operation != "overwrite" || p2.Rows[0].OldDigest != f.digest || p2.Rows[0].BackupPath == "" {
			t.Fatal("overwrite consent lost old digest/backup")
		}
		if _, err := s2.Confirm(context.Background(), p2.Token); err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
		qaNativeSkillLiveProof(t, f, p2.Rows[0].Target)
		qaNativeSkillLiveProof(t, f, p2.Rows[0].BackupPath)
		if _, err := s2.Confirm(context.Background(), p2.Token); !errors.Is(err, registry.ErrNativeSessionUnavailable) {
			t.Fatal("successful token reused", err)
		}
	})
	t.Run("wrong-token-no-body", func(t *testing.T) {
		f := qaNativeSkillLiveNew(t, nil)
		p := f.load(t)
		f.enroll(t, p)
		s, plan := qaNativeSkillLivePlan(t, p, f.digest)
		wrong := strings.Repeat("A", 43)
		if wrong == plan.Token {
			wrong = strings.Repeat("B", 42) + "A"
		}
		if _, err := s.Confirm(context.Background(), wrong); !errors.Is(err, registry.ErrNativeConsentInvalid) {
			t.Fatal("caller token was not preserved", err)
		}
		if _, err := os.Stat(plan.Rows[0].Target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("wrong token published skill", err)
		}
	})
	t.Run("same-authority-agent-contender-blocked", func(t *testing.T) {
		f := qaNativeSkillLiveNew(t, nil)
		p := f.load(t)
		j := f.enroll(t, p)
		s, _ := qaNativeSkillLivePlan(t, p, f.digest)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if held, err := j.BeginOfflineInstall(ctx, f.digest); held != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("skill held journal failed cross-kind exclusion", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(qaNativeSkillPolicyCauses(err))
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		if _, err := j.Status(ctx2); err != nil {
			t.Fatal("closed skill retained journal", err)
		}
	})
}

func qaNativeSkillPolicyCauses(err error) string {
	if err == nil {
		return "<nil>"
	}
	s := fmt.Sprintf("%T:%s", err, err.Error())
	if x, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range x.Unwrap() {
			s += "; " + qaNativeSkillPolicyCauses(e)
		}
	} else if e := errors.Unwrap(err); e != nil {
		s += "; " + qaNativeSkillPolicyCauses(e)
	}
	return s
}
