package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
)

type nativeSessionQAFixture struct {
	agent   *qaAgentFixture
	journal *NativeJournal
	now     time.Time
}

func nativeSessionQAArchive(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	manifest := map[string]any{"schema": "m3c-skill-bundle/v2", "kind": "agent", "name": "native-session-agent", "version": "1.0.0", "depends_on": []any{}}
	for k, v := range fields {
		manifest[k] = v
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, e := range []struct {
		name string
		body []byte
	}{{"bundle.json", raw}, {"native-session-agent.md", []byte("---\nname: native-session-agent\n---\n\nSigned native session fixture.\n")}} {
		if err = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0600, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func nativeSessionQANew(t *testing.T, fields map[string]any) *nativeSessionQAFixture {
	t.Helper()
	return nativeSessionQANewWithAge(t, fields, time.Hour)
}
func nativeSessionQANewWithAge(t *testing.T, fields map[string]any, evidenceAge time.Duration) *nativeSessionQAFixture {
	t.Helper()
	// The shared stagedAgent helper parses bundle.json before the consumer.
	// Retain its real random signing keys/home, then sign the exact test archive
	// independently so malformed declarations reach the actual session boundary.
	a := qaAgentSignedNamed(t, "native-session-agent", nil)
	a.blob = nativeSessionQAArchive(t, fields)
	item, digest := mintAdmitItem(t, a.registryKey, a.name, "1.0.0", string(a.blob))
	event, err := extractEvent(itemBody(item))
	if err != nil {
		t.Fatal(err)
	}
	a.admit = item
	a.staged.Digest = digest
	if err = os.WriteFile(a.staged.StagedSkbPath, a.blob, 0600); err != nil {
		t.Fatal(err)
	}
	a.attest = nil
	for i, key := range a.signerKeys {
		a.attest = append(a.attest, signedAttest(t, key, a.roots.Signers[i].ReviewerID, digest, "green", a.now.Add(-time.Minute).Format(time.RFC3339), nil))
	}
	a.staged.Attestation = &AttestationContext{AdmitEvent: event, GovernanceAttestation: a.attest[0], GovernanceAttestations: a.attest}
	// Feed genuine pinned key material through the same bounded roots parser.
	var text strings.Builder
	fmt.Fprintf(&text, "registry: self\npubkey_b64: %s\ngovernance_minimum: green\ngovernance_quorum: 2\nsigners:\n", a.roots.PubKeyB64)
	for _, signer := range a.roots.Signers {
		fmt.Fprintf(&text, " - reviewer_id: %s\n   pubkey_b64: %s\n", signer.ReviewerID, signer.PubKeyB64)
	}
	artifactRoots, err := ParseNativeRootsSnapshot([]byte(text.String()))
	if err != nil {
		t.Fatal(err)
	}
	headRoots, headKey, _ := nativeFixtureRoots(t)
	authority, err := NewNativeRevocationAuthority("self", nil, headRoots)
	if err != nil {
		t.Fatal(err)
	}
	home, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(a.skills)))
	if err != nil {
		t.Fatal(err)
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewNativeInstallSelection(strings.Repeat("a", 64), strings.Repeat("b", 64), project, home, artifactRoots, authority, dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: project, Tools: []dependencies.Tool{}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenNativeJournal(selection)
	if err != nil {
		t.Fatal(err)
	}
	f := &nativeSessionQAFixture{agent: a, journal: j, now: a.now}
	j.now = func() time.Time { return f.now }
	evidence := nativeEvidenceBytes(t, headKey, f.now.Add(-evidenceAge), 7, []string{}, nil)
	if _, err = j.Enroll(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *nativeSessionQAFixture) begin(t *testing.T) *NativeInstallSession {
	t.Helper()
	s, err := f.journal.BeginOfflineInstall(context.Background(), f.agent.staged.Digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("checked native session cleanup: %v", err)
		}
	})
	return s
}
func nativeSessionQAPlan(t *testing.T, s *NativeInstallSession, a *qaAgentFixture) *NativeInstallPlan {
	t.Helper()
	p, err := s.PlanInstall(context.Background(), []*StagedBundle{a.staged})
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || len(p.Rows) != 1 || len(p.Token) != 43 {
		t.Fatal("native consent must expose exactly one row and canonical nonce")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(p.Token)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != p.Token {
		t.Fatal("native consent nonce is not canonical 32-byte randomness")
	}
	if p.Rows[0].Digest != a.staged.Digest || p.Rows[0].Name != a.name || p.Rows[0].Kind != "agent" {
		t.Fatal("native plan differs from signed selected subject")
	}
	return p
}
func nativeSessionQAInventory(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range []string{"native-session-agent.md", ".skillctl-evidence/native-session-agent.record", ".provenance/native-session-agent.json"} {
		raw, err := os.ReadFile(filepath.Join(home, ".claude", "agents", rel))
		if errors.Is(err, os.ErrNotExist) {
			out[rel] = "absent"
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out[rel] = "present:" + string(raw)
	}
	return out
}

func nativeSessionQANoPublication(t *testing.T, f *nativeSessionQAFixture, before map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(before, nativeSessionQAInventory(t, f.journal.selection.home)) {
		t.Fatal("refused native operation changed active agent or retained evidence")
	}
}

func nativeSessionQAContender(t *testing.T, f *nativeSessionQAFixture, busy bool) {
	t.Helper()
	home := f.journal.selection.home
	public := base64.StdEncoding.EncodeToString(f.journal.selection.authority.key)
	raw := []byte("registry: self\npubkey_b64: " + public + "\ngovernance_minimum: green\ngovernance_quorum: 1\n")
	if err := os.WriteFile(filepath.Join(home, "fixture-roots.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNativeJournalLockAndPersistence$", "-test.v")
	cmd.WaitDelay = time.Second
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "HOME" || key == "USERPROFILE" || strings.HasPrefix(key, "M3C_NATIVE_JOURNAL_") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	wantBusy := "0"
	if busy {
		wantBusy = "1"
	}
	cmd.Env = append(cmd.Env, "HOME="+home, "USERPROFILE="+home, "M3C_NATIVE_JOURNAL_CHILD=1", "M3C_NATIVE_JOURNAL_EXPECT_BUSY="+wantBusy)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil || err != nil || !bytes.Contains(out, []byte("--- PASS: TestNativeJournalLockAndPersistence")) || bytes.Contains(out, []byte("--- SKIP:")) {
		t.Fatalf("actual bounded native journal contender: busy%v error%v context%v output%s", busy, err, ctx.Err(), out)
	}
}

func nativeSessionQAUncertaintyText(t *testing.T, err error, publication bool) {
	t.Helper()
	want := "native trust persistence is uncertain; inspect trust status, close session and begin again"
	if publication {
		want = "native offline installation incomplete; files may already have changed; inspect destination, close session and begin again"
	}
	if err == nil || err.Error() != want {
		t.Fatalf("public native uncertainty guidance lost: got %v want %q", err, want)
	}
}

func TestNativeOfflineInstallSessionBinding(t *testing.T) {
	t.Run("fully-signed-agent-native-consent", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		if !p.ExpiresAt.Equal(f.now.Add(300 * time.Second)) {
			t.Fatal("native consent expiry is not bound to exact plan time")
		}
		results, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
		if err != nil || len(results) != 1 {
			t.Fatalf("genuine native installation failed: %v", err)
		}
		qaAgentVerifyRecord(t, f.agent)
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatalf("published/closed session reused: %v", err)
		}
	})
	t.Run("wrong-token-consumes-plan", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		before := nativeSessionQAInventory(t, f.journal.selection.home)
		for _, token := range []string{strings.Repeat("!", 43), p.Token} {
			if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, token); !errors.Is(err, ErrNativeConsentInvalid) {
				t.Fatalf("invalid/replayed native consent: %v", err)
			}
		}
		nativeSessionQANoPublication(t, f, before)
		fresh := nativeSessionQAPlan(t, s, f.agent)
		if fresh.Token == p.Token {
			t.Fatal("replanning reused consumed native nonce")
		}
		if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, fresh.Token); err != nil {
			t.Fatal(err)
		}
		qaAgentVerifyRecord(t, f.agent)
	})
	for _, edge := range []struct {
		name    string
		elapsed time.Duration
		allow   bool
	}{{"expiry-exact", 300 * time.Second, true}, {"expiry-plus-nanosecond", 300*time.Second + time.Nanosecond, false}} {
		t.Run(edge.name, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			s := f.begin(t)
			p := nativeSessionQAPlan(t, s, f.agent)
			f.now = f.now.Add(edge.elapsed)
			_, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
			if edge.allow {
				if err != nil {
					t.Fatal(err)
				}
				qaAgentVerifyRecord(t, f.agent)
			} else if !errors.Is(err, ErrNativeConsentInvalid) {
				t.Fatalf("expired token accepted or misclassified: %v", err)
			}
		})
	}
	t.Run("replan-failure-invalidates-old-token", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		if _, err := s.PlanInstall(context.Background(), nil); !errors.Is(err, ErrNativeDependenciesUnavailable) {
			t.Fatalf("unsupported replacement plan: %v", err)
		}
		if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatalf("old plan survived failed replan: %v", err)
		}
	})
	t.Run("original-root-cannot-be-substituted", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		other := qaAgentSignedNamed(t, "native-session-agent", nativeSessionQAArchive(t, map[string]any{"description": "different signed archive"}))
		before := nativeSessionQAInventory(t, f.journal.selection.home)
		if _, err := s.PlanInstall(context.Background(), []*StagedBundle{other.staged}); !errors.Is(err, ErrAgentEvidenceInvalid) {
			t.Fatalf("other signed subject substituted original root: %v", err)
		}
		nativeSessionQANoPublication(t, f, before)
	})
	t.Run("context-drift-consumes-consent", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		before := nativeSessionQAInventory(t, f.journal.selection.home)
		f.agent.staged.Attestation.GovernanceAttestations[1]["rationale"] = "changed after planning"
		if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); !errors.Is(err, ErrNativeConsentInvalid) {
			t.Fatalf("changed context reused native consent: %v", err)
		}
		nativeSessionQANoPublication(t, f, before)
	})
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{{"nonempty-skill", "depends_on", []any{map[string]any{"kind": "skill", "name": "missing", "version": "1.0.0"}}}, {"nonempty-agent", "depends_on", []any{map[string]any{"kind": "agent", "name": "missing", "version": "1.0.0"}}}, {"nonempty-python", "depends_on", []any{map[string]any{"kind": "python", "name": "missing", "version": "1.0.0"}}}, {"nonempty-system", "depends_on", []any{map[string]any{"kind": "system", "name": "missing", "version": "1.0.0"}}}, {"null-dependencies", "depends_on", nil}, {"object-dependencies", "depends_on", map[string]any{}}, {"alias-dependencies", "Depends_On", []any{}}, {"package-even-empty", "package_dependencies", []any{}}, {"data-null", "data_dependencies", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			f := nativeSessionQANew(t, map[string]any{tc.field: tc.value})
			s := f.begin(t)
			before := nativeSessionQAInventory(t, f.journal.selection.home)
			if _, err := s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrNativeDependenciesUnavailable) {
				t.Fatalf("signed unsupported dependency declaration accepted: %v", err)
			}
			nativeSessionQANoPublication(t, f, before)
		})
	}
	for _, where := range []string{"admit", "each-reviewer"} {
		t.Run("wrong-signed-tenant-"+where, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			s := f.begin(t)
			if where == "admit" {
				f.agent.staged.Attestation.AdmitEvent["tenant_scope"] = "foreign"
				if _, err := SignEnvelopeSignature(f.agent.registryKey, f.agent.staged.Attestation.AdmitEvent); err != nil {
					t.Fatal(err)
				}
			} else {
				ev := f.agent.staged.Attestation.GovernanceAttestations[1]
				ev["tenant_scope"] = "foreign"
				if _, err := SignEnvelopeSignature(f.agent.signerKeys[1], ev); err != nil {
					t.Fatal(err)
				}
			}
			before := nativeSessionQAInventory(t, f.journal.selection.home)
			if _, err := s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrAgentEvidenceInvalid) {
				t.Fatalf("valid foreign-tenant signature accepted: %v", err)
			}
			nativeSessionQANoPublication(t, f, before)
		})
	}
	for _, where := range []string{"admit", "second-reviewer"} {
		for _, shape := range []string{"missing", "wrong-type", "case-alias"} {
			t.Run("signed-tenant-"+where+"-"+shape, func(t *testing.T) {
				f := nativeSessionQANew(t, nil)
				s := f.begin(t)
				ev := f.agent.staged.Attestation.AdmitEvent
				key := f.agent.registryKey
				if where == "second-reviewer" {
					ev = f.agent.staged.Attestation.GovernanceAttestations[1]
					key = f.agent.signerKeys[1]
				}
				switch shape {
				case "missing":
					delete(ev, "tenant_scope")
				case "wrong-type":
					ev["tenant_scope"] = false
				case "case-alias":
					ev["Tenant_Scope"] = nil
				}
				if _, err := SignEnvelopeSignature(key, ev); err != nil {
					t.Fatal(err)
				}
				before := nativeSessionQAInventory(t, f.journal.selection.home)
				if _, err := s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrAgentEvidenceInvalid) {
					t.Fatalf("signed noncanonical tenant accepted: %v", err)
				}
				nativeSessionQANoPublication(t, f, before)
			})
		}
	}
	for _, change := range []string{"profile", "runtime"} {
		t.Run("cross-selection-token-"+change, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			first := f.begin(t)
			old := nativeSessionQAPlan(t, first, f.agent)
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			selected := f.journal.selection
			profile := selected.profileDigest
			var runtime dependencies.Profile
			if err := json.Unmarshal(selected.runtimeRaw, &runtime); err != nil {
				t.Fatal(err)
			}
			if change == "profile" {
				profile = strings.Repeat("c", 64)
			} else {
				runtime.Tools = []dependencies.Tool{{Name: "not-executed", Path: filepath.Join(selected.project, "never-execute"), Args: []string{"--version"}, VersionPattern: `^([0-9]+)$`}}
			}
			// A genuine new bounded selection shares stable revocation history,
			// but never the previous concrete session's native consent.
			policy, err := NewNativeInstallSelection(profile, selected.selectionID, selected.project, selected.home, &NativeRootsSnapshot{roots: selected.artifactRoots}, selected.authority, runtime)
			if err != nil {
				t.Fatal(err)
			}
			j, err := OpenNativeJournal(policy)
			if err != nil {
				t.Fatal(err)
			}
			j.now = func() time.Time { return f.now }
			second, err := j.BeginOfflineInstall(context.Background(), f.agent.staged.Digest)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := second.Close(); err != nil {
					t.Error(err)
				}
			})
			fresh := nativeSessionQAPlan(t, second, f.agent)
			if fresh.Token == old.Token {
				t.Fatal("separate session reused previous consent nonce")
			}
			before := nativeSessionQAInventory(t, selected.home)
			if _, err = second.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, old.Token); !errors.Is(err, ErrNativeConsentInvalid) {
				t.Fatalf("foreign selection token granted install: %v", err)
			}
			nativeSessionQANoPublication(t, f, before)
			fresh = nativeSessionQAPlan(t, second, f.agent)
			if _, err = second.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, fresh.Token); err != nil {
				t.Fatal(err)
			}
			qaAgentVerifyRecord(t, f.agent)
		})
	}
	for _, field := range []string{"profile-digest", "runtime-snapshot"} {
		t.Run("private-consent-hash-drift-"+field, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			s := f.begin(t)
			p := nativeSessionQAPlan(t, s, f.agent)
			before := nativeSessionQAInventory(t, f.journal.selection.home)
			// This is a deliberate private same-instance fault, not a public
			// mutable selection API or an alternative way to grant authority.
			if field == "profile-digest" {
				s.journal.selection.profileDigest = strings.Repeat("c", 64)
			} else {
				var runtime dependencies.Profile
				if err := json.Unmarshal(s.journal.selection.runtimeRaw, &runtime); err != nil {
					t.Fatal(err)
				}
				runtime.Tools = []dependencies.Tool{{Name: "not-executed", Path: filepath.Join(s.journal.selection.project, "never-execute"), Args: []string{"--version"}, VersionPattern: `^([0-9]+)$`}}
				raw, err := json.Marshal(runtime)
				if err != nil {
					t.Fatal(err)
				}
				s.journal.selection.runtimeRaw = raw
			}
			if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); !errors.Is(err, ErrNativeConsentInvalid) {
				t.Fatalf("valid nonce authorized private consent-hash drift: %v", err)
			}
			nativeSessionQANoPublication(t, f, before)
			fresh := nativeSessionQAPlan(t, s, f.agent)
			if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, fresh.Token); err != nil {
				t.Fatal("fresh explicit plan must bind the new selected snapshot", err)
			}
			qaAgentVerifyRecord(t, f.agent)
		})
	}
	t.Run("display-row-is-not-authority", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		p.Rows[0].Name = "foreign"
		p.Rows[0].Target = filepath.Join(t.TempDir(), "foreign.md")
		p.Rows[0].Digest = "sha256:" + strings.Repeat("f", 64)
		if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); err != nil {
			t.Fatal(err)
		}
		qaAgentVerifyRecord(t, f.agent)
		if _, err := os.Stat(p.Rows[0].Target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("caller display row redirected publication")
		}
	})
	t.Run("nil-zero-closed-no-fallback", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		closed := f.begin(t)
		if err := closed.Close(); err != nil {
			t.Fatal(err)
		}
		for _, s := range []*NativeInstallSession{nil, {}, closed} {
			if _, err := s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrNativeSessionUnavailable) {
				t.Fatalf("unheld native session planned: %v", err)
			}
			if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, ""); !errors.Is(err, ErrNativeSessionUnavailable) {
				t.Fatalf("unheld native session confirmed: %v", err)
			}
		}
	})
}

func TestNativeOfflineInstallPublicationBoundary(t *testing.T) {
	t.Run("retained-archive-not-reopened", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		if err := os.Remove(f.agent.staged.StagedSkbPath); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); err != nil {
			t.Fatal(err)
		}
		qaAgentVerifyRecord(t, f.agent)
	})
	for _, phase := range []string{"before-agent-lock", "before-artifact-write", "before-replace"} {
		t.Run("final-stale-"+phase, func(t *testing.T) {
			f := nativeSessionQANewWithAge(t, nil, 24*time.Hour-time.Minute)
			s := f.begin(t)
			if err := os.MkdirAll(filepath.Dir(f.agent.active()), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.agent.active(), []byte("previous active agent"), 0600); err != nil {
				t.Fatal(err)
			}
			p := nativeSessionQAPlan(t, s, f.agent)
			before := nativeSessionQAInventory(t, f.journal.selection.home)
			observed := false
			s.phase = func(got string) {
				if got == phase && !observed {
					observed = true
					f.now = f.now.Add(61 * time.Second)
				}
			}
			_, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
			if !observed || !errors.Is(err, ErrNativeHistoryStale) {
				t.Fatalf("final time boundary not enforced at %s: observed=%v error=%v", phase, observed, err)
			}
			nativeSessionQANoPublication(t, f, before)
		})
	}
	for _, phase := range []string{"before-agent-lock", "before-artifact-write", "before-replace"} {
		t.Run("consent-expires-during-confirm-"+phase, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			s := f.begin(t)
			p := nativeSessionQAPlan(t, s, f.agent)
			before := nativeSessionQAInventory(t, f.journal.selection.home)
			observed := false
			s.phase = func(got string) {
				if got == phase && !observed {
					observed = true
					f.now = f.now.Add(300*time.Second + time.Nanosecond)
				}
			}
			results, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
			if !observed || len(results) != 0 || !errors.Is(err, ErrNativeConsentInvalid) {
				t.Fatalf("confirmation crossed native consent deadline: phase%s observed%v error%v", phase, observed, err)
			}
			nativeSessionQANoPublication(t, f, before)
		})
	}
	t.Run("journal-persistence-error-guidance-before-publication", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		before := nativeSessionQAInventory(t, f.journal.selection.home)
		fault := errors.New("synthetic private persistence detail")
		realSync := f.journal.ops.sync
		f.journal.ops.sync = func(file *os.File) error { return errors.Join(realSync(file), fault) }
		results, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
		if len(results) != 0 || !errors.Is(err, ErrNativePersistence) || !errors.Is(err, fault) || errors.Is(err, ErrAgentPublicationIncomplete) {
			t.Fatalf("prepublication persistence classification: %v", err)
		}
		nativeSessionQAUncertaintyText(t, err, false)
		nativeSessionQANoPublication(t, f, before)
		f.journal.ops.sync = realSync
		if _, err = s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatalf("persistence-uncertain session recovered before Close: %v", err)
		}
	})
	t.Run("checked-journal-close-error-is-retained", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s, err := f.journal.BeginOfflineInstall(context.Background(), f.agent.staged.Digest)
		if err != nil {
			t.Fatal(err)
		}
		p := nativeSessionQAPlan(t, s, f.agent)
		if _, err = s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); err != nil {
			if closeErr := s.Close(); closeErr != nil {
				t.Error(closeErr)
			}
			t.Fatal(err)
		}
		qaAgentVerifyRecord(t, f.agent)
		fault := errors.New("synthetic checked journal close fault")
		realClose := f.journal.ops.close
		closed := 0
		f.journal.ops.close = func(file *os.File) error {
			err := realClose(file)
			if filepath.Base(file.Name()) == "lock" {
				closed++
				return errors.Join(err, fault)
			}
			return err
		}
		first := s.Close()
		second := s.Close()
		if closed != 1 || first != second || !errors.Is(first, fault) || !errors.Is(first, ErrNativePersistence) || !errors.Is(first, ErrAgentPublicationIncomplete) {
			t.Fatalf("checked Close uncertainty not retained: count%d first%v repeated%v", closed, first, second)
		}
		nativeSessionQAUncertaintyText(t, first, true)
		nativeSessionQAUncertaintyText(t, second, true)
	})
	t.Run("replace-error-poisons-before-retry", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		fault := errors.New("synthetic replace fault")
		ops := defaultAgentFileOps()
		attempted := 0
		ops.replace = func(string, string) error { attempted++; return fault }
		s.agentOps = &ops
		_, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
		if attempted != 1 || !errors.Is(err, fault) || !errors.Is(err, ErrAgentPublicationIncomplete) {
			t.Fatalf("attempted publication lost uncertainty/cause: attempts%d error%v", attempted, err)
		}
		nativeSessionQAUncertaintyText(t, err, true)
		s.agentOps = nil
		if _, err = s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatalf("publication-attempt session recovered without Close: %v", err)
		}
	})
	t.Run("later-replace-fault-keeps-partial-classification", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		fault := errors.New("synthetic later replace fault")
		ops := defaultAgentFileOps()
		realReplace := ops.replace
		calls := 0
		ops.replace = func(old, next string) error {
			calls++
			if calls == 2 {
				return fault
			}
			return realReplace(old, next)
		}
		s.agentOps = &ops
		results, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
		if len(results) != 0 || calls != 2 || !errors.Is(err, fault) || !errors.Is(err, ErrAgentPublicationIncomplete) {
			t.Fatalf("partial publication became success or lost cause: calls%d error%v", calls, err)
		}
		r := qaAgentReadRecord(t, f.agent.record())
		if !bytes.Equal(r.blob, f.agent.blob) {
			t.Fatal("published retained record lost exact authenticated archive")
		}
		nativeSessionQAUncertaintyText(t, err, true)
		s.agentOps = nil
		if _, err = s.PlanInstall(context.Background(), []*StagedBundle{f.agent.staged}); !errors.Is(err, ErrNativeSessionUnavailable) {
			t.Fatalf("partial session recovered without Close: %v", err)
		}
	})
	t.Run("later-final-check-preserves-uncertainty", func(t *testing.T) {
		f := nativeSessionQANewWithAge(t, nil, 24*time.Hour-time.Minute)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		replacements := 0
		s.phase = func(phase string) {
			if phase == "before-replace" {
				replacements++
				if replacements == 2 {
					f.now = f.now.Add(61 * time.Second)
				}
			}
		}
		results, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
		if len(results) != 0 || replacements != 2 || !errors.Is(err, ErrNativeHistoryStale) || !errors.Is(err, ErrAgentPublicationIncomplete) {
			t.Fatalf("later stale check lost partial state: checks%d error%v", replacements, err)
		}
		nativeSessionQAUncertaintyText(t, err, true)
		if _, err = os.Stat(f.agent.active()); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("stale second replace published active body")
		}
	})
	for _, phase := range []string{"before-artifact-write", "before-replace"} {
		t.Run("real-child-lease-held-"+phase, func(t *testing.T) {
			f := nativeSessionQANew(t, nil)
			s := f.begin(t)
			p := nativeSessionQAPlan(t, s, f.agent)
			observed := false
			s.phase = func(got string) {
				if got == phase && !observed {
					observed = true
					nativeSessionQAContender(t, f, true)
				}
			}
			if _, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token); err != nil {
				t.Fatal(err)
			}
			if !observed {
				t.Fatal("actual publication phase was not observed")
			}
			qaAgentVerifyRecord(t, f.agent)
			nativeSessionQAContender(t, f, true)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			nativeSessionQAContender(t, f, false)
			status, err := f.journal.Status(context.Background())
			if err != nil || status.Epoch != 7 {
				t.Fatalf("released journal lost authenticated history: epoch%d error%v", status.Epoch, err)
			}
		})
	}
	t.Run("close-cannot-release-running-confirm", func(t *testing.T) {
		f := nativeSessionQANew(t, nil)
		s := f.begin(t)
		p := nativeSessionQAPlan(t, s, f.agent)
		entered := make(chan struct{})
		resume := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(resume) }) }
		defer release()
		s.phase = func(phase string) {
			if phase == "before-artifact-write" {
				close(entered)
				<-resume
			}
		}
		confirmed := make(chan error, 1)
		go func() {
			_, err := s.ConfirmInstall(context.Background(), []*StagedBundle{f.agent.staged}, p.Token)
			confirmed <- err
		}()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("Confirm did not reach publication boundary")
		}
		closed := make(chan error, 1)
		go func() { closed <- s.Close() }()
		select {
		case err := <-closed:
			t.Fatalf("Close released a running native confirmation: %v", err)
		case <-time.After(30 * time.Millisecond):
		}
		release()
		if err := <-confirmed; err != nil {
			t.Fatal(err)
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		qaAgentVerifyRecord(t, f.agent)
	})
}
