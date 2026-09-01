package install

// End-to-end install tests. Each test wires a fixture httptest.Server,
// a real ed25519 keypair, a real gzip+tar bundle, and exercises the
// whole pipeline including the §7 verifier and the atomic-rename
// install path.
//
// SPEC-0188 acceptance criteria covered here:
//   - T8: tampered-bundle test (single-byte flip → exit 10).
//   - T9: wrong-pubkey test (identity registers key A, signature is from
//     key B → exit 11).
//   - T10: --allow-yellow / --ignore-deps audit BEFORE proceeding;
//     refuse if the audit POST fails.
//   - Plan §294-301 acceptance: green minimum rejects yellow → exit 13;
//     happy install writes ~/.claude/skills/<name>/ and exits 0.

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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// ----- bundle factory -----

type bundleSpec struct {
	name    string
	version string
	files   map[string]string // relative-to-bundle-root path → content
	scripts map[string]string // relative-to-scripts/ path → content
}

// buildBundleTGZ returns the gzipped tarball + the inner top-level dir
// name. The tarball follows SPEC §3.1's layout: one top-level dir
// "<name>-<version>/" with bundle.json + SKILL.md inside.
func buildBundleTGZ(t *testing.T, spec bundleSpec) []byte {
	t.Helper()
	if spec.files == nil {
		spec.files = map[string]string{}
	}
	if _, ok := spec.files["bundle.json"]; !ok {
		spec.files["bundle.json"] = `{"name":"` + spec.name + `","version":"` + spec.version + `","schema":"m3c-skill-bundle/v1"}` + "\n"
	}
	if _, ok := spec.files["SKILL.md"]; !ok {
		spec.files["SKILL.md"] = "# " + spec.name + "\n"
	}

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)

	root := spec.name + "-" + spec.version

	// Top-level dir.
	if err := tw.WriteHeader(&tar.Header{
		Name:     root + "/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}); err != nil {
		t.Fatalf("tar dir: %v", err)
	}

	for path, content := range spec.files {
		hdr := &tar.Header{
			Name:     root + "/" + path,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", path, err)
		}
	}
	for path, content := range spec.scripts {
		full := "scripts/" + path
		hdr := &tar.Header{
			Name:     root + "/" + full,
			Mode:     0o755,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", full, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", full, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return gzBuf.Bytes()
}

// ----- fake registry -----

type fakeRegistry struct {
	t *testing.T

	// State the test installs into.
	versions []registry.BundleVersion
	bundles  map[string][]byte // digest → blob
	metas    map[string]map[string]any
	idents   map[string]map[string]any

	// Audit POSTs the server received. Tests assert against this.
	auditCalls []map[string]any

	// auditStatus to return; default 201.
	auditStatus int
}

func newFakeRegistry(t *testing.T) (*httptest.Server, *fakeRegistry) {
	fr := &fakeRegistry{
		t:           t,
		bundles:     map[string][]byte{},
		metas:       map[string]map[string]any{},
		idents:      map[string]map[string]any{},
		auditStatus: http.StatusCreated,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":     filepath.Base(r.URL.Path),
			"versions": fr.versions,
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		seg := strings.TrimPrefix(r.URL.Path, "/api/skills/bundles/")
		// /bundles/<digest>/manifest is also possible — this test fixture
		// doesn't exercise it.
		seg = strings.SplitN(seg, "/", 2)[0]
		if r.URL.Query().Get("meta") == "1" {
			meta, ok := fr.metas[seg]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(meta)
			return
		}
		blob, ok := fr.bundles[seg]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/skills/identities/")
		ident, ok := fr.idents[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ident)
	})
	mux.HandleFunc("/api/skills/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var entry map[string]any
		_ = json.NewDecoder(r.Body).Decode(&entry)
		fr.auditCalls = append(fr.auditCalls, entry)
		w.WriteHeader(fr.auditStatus)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, fr
}

// ----- happy-path scaffolding -----

type bundleFixture struct {
	authorPub  ed25519.PublicKey
	authorPriv ed25519.PrivateKey
	regPub     ed25519.PublicKey
	regPriv    ed25519.PrivateKey
	digestRaw  [32]byte
	digestStr  string
	blob       []byte
}

func mkBundleFixture(t *testing.T) *bundleFixture {
	t.Helper()
	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 author: %v", err)
	}
	regPub, regPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 registry: %v", err)
	}
	blob := buildBundleTGZ(t, bundleSpec{
		name:    "fetch-contract",
		version: "1.0.0",
	})
	digest := sha256.Sum256(blob)
	return &bundleFixture{
		authorPub:  authorPub,
		authorPriv: authorPriv,
		regPub:     regPub,
		regPriv:    regPriv,
		digestRaw:  digest,
		digestStr:  "sha256:" + hex.EncodeToString(digest[:]),
		blob:       blob,
	}
}

// fillRegistry wires fr to serve fixture's bundle as fetch-contract@1.0.0.
func fillRegistry(t *testing.T, fr *fakeRegistry, fx *bundleFixture, currentGov string) {
	t.Helper()
	fr.versions = []registry.BundleVersion{
		{Version: "1.0.0", Digest: fx.digestStr, Status: "admitted", AuthorIntent: "green"},
	}
	fr.bundles[fx.digestStr] = fx.blob
	authorSig := ed25519.Sign(fx.authorPriv, fx.digestRaw[:])
	regSig := ed25519.Sign(fx.regPriv, fx.digestRaw[:])
	fr.metas[fx.digestStr] = map[string]any{
		"bundle": map[string]any{
			"bundle_digest": fx.digestStr,
			"name":          "fetch-contract",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		"signatures": []map[string]any{
			{"role": "author", "identity_id": "id:author@m3c", "signature_b64": base64.StdEncoding.EncodeToString(authorSig), "status": "active"},
			{"role": "registry", "identity_id": "id:registry@aims-core", "signature_b64": base64.StdEncoding.EncodeToString(regSig), "status": "active"},
		},
		"manifest": map[string]any{
			"author_governance_intent": "green",
			"depends_on":               []any{},
		},
		"current_governance": currentGov,
		"attestations": []map[string]any{
			{"level": currentGov, "reviewer_id": "id:reviewer@m3c", "attested_at": "2026-05-05T20:00:00Z"},
		},
	}
	fr.idents["id:author@m3c"] = map[string]any{
		"id":          "id:author@m3c",
		"pubkey_b64":  base64.StdEncoding.EncodeToString(fx.authorPub),
		"auth_source": "manual",
	}
}

func mkTrustRoot(t *testing.T, regPub ed25519.PublicKey, baseURL, governanceMin string) *verify.TrustRoot {
	t.Helper()
	return &verify.TrustRoot{
		RegistryURL:            baseURL,
		IdentityKeysAuthorized: "from-registry",
		GovernanceMinimum:      governanceMin,
		RegistryKeys: []verify.RegistryKey{{
			ID:        "reg-key-1",
			Pubkey:    []byte(regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(regPub),
			Issued:    "2026-05-05",
		}},
	}
}

// ----- happy path -----

func TestInstall_HappyPath(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	res, err := Install(Opts{
		Name:      "fetch-contract",
		Version:   "1.0.0",
		Client:    c,
		TrustRoot: tr,
		HomeDir:   homeDir,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.InstalledPath == "" {
		t.Fatalf("InstalledPath empty")
	}
	if res.Verify == nil || res.Verify.AuthorIdentity != "id:author@m3c" {
		t.Errorf("verify result wrong: %+v", res.Verify)
	}

	// Sanity-check that the bundle.json landed.
	if _, err := os.Stat(filepath.Join(res.InstalledPath, "bundle.json")); err != nil {
		t.Errorf("bundle.json missing: %v", err)
	}
	// And that the staging dir was cleaned up.
	tmpRoot := filepath.Join(homeDir, ".claude/skills/.tmp")
	if entries, err := os.ReadDir(tmpRoot); err == nil && len(entries) > 0 {
		t.Errorf("staging dir not cleaned: %d entries left", len(entries))
	}
}

// ----- T8: tampered bundle -----

func TestInstall_T8_TamperedBundle_Exit10(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")

	// Tamper: replace the served blob with a 1-byte-flipped version,
	// but keep the metadata pointing at the ORIGINAL digest. That's
	// the classic "registry signed digest D, attacker swaps blob" attack.
	tampered := make([]byte, len(fx.blob))
	copy(tampered, fx.blob)
	tampered[10] ^= 0x01
	fr.bundles[fx.digestStr] = tampered

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	_, err := Install(Opts{
		Name:      "fetch-contract",
		Version:   "1.0.0",
		Client:    c,
		TrustRoot: tr,
		HomeDir:   homeDir,
	})
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Errorf("tampered bundle: want ErrDigestMismatch, got %v", err)
	}
	if got := verify.ExitCode(err); got != 10 {
		t.Errorf("tampered bundle: exit code = %d, want 10", got)
	}
	// Nothing must have been written to ~/.claude/skills/<name>/.
	if _, err := os.Stat(filepath.Join(homeDir, ".claude/skills/fetch-contract")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("install dir should not exist after rejection: %v", err)
	}
}

// ----- T9: wrong pubkey -----

func TestInstall_T9_WrongPubkey_Exit11(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")

	// Identity B is registered; the author signed with key A. Replace
	// the identity's pubkey with key B (a fresh, unrelated key).
	imposterPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 imposter: %v", err)
	}
	fr.idents["id:author@m3c"] = map[string]any{
		"id":          "id:author@m3c",
		"pubkey_b64":  base64.StdEncoding.EncodeToString(imposterPub),
		"auth_source": "manual",
	}

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	_, err = Install(Opts{
		Name:      "fetch-contract",
		Version:   "1.0.0",
		Client:    c,
		TrustRoot: tr,
		HomeDir:   homeDir,
	})
	if !errors.Is(err, verify.ErrAuthorSigInvalid) {
		t.Errorf("wrong pubkey: want ErrAuthorSigInvalid, got %v", err)
	}
	if got := verify.ExitCode(err); got != 11 {
		t.Errorf("wrong pubkey: exit code = %d, want 11", got)
	}
}

// ----- governance gate -----

func TestInstall_GovernanceBelowMin_Exit13(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "yellow") // bundle is yellow

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green") // require green

	_, err := Install(Opts{
		Name:      "fetch-contract",
		Version:   "1.0.0",
		Client:    c,
		TrustRoot: tr,
		HomeDir:   homeDir,
	})
	if !errors.Is(err, verify.ErrGovernanceBelowMin) {
		t.Errorf("yellow vs green: want ErrGovernanceBelowMin, got %v", err)
	}
	if got := verify.ExitCode(err); got != 13 {
		t.Errorf("exit code = %d, want 13", got)
	}
}

// ----- T10: --allow-yellow audit-before-proceeding -----

func TestInstall_T10_AllowYellow_AuditsBeforeProceed(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "yellow")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	auditCalls := 0
	res, err := Install(Opts{
		Name:        "fetch-contract",
		Version:     "1.0.0",
		Client:      c,
		TrustRoot:   tr,
		HomeDir:     homeDir,
		AllowYellow: true,
		AuditPoster: func(ctx context.Context, e AuditEntry) error {
			auditCalls++
			if e.Action != "install.allow-yellow" {
				t.Errorf("action = %q", e.Action)
			}
			if !e.AllowYellow || e.IgnoreDeps {
				t.Errorf("flags wrong: %+v", e)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("--allow-yellow happy path: %v", err)
	}
	if auditCalls != 1 {
		t.Errorf("audit calls = %d, want 1", auditCalls)
	}
	if res.Verify.GovernanceLevel != "yellow" {
		t.Errorf("governance = %q", res.Verify.GovernanceLevel)
	}
}

func TestInstall_T10_AllowYellow_RefusesIfAuditFails(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "yellow")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	_, err := Install(Opts{
		Name:        "fetch-contract",
		Version:     "1.0.0",
		Client:      c,
		TrustRoot:   tr,
		HomeDir:     homeDir,
		AllowYellow: true,
		AuditPoster: func(ctx context.Context, e AuditEntry) error {
			return errors.New("audit server is down")
		},
	})
	if err == nil {
		t.Fatalf("expected refuse-on-audit-failure")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("error should mention audit: %v", err)
	}
	// Nothing must have been installed.
	if _, err := os.Stat(filepath.Join(homeDir, ".claude/skills/fetch-contract")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("install dir should not exist after audit failure: %v", err)
	}
}

func TestInstall_T10_AllowYellow_RefusesIfNoAuditPoster(t *testing.T) {
	// SPEC-0188: setting --allow-yellow without an audit channel means
	// the override would be silent. We refuse rather than ship a yellow
	// install that no one knows about.
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "yellow")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	_, err := Install(Opts{
		Name:        "fetch-contract",
		Version:     "1.0.0",
		Client:      c,
		TrustRoot:   tr,
		HomeDir:     homeDir,
		AllowYellow: true,
		// AuditPoster intentionally nil
	})
	if err == nil {
		t.Fatalf("expected refuse-on-no-audit-poster")
	}
}

// ----- HTTPAuditPoster shape -----

func TestHTTPAuditPoster_201_OK(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	poster := HTTPAuditPoster(srv.Client(), srv.URL+"/api/skills")
	err := poster(context.Background(), AuditEntry{
		Action:      "install.allow-yellow",
		Name:        "fetch-contract",
		Version:     "1.0.0",
		AllowYellow: true,
		RecordedAt:  "2026-05-05T20:00:00Z",
		Origin:      "skillctl",
		RegistryURL: srv.URL + "/api/skills",
	})
	if err != nil {
		t.Errorf("HTTPAuditPoster: %v", err)
	}
	if len(fr.auditCalls) != 1 {
		t.Fatalf("got %d audit calls, want 1", len(fr.auditCalls))
	}
	if fr.auditCalls[0]["action"] != "install.allow-yellow" {
		t.Errorf("audit action = %v", fr.auditCalls[0]["action"])
	}
}

func TestHTTPAuditPoster_500_Refused(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fr.auditStatus = http.StatusInternalServerError
	poster := HTTPAuditPoster(srv.Client(), srv.URL+"/api/skills")
	err := poster(context.Background(), AuditEntry{Action: "install.allow-yellow", Name: "x"})
	if err == nil {
		t.Errorf("expected error on 500")
	}
}

// ----- archive-on-overwrite -----

func TestInstall_ArchivesPriorVersion(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	// First install.
	res1, err := Install(Opts{Name: "fetch-contract", Version: "1.0.0", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if err != nil {
		t.Fatalf("install 1: %v", err)
	}
	// Drop a sentinel file so we can check it ends up in the archive.
	if err := os.WriteFile(filepath.Join(res1.InstalledPath, "USER_FILE"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	// Second install (same digest) — should archive the prior install.
	res2, err := Install(Opts{Name: "fetch-contract", Version: "1.0.0", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if err != nil {
		t.Fatalf("install 2: %v", err)
	}
	if res2.ArchivedPath == "" {
		t.Fatalf("ArchivedPath empty on overwrite")
	}
	if _, err := os.Stat(filepath.Join(res2.ArchivedPath, "USER_FILE")); err != nil {
		t.Errorf("archived USER_FILE missing: %v", err)
	}
}

// ----- tar bomb / path-traversal -----

func TestInstall_TarPathTraversal_Refused(t *testing.T) {
	srv, fr := newFakeRegistry(t)

	// Hand-build a malicious bundle where one tar entry escapes the root.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	body := []byte("malicious")
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tar: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	_ = tw.Close()
	_ = gw.Close()
	blob := gzBuf.Bytes()

	authorPub, authorPriv, _ := ed25519.GenerateKey(rand.Reader)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha256.Sum256(blob)
	digestStr := "sha256:" + hex.EncodeToString(digest[:])

	fr.versions = []registry.BundleVersion{{Version: "1.0.0", Digest: digestStr, Status: "admitted"}}
	fr.bundles[digestStr] = blob
	authorSig := ed25519.Sign(authorPriv, digest[:])
	regSig := ed25519.Sign(regPriv, digest[:])
	fr.metas[digestStr] = map[string]any{
		"bundle":             map[string]any{"bundle_digest": digestStr, "status": "admitted"},
		"signatures":         []map[string]any{{"role": "author", "identity_id": "id:a", "signature_b64": base64.StdEncoding.EncodeToString(authorSig), "status": "active"}, {"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(regSig), "status": "active"}},
		"manifest":           map[string]any{},
		"current_governance": "green",
	}
	fr.idents["id:a"] = map[string]any{"id": "id:a", "pubkey_b64": base64.StdEncoding.EncodeToString(authorPub), "auth_source": "manual"}

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, regPub, srv.URL+"/api/skills", "green")

	_, err := Install(Opts{Name: "evil", Version: "1.0.0", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if err == nil {
		t.Fatalf("expected refuse on path traversal")
	}
	if !strings.Contains(err.Error(), "escape") && !strings.Contains(err.Error(), "outside destination") {
		t.Errorf("error should mention path escape: %v", err)
	}
	// And the escape target must NOT exist.
	if _, err := os.Stat(filepath.Join(filepath.Dir(homeDir), "escape.txt")); err == nil {
		t.Errorf("path-traversal landed a file outside the home dir!")
	}
}

func TestInstall_GzipBomb_Refused(t *testing.T) {
	srv, fr := newFakeRegistry(t)

	// Build a tarball that decompresses into more bytes than allowed.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	body := bytes.Repeat([]byte{'A'}, 200) // small payload, but we'll cap at 100 bytes
	if err := tw.WriteHeader(&tar.Header{Name: "evil-1.0.0/big.bin", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tar: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	_ = tw.Close()
	_ = gw.Close()
	blob := gzBuf.Bytes()

	authorPub, authorPriv, _ := ed25519.GenerateKey(rand.Reader)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha256.Sum256(blob)
	digestStr := "sha256:" + hex.EncodeToString(digest[:])

	fr.versions = []registry.BundleVersion{{Version: "1.0.0", Digest: digestStr, Status: "admitted"}}
	fr.bundles[digestStr] = blob
	authorSig := ed25519.Sign(authorPriv, digest[:])
	regSig := ed25519.Sign(regPriv, digest[:])
	fr.metas[digestStr] = map[string]any{
		"bundle":             map[string]any{"bundle_digest": digestStr, "status": "admitted"},
		"signatures":         []map[string]any{{"role": "author", "identity_id": "id:a", "signature_b64": base64.StdEncoding.EncodeToString(authorSig), "status": "active"}, {"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(regSig), "status": "active"}},
		"manifest":           map[string]any{},
		"current_governance": "green",
	}
	fr.idents["id:a"] = map[string]any{"id": "id:a", "pubkey_b64": base64.StdEncoding.EncodeToString(authorPub), "auth_source": "manual"}

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, regPub, srv.URL+"/api/skills", "green")

	_, err := Install(Opts{
		Name:              "evil",
		Version:           "1.0.0",
		Client:            c,
		TrustRoot:         tr,
		HomeDir:           homeDir,
		MaxExtractedBytes: 100, // 100 bytes cap; payload is 200 bytes
	})
	if err == nil {
		t.Fatalf("expected refuse on size cap")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should mention size cap: %v", err)
	}
}

// ----- VerifyInstalled -----

func TestVerifyInstalled_OK(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	if _, err := Install(Opts{Name: "fetch-contract", Version: "1.0.0", Client: c, TrustRoot: tr, HomeDir: homeDir}); err != nil {
		t.Fatalf("install: %v", err)
	}
	res, err := VerifyInstalled(Opts{Name: "fetch-contract", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if err != nil {
		t.Fatalf("VerifyInstalled: %v", err)
	}
	if res.AuthorIdentity != "id:author@m3c" {
		t.Errorf("AuthorIdentity = %q", res.AuthorIdentity)
	}
}

// SEC-M4: content-binding is UNCONDITIONAL on the ONLINE managed-verify path.
// After a clean install + a registry-PASS re-verify, editing the on-disk
// SKILL.md (the body Claude actually loads) must be caught as ErrDigestMismatch
// (exit 10) even though the registry-side §7 chain still passes — proving the
// online path binds the extracted content to the signed .skb.
func TestVerifyInstalled_EditedBody_Exit10(t *testing.T) {
	srv, fr := newFakeRegistry(t)
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")

	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")

	res, err := Install(Opts{Name: "fetch-contract", Version: "1.0.0", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	// Baseline: a pristine install re-verifies clean.
	if _, err := VerifyInstalled(Opts{Name: "fetch-contract", Client: c, TrustRoot: tr, HomeDir: homeDir}); err != nil {
		t.Fatalf("pristine VerifyInstalled should pass, got %v", err)
	}

	// Tamper the body Claude would load AFTER install. The registry chain still
	// passes (the stashed .skb is untouched), so only the content-binding catches it.
	skillMd := filepath.Join(res.InstalledPath, "SKILL.md")
	if err := os.WriteFile(skillMd, []byte("# pwned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyInstalled(Opts{Name: "fetch-contract", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("edited body via online path must be ErrDigestMismatch, got %v", err)
	}
	if got := verify.ExitCode(err); got != verify.ExitDigestMismatch {
		t.Fatalf("exit code = %d, want %d", got, verify.ExitDigestMismatch)
	}
}

func TestVerifyInstalled_NotInstalled(t *testing.T) {
	srv, _ := newFakeRegistry(t)
	homeDir := t.TempDir()
	c := registry.New(srv.URL+"/api/skills", srv.Client())
	tr := &verify.TrustRoot{
		RegistryURL:            srv.URL + "/api/skills",
		IdentityKeysAuthorized: "from-registry",
		GovernanceMinimum:      "green",
		RegistryKeys: []verify.RegistryKey{{
			ID:     "k",
			Pubkey: bytes.Repeat([]byte{0}, 32),
		}},
	}
	_, err := VerifyInstalled(Opts{Name: "ghost", Client: c, TrustRoot: tr, HomeDir: homeDir})
	if err == nil {
		t.Errorf("expected error for missing install")
	}
}

// ----- helpers -----

// guard against unused-import drift while iterating.
var _ = io.EOF
var _ = fmt.Sprintf
var _ = hex.EncodeToString
