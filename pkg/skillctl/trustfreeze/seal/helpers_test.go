package seal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// testTime is the fixed capture time (SPEC-0470 TF05-AC7: no wall clock).
var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// approveTime is the fixed approval time used by defaultRequest.
var approveTime = testTime.Add(time.Hour)

// verifyTime is the fixed "now" of testPolicy.
var verifyTime = testTime.Add(2 * time.Hour)

// Synthetic seeds (TF05-R8). They are derived from public labels, exist only
// in tests and are never production keys.
var (
	seedTrusted  = seedFrom("trust-freeze seal test key: trusted reviewer")
	seedAttacker = seedFrom("trust-freeze seal test key: attacker")
	seedSecond   = seedFrom("trust-freeze seal test key: second reviewer")
)

func seedFrom(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

func seedSigner(t *testing.T, seed []byte) *SeedSigner {
	t.Helper()
	s, err := NewSeedSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// writeKeyFiles writes the PEM/PKCS#8 private key (0600) and the PEM/SPKI
// public key of seed below dir, in the format signing.Generate writes.
func writeKeyFiles(t *testing.T, dir, base string, seed []byte) (privPath, pubPath string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, base+".priv")
	pubPath = filepath.Join(dir, base+".pub")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

// countingSigner records how often Sign was called.
type countingSigner struct {
	Signer
	mu sync.Mutex
	n  int
}

func (c *countingSigner) Sign(msg []byte) ([]byte, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.Signer.Sign(msg)
}

func (c *countingSigner) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// fixture describes a synthetic capture.
type fixture struct {
	osFamily string
	hostname string
	actor    string
	kernel   string
	required []string
	// reverseMaps inserts attribute map keys in reverse order.
	reverseMaps bool
}

func defaultFixture() fixture {
	return fixture{
		osFamily: "linux",
		hostname: "host-a.example",
		actor:    "alice",
		kernel:   "6.8.0-generic",
		required: []string{"common.identity"},
	}
}

func (fx fixture) subject() trustfreeze.Subject {
	return trustfreeze.Subject{ID: trustfreeze.SubjectID(fx.osFamily, fx.hostname), OSFamily: fx.osFamily}
}

func buildMap(reverse bool, kv [][2]string) map[string]string {
	m := make(map[string]string, len(kv))
	if reverse {
		for i := len(kv) - 1; i >= 0; i-- {
			m[kv[i][0]] = kv[i][1]
		}
		return m
	}
	for _, p := range kv {
		m[p[0]] = p[1]
	}
	return m
}

// writeCapture writes a finalized synthetic capture bundle at dir. The files
// are written directly (not through trustfreeze.Writer) so the evidence can
// carry synthetic bytes; the result must pass VerifyDir and ReadBundle like
// any capture.
func writeCapture(t *testing.T, dir string, fx fixture) trustfreeze.Manifest {
	t.Helper()
	subj := fx.subject()
	obs := trustfreeze.FormatTime(testTime)
	finished := testTime.Add(1500 * time.Millisecond)
	osRelease := []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n")
	uname := []byte(fx.kernel + "\n")

	arts := []trustfreeze.Artifact{
		{
			ID: "device/os", Type: "os", Scope: "device", Source: "common.identity",
			State: trustfreeze.StateObserved,
			Attributes: buildMap(fx.reverseMaps, [][2]string{
				{"arch", "amd64"}, {"kernel_release", fx.kernel}, {"os_build", ""},
				{"os_family", fx.osFamily}, {"os_name", "Ubuntu"}, {"os_version", "24.04"},
			}),
			Provenance:  trustfreeze.Provenance{Method: "file", Confidence: trustfreeze.ConfidenceProven, Sources: []string{"file:/etc/os-release", "command:uname -r"}, ObservedAt: obs},
			Sensitivity: trustfreeze.SensitivityPublic,
		},
		{
			ID: "device/host", Type: "host", Scope: "device", Source: "common.identity",
			State:       trustfreeze.StateObserved,
			Attributes:  buildMap(fx.reverseMaps, [][2]string{{"hostname", fx.hostname}}),
			Provenance:  trustfreeze.Provenance{Method: "runtime", Confidence: trustfreeze.ConfidenceProven, Sources: []string{"runtime:os.Hostname"}, ObservedAt: obs},
			Sensitivity: trustfreeze.SensitivityInternal,
		},
	}
	for i := range arts {
		d, err := trustfreeze.ComputeArtifactDigest(arts[i])
		if err != nil {
			t.Fatal(err)
		}
		arts[i].Digest = d
	}
	trustfreeze.SortArtifacts(arts)

	result := trustfreeze.ProbeResult{
		ProbeID: "common.identity", ProbeVersion: "1", Status: trustfreeze.StatusCaptured,
		Support: trustfreeze.SupportRecord{Available: true}, StartedAt: obs, DurationMS: 7,
		Privilege: trustfreeze.PrivilegeUser,
		Tools: []trustfreeze.ToolInvocation{{
			Name: "uname", Path: "/usr/bin/uname", Args: []string{"-r"}, ExitCode: 0,
			DurationMS: 2, StdoutBytes: int64(len(uname)),
		}},
		RawEvidence: []trustfreeze.EvidenceRef{
			{Path: "evidence/common.identity/os-release", Size: int64(len(osRelease)), SHA256: trustfreeze.SHA256Hex(osRelease), Source: "file:/etc/os-release"},
			{Path: "evidence/common.identity/uname-r", Size: int64(len(uname)), SHA256: trustfreeze.SHA256Hex(uname), Source: "stdout:uname -r"},
		},
		NormalizedState: arts,
	}
	results := []trustfreeze.ProbeResult{result}
	doc := trustfreeze.CaptureDoc{
		SchemaVersion: trustfreeze.SchemaCapture,
		Kind:          trustfreeze.KindCapture,
		Capture: trustfreeze.CaptureMeta{
			StartedAt:   obs,
			FinishedAt:  trustfreeze.FormatTime(finished),
			Tool:        trustfreeze.CaptureTool,
			ToolVersion: "0.0.0-test",
			Profile:     trustfreeze.ProfileRef{ID: "walking-skeleton", Version: "1", Digest: trustfreeze.Digest([]byte("profile"))},
			Actor:       fx.actor,
		},
		Subject:      subj,
		Completeness: trustfreeze.ComputeCompleteness(fx.required, results),
		Probes:       trustfreeze.Summarize(results),
	}
	probePath, err := trustfreeze.ProbeResultPath(result.ProbeID)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, dir, trustfreeze.CaptureFile, doc)
	writeJSONFile(t, dir, trustfreeze.StateDeviceFile, trustfreeze.StateDoc{Artifacts: arts})
	writeJSONFile(t, dir, probePath, result)
	writeRaw(t, dir, "evidence/common.identity/os-release", osRelease)
	writeRaw(t, dir, "evidence/common.identity/uname-r", uname)

	// The capture engine's manifest header, which Verify rebuilds from a
	// baseline (trustfreeze.DeriveCaptureManifest): created_at and bundle_id
	// come from capture.json finished_at.
	m, err := trustfreeze.BuildManifest(dir, trustfreeze.ManifestHeader{
		Kind: trustfreeze.KindCapture, BundleID: trustfreeze.BundleID(trustfreeze.KindCapture, finished, subj.ID),
		CreatedAt: finished, Subject: subj,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, dir, trustfreeze.ManifestFile, m)
	if _, err := trustfreeze.ReadBundle(dir); err != nil {
		t.Fatalf("fixture capture does not verify: %v", err)
	}
	return m
}

// newCapture writes a capture at <tmp>/<name> and returns its directory.
func newCapture(t *testing.T, parent, name string, fx fixture) (string, trustfreeze.Manifest) {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, writeCapture(t, dir, fx)
}

func defaultRequest(captureDir, outputDir string, s Signer) SealRequest {
	return SealRequest{
		CaptureDir: captureDir,
		OutputDir:  outputDir,
		Approval: ApprovalInput{
			Reviewer:          "bob",
			ChangeID:          "CHG-0001",
			Reason:            "Reviewed the walking skeleton capture of host-a.",
			ApproverSubjectID: trustfreeze.SubjectID("darwin", "approver.example"),
		},
		Signer:       s,
		Clock:        trustfreeze.FixedClock{T: approveTime},
		SelfApproval: SelfApprovalWarn,
	}
}

// sealed is a baseline produced for a test.
type sealed struct {
	root       string
	captureDir string
	dir        string
	signer     *SeedSigner
	result     *SealResult
}

// newBaseline writes a capture and seals it with the trusted test key.
func newBaseline(t *testing.T, mutate func(*SealRequest)) sealed {
	t.Helper()
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	s := seedSigner(t, seedTrusted)
	req := defaultRequest(capDir, filepath.Join(root, "baseline"), s)
	if mutate != nil {
		mutate(&req)
	}
	res, err := Seal(t.Context(), req)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed{root: root, captureDir: capDir, dir: req.OutputDir, signer: s, result: res}
}

// testPolicy trusts the given signers, warns on self-approval and uses the
// fixed verifyTime.
func testPolicy(signers ...Signer) TrustPolicy {
	p := TrustPolicy{SelfApproval: SelfApprovalWarn, RejectAdditions: true, Now: trustfreeze.FixedClock{T: verifyTime}}
	for _, s := range signers {
		p.TrustedKeys = append(p.TrustedKeys, TrustedKey{KeyID: s.KeyID(), PublicKey: s.PublicKey()})
	}
	return p
}

func describe(res VerificationResult) string {
	var sb strings.Builder
	for _, f := range res.Failures {
		sb.WriteString(string(f.Reason))
		if f.IntegrityReason != "" {
			sb.WriteString("/" + string(f.IntegrityReason))
		}
		sb.WriteString("@" + f.Path + " (" + f.Detail + "); ")
	}
	return sb.String()
}

func requireOK(t *testing.T, res VerificationResult) {
	t.Helper()
	if !res.OK || len(res.Failures) != 0 || res.Err() != nil {
		t.Fatalf("verification failed, want OK: %s", describe(res))
	}
	if !res.SignatureChecked || !res.SignatureValid || !res.KeyTrusted {
		t.Fatalf("OK result without a checked, valid, trusted signature: %+v", res)
	}
}

// requireReasons asserts that verification failed and that every wanted
// reason (and integrity reason) is present.
func requireReasons(t *testing.T, res VerificationResult, want []Reason, wantIntegrity ...trustfreeze.IntegrityReason) {
	t.Helper()
	if res.OK || res.Err() == nil || !errors.Is(res.Err(), ErrVerification) {
		t.Fatalf("verification passed, want failure %v %v", want, wantIntegrity)
	}
	for _, r := range want {
		if !res.Has(r) {
			t.Fatalf("missing reason %s; got %s", r, describe(res))
		}
	}
	for _, r := range wantIntegrity {
		if !res.HasIntegrity(r) {
			t.Fatalf("missing integrity reason %s; got %s", r, describe(res))
		}
	}
}

// requireExactReasons asserts the distinct reasons exactly.
func requireExactReasons(t *testing.T, res VerificationResult, want ...Reason) {
	t.Helper()
	got := res.Reasons()
	gs := make([]string, 0, len(got))
	for _, r := range got {
		gs = append(gs, string(r))
	}
	ws := make([]string, 0, len(want))
	for _, r := range want {
		ws = append(ws, string(r))
	}
	sort.Strings(gs)
	sort.Strings(ws)
	if strings.Join(gs, ",") != strings.Join(ws, ",") {
		t.Fatalf("reasons = %v, want %v; %s", gs, ws, describe(res))
	}
}

func writeJSONFile(t *testing.T, dir, rel string, v any) {
	t.Helper()
	b, err := trustfreeze.MarshalFile(v)
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, rel, b)
}

func writeRaw(t *testing.T, dir, rel string, b []byte) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRaw(t *testing.T, dir, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readManifest(t *testing.T, dir string) trustfreeze.Manifest {
	t.Helper()
	m, err := trustfreeze.ParseManifest(readRaw(t, dir, trustfreeze.ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// writeManifest plays an attacker who rewrites the unsigned manifest; with
// recompute the content digest is made consistent again.
func writeManifest(t *testing.T, dir string, m trustfreeze.Manifest, recompute bool) {
	t.Helper()
	if recompute {
		d, err := trustfreeze.ComputeContentDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		m.ContentDigest = d
	}
	writeJSONFile(t, dir, trustfreeze.ManifestFile, m)
}

// refreshEntry sets size and sha256 of the manifest entry rel from disk.
func refreshEntry(t *testing.T, dir string, m *trustfreeze.Manifest, rel string) {
	t.Helper()
	b := readRaw(t, dir, rel)
	for i := range m.Files {
		if m.Files[i].Path == rel {
			m.Files[i].Size = int64(len(b))
			m.Files[i].SHA256 = trustfreeze.SHA256Hex(b)
			return
		}
	}
	t.Fatalf("%s is not in the manifest", rel)
}

func readSig(t *testing.T, dir string) SignatureDoc {
	t.Helper()
	var d SignatureDoc
	if err := trustfreeze.UnmarshalCanonicalFile(readRaw(t, dir, trustfreeze.SignatureFile), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeSig(t *testing.T, dir string, d SignatureDoc) {
	t.Helper()
	writeJSONFile(t, dir, trustfreeze.SignatureFile, d)
}

func readApproval(t *testing.T, dir string) Approval {
	t.Helper()
	var a Approval
	if err := trustfreeze.UnmarshalCanonicalFile(readRaw(t, dir, trustfreeze.ApprovalFile), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// treeState returns path -> sha256 of every entry below dir (directories as
// "dir"), so any added, removed or changed entry shows.
func treeState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		switch {
		case info.IsDir():
			out[rel] = "dir"
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = trustfreeze.SHA256Hex(b) + " " + info.Mode().Perm().String()
		default:
			out[rel] = info.Mode().String()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("tree changed: %d entries before, %d after", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("tree changed at %s: %q -> %q", k, v, after[k])
		}
	}
}

// noSiblingsLike fails when dir contains an entry whose name starts with prefix.
func noSiblingsLike(t *testing.T, dir, prefix string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			t.Fatalf("leftover %s in %s", e.Name(), dir)
		}
	}
}
