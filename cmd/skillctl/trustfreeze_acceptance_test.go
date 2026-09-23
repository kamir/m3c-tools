package main

// End-to-end acceptance of the Trust Freeze walking skeleton (SPEC-0466 to
// SPEC-0471, PR-1 acceptance path) through the CLI dispatcher: synthetic host,
// capture, explicit approval, baseline, offline verify PASS, one flipped byte,
// verify FAIL, restore, changed capture, deterministic diff with a stable
// finding, fail-on exit codes, report. Everything is injected: a fixed clock,
// a fake command runner, an in-memory os-release, a synthetic host name, a
// temp HOME/USERPROFILE and a key from a fixed synthetic seed.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/capture"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/seal"
)

// tfTestSeed is a synthetic ed25519 seed. It is not and never was a real key.
var tfTestSeed = bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)

const (
	tfTestHost      = "host-a.example"
	tfTestOSRelease = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"
	tfTestKernel    = "6.8.0-45-generic\n"
)

var tfTestTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// tfTestEnv is one synthetic host with its home, key and outputs.
type tfTestEnv struct {
	t         *testing.T
	root      string
	osRelease []byte
	runner    *probe.FakeRunner
	priv, pub string
	deps      tfDeps
	// outputs collects every stdout and stderr, for the key material scan.
	outputs []string
}

func newTFEnv(t *testing.T) *tfTestEnv {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	// Never the real home: homeroot reads HOME on Unix and %USERPROFILE% on
	// Windows, so both point into the temp tree.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	e := &tfTestEnv{t: t, root: root, osRelease: []byte(tfTestOSRelease)}
	e.runner = probe.NewFakeRunner().Script("uname", []string{"-r"}, probe.FakeResponse{Stdout: []byte(tfTestKernel)}).
		Script("uname", []string{"-m"}, probe.FakeResponse{Stdout: []byte("x86_64\n")})
	e.priv, e.pub = writeTFTestKey(t, filepath.Join(root, "keys"))
	e.deps = tfDeps{
		Clock: trustfreeze.FixedClock{T: tfTestTime},
		Host: func() probe.HostContext {
			return probe.HostContext{
				GOOS:      "linux",
				GOARCH:    "amd64",
				Hostname:  func() (string, error) { return tfTestHost, nil },
				Files:     probe.FakeFiles{Files: map[string][]byte{"/etc/os-release": append([]byte(nil), e.osRelease...)}},
				Runner:    e.runner,
				Clock:     trustfreeze.FixedClock{T: tfTestTime},
				Privilege: probe.PrivilegeUser,
			}
		},
		Registry: capture.DefaultRegistry,
		HomeRoot: userHome,
		Version:  "test",
	}
	return e
}

// writeTFTestKey writes the synthetic key pair in the `skillctl keygen`
// format: PEM PKCS#8 private key with mode 0600, PEM SPKI public key.
func writeTFTestKey(t *testing.T, dir string) (priv, pub string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(tfTestSeed)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	priv, pub = filepath.Join(dir, "tf-test.priv"), filepath.Join(dir, "tf-test.pub")
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func (e *tfTestEnv) path(elem ...string) string {
	return filepath.Join(append([]string{e.root}, elem...)...)
}

func (e *tfTestEnv) run(args ...string) (int, string, string) {
	e.t.Helper()
	var out, errOut bytes.Buffer
	code := runTrustFreezeWith(context.Background(), e.deps, args, &out, &errOut)
	e.outputs = append(e.outputs, out.String(), errOut.String())
	return code, out.String(), errOut.String()
}

// runJSON runs a command with --format json, checks the exit code and that
// the output is one JSON document carrying result_class, and returns it.
func (e *tfTestEnv) runJSON(wantCode int, wantClass string, args ...string) map[string]any {
	e.t.Helper()
	code, out, errOut := e.run(append(args, "--format", "json")...)
	if code != wantCode {
		e.t.Fatalf("%v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, code, wantCode, out, errOut)
	}
	doc := decodeTFJSON(e.t, out)
	if got := doc["result_class"]; got != wantClass {
		e.t.Fatalf("%v: result_class %v, want %s\n%s", args, got, wantClass, out)
	}
	return doc
}

func decodeTFJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, s)
	}
	if dec.More() {
		t.Fatalf("output holds more than one JSON document:\n%s", s)
	}
	if _, ok := doc["result_class"]; !ok {
		t.Fatalf("JSON output without result_class:\n%s", s)
	}
	return doc
}

// tfHashTree returns path -> sha256 of every regular file below dir.
func tfHashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		sum := sha256.Sum256(b)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func tfSameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func tfFlipByte(t *testing.T, path string) (restore func()) {
	t.Helper()
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mut := append([]byte(nil), orig...)
	mut[len(mut)/2] ^= 0x01
	if err := os.WriteFile(path, mut, 0o600); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.WriteFile(path, orig, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func tfFailureReasons(doc map[string]any) []string {
	var out []string
	fs, _ := doc["failures"].([]any)
	for _, f := range fs {
		m, _ := f.(map[string]any)
		r, _ := m["reason"].(string)
		if ir, _ := m["integrity_reason"].(string); ir != "" {
			r += "/" + ir
		}
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func tfWarningCodes(doc map[string]any) []string {
	var out []string
	ws, _ := doc["warnings"].([]any)
	for _, w := range ws {
		m, _ := w.(map[string]any)
		c, _ := m["code"].(string)
		out = append(out, c)
	}
	return out
}

func tfHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func tfMustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Fatalf("%s exists, want nothing written", path)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".tf-staging-") {
			t.Fatalf("staging directory %s left behind", en.Name())
		}
	}
}

// TestTrustFreezeAcceptanceWalkingSkeleton is the PR-1 acceptance path
// (TF05-AC1, TF05-AC2, TF05-R6, SPEC-0469 R1/R8/R9, SPEC-0466 AC1).
func TestTrustFreezeAcceptanceWalkingSkeleton(t *testing.T) {
	e := newTFEnv(t)
	cap1, base, cap2 := e.path("cap1"), e.path("base1"), e.path("cap2")

	// 1. Capture: kind capture, complete, never an approval or a signature.
	doc := e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1)
	if doc["kind"] != "capture" {
		t.Fatalf("capture kind %v", doc["kind"])
	}
	if c, _ := doc["completeness"].(map[string]any); c["status"] != "complete" {
		t.Fatalf("capture completeness %v", doc["completeness"])
	}
	captureDigest, _ := doc["content_digest"].(string)
	if !strings.HasPrefix(captureDigest, "sha256:") {
		t.Fatalf("capture content_digest %q", captureDigest)
	}
	for _, p := range []string{trustfreeze.ApprovalFile, trustfreeze.SignaturesDir} {
		if _, err := os.Stat(filepath.Join(cap1, filepath.FromSlash(p))); err == nil {
			t.Fatalf("capture carries %s (TF05-R2: only baseline approve creates a baseline)", p)
		}
	}
	if b, err := os.ReadFile(filepath.Join(cap1, "state", "device.json")); err != nil || !bytes.Contains(b, []byte(`"os_version": "24.04"`)) {
		t.Fatalf("state/device.json lacks the synthetic os_version: %v\n%s", err, b)
	}

	// 2. Explicit approval from a CRLF reason file; the capture stays
	// byte-identical (SPEC-0470 section 4.1) and the same-device self-approval
	// is warned about under the default mode (TF05-R7).
	reasonFile := e.path("reason.txt")
	if err := os.WriteFile(reasonFile, []byte("Walking skeleton baseline.\r\nReviewed the identity probe.\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := tfHashTree(t, cap1)
	doc = e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", cap1, "--output", base,
		"--reviewer", "alice", "--change-id", "CHG-0001", "--reason", "@"+reasonFile, "--key", e.priv)
	if doc["kind"] != "baseline" || doc["capture_digest"] != captureDigest {
		t.Fatalf("approve: kind %v capture_digest %v, want baseline and %s", doc["kind"], doc["capture_digest"], captureDigest)
	}
	if !tfHas(tfWarningCodes(doc), "self_approval_same_device") {
		t.Fatalf("approve warnings %v, want self_approval_same_device", tfWarningCodes(doc))
	}
	if ap, _ := doc["approval"].(map[string]any); ap["reason"] != "Walking skeleton baseline.\nReviewed the identity probe." {
		t.Fatalf("approval reason %q: CRLF must become LF (TF05-R4)", ap["reason"])
	}
	if !tfSameTree(before, tfHashTree(t, cap1)) {
		t.Fatal("baseline approve modified the capture directory")
	}
	baselineDigest, _ := doc["content_digest"].(string)

	// 3. Offline verify PASS with the trusted key (TF05-AC1).
	doc = e.runJSON(exitOK, tfResultOK, "verify", "--bundle", base, "--trusted-key", e.pub)
	if doc["ok"] != true || doc["signature_valid"] != true || doc["key_trusted"] != true || doc["scope"] != "baseline" {
		t.Fatalf("verify: %v", doc)
	}
	// Without trust material the same baseline fails as key_not_trusted, the
	// cryptographic result still reported (SPEC-0470 section 4.6).
	doc = e.runJSON(exitGeneric, tfResultVerification, "verify", "--bundle", base)
	if doc["signature_valid"] != true || !tfHas(tfFailureReasons(doc), "key_not_trusted") {
		t.Fatalf("verify without trusted key: %v", doc)
	}

	// 4. One flipped byte in a manifested file: verify FAIL (TF05-AC2).
	restore := tfFlipByte(t, filepath.Join(base, "state", "device.json"))
	doc = e.runJSON(exitGeneric, tfResultVerification, "verify", "--bundle", base, "--trusted-key", e.pub)
	if !tfHas(tfFailureReasons(doc), "integrity/digest_mismatch") {
		t.Fatalf("flipped byte: failures %v, want integrity/digest_mismatch", tfFailureReasons(doc))
	}
	// diff refuses the tampered baseline and writes nothing (SPEC-0469 R1).
	refused := e.path("diff-refused")
	doc = e.runJSON(exitGeneric, tfResultVerification, "diff", "--baseline", base, "--current", cap1, "--trusted-key", e.pub, "--output", refused)
	if doc["input"] != "baseline" {
		t.Fatalf("diff refusal names input %v, want baseline", doc["input"])
	}
	if _, ok := doc["diff"]; ok {
		t.Fatal("diff compared a baseline that failed verification")
	}
	tfMustNotExist(t, refused)

	// 5. Restore: PASS again.
	restore()
	e.runJSON(exitOK, tfResultOK, "verify", "--bundle", base, "--trusted-key", e.pub)

	// 6. A changed capture: the host now reports another os_version.
	e.osRelease = []byte(strings.Replace(tfTestOSRelease, `VERSION_ID="24.04"`, `VERSION_ID="24.10"`, 1))
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap2)

	// 7. Diff: exactly one stable finding, device/os changed in os_version,
	// medium under the default policy, which fails on high (exit 0).
	code, first, errOut := e.run("diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--format", "json")
	if code != exitOK {
		t.Fatalf("diff: exit %d\n%s\n%s", code, first, errOut)
	}
	doc = decodeTFJSON(t, first)
	if doc["result_class"] != tfResultOK {
		t.Fatalf("diff result_class %v", doc["result_class"])
	}
	df, _ := doc["diff"].(map[string]any)
	changes, _ := df["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("diff changes %v, want exactly one", changes)
	}
	ch, _ := changes[0].(map[string]any)
	if ch["kind"] != "changed" || ch["artifact_id"] != "device/os" {
		t.Fatalf("diff change %v, want changed device/os", ch)
	}
	if attrs, _ := ch["changed_attributes"].([]any); len(attrs) != 1 || attrs[0] != "os_version" {
		t.Fatalf("changed attributes %v, want [os_version]", ch["changed_attributes"])
	}
	if bl, _ := df["baseline"].(map[string]any); bl["content_digest"] != baselineDigest {
		t.Fatalf("diff baseline ref %v, want %s", bl["content_digest"], baselineDigest)
	}
	v, _ := doc["verdict"].(map[string]any)
	findings, _ := v["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings %v, want one", findings)
	}
	fd, _ := findings[0].(map[string]any)
	if fd["severity"] != "medium" || fd["rule_id"] != "TF-POL-DEVICE-IDENTITY" || fd["artifact_id"] != "device/os" {
		t.Fatalf("finding %v, want medium TF-POL-DEVICE-IDENTITY on device/os", fd)
	}
	if v["fail_on"] != "high" || v["threshold_exceeded"] != false {
		t.Fatalf("verdict fail_on %v exceeded %v, want high/false", v["fail_on"], v["threshold_exceeded"])
	}
	findingID := fd["id"]

	// 8. Deterministic: the same inputs give the same bytes (SPEC-0469 R9).
	_, second, _ := e.run("diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--format", "json")
	if first != second {
		t.Fatalf("diff output is not deterministic:\n%s\n---\n%s", first, second)
	}

	// 9. --fail-on drives only the exit code (SPEC-0469 R8).
	doc = e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--fail-on", "medium")
	v, _ = doc["verdict"].(map[string]any)
	fds, _ := v["findings"].([]any)
	if f0, _ := fds[0].(map[string]any); f0["id"] != findingID {
		t.Fatalf("finding id changed with --fail-on: %v vs %v", f0["id"], findingID)
	}
	e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--fail-on", "none")
	e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--fail-on", "low")
	e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--fail-on", "critical")

	// 10. Diff bundles: two runs give byte-identical documents, and the
	// bundle verifies (integrity scope: a diff carries no signature).
	d1, d2 := e.path("diff1"), e.path("diff2")
	e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--output", d1)
	e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--output", d2)
	if !tfSameTree(tfHashTree(t, d1), tfHashTree(t, d2)) {
		t.Fatal("two diff bundles of the same inputs differ")
	}
	for _, f := range []string{"diff.json", "verdict.json", "policy/evaluated-policy.json", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(d1, filepath.FromSlash(f))); err != nil {
			t.Fatalf("diff bundle lacks %s: %v", f, err)
		}
	}
	doc = e.runJSON(exitOK, tfResultOK, "verify", "--bundle", d1)
	if doc["kind"] != "diff" || doc["scope"] != "integrity" {
		t.Fatalf("verify diff bundle: %v", doc)
	}
	doc = e.runJSON(exitOK, tfResultOK, "verify", "--bundle", cap2)
	if doc["kind"] != "capture" || doc["scope"] != "integrity" {
		t.Fatalf("verify capture bundle: %v", doc)
	}

	// 11. Reports are deterministic, for the baseline and for the diff bundle.
	for _, in := range []string{base, d1, cap1} {
		r1, r2 := e.path("r1-"+filepath.Base(in)+".json"), e.path("r2-"+filepath.Base(in)+".json")
		e.runJSON(exitOK, tfResultOK, "report", "--input", in, "--output", r1)
		e.runJSON(exitOK, tfResultOK, "report", "--input", in, "--output", r2)
		b1, err1 := os.ReadFile(r1)
		b2, err2 := os.ReadFile(r2)
		if err1 != nil || err2 != nil || !bytes.Equal(b1, b2) {
			t.Fatalf("report of %s is not deterministic (%v, %v)", in, err1, err2)
		}
		// A report file is never overwritten.
		e.runJSON(exitGeneric, tfResultExecution, "report", "--input", in, "--output", r1)
	}

	// 12. No private key material anywhere: bundles, reports, command output
	// (TF05-R8).
	tfScanKeyMaterial(t, e)
}

// tfScanKeyMaterial fails when any produced file or output carries the
// synthetic private key in any encoding.
func tfScanKeyMaterial(t *testing.T, e *tfTestEnv) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(tfTestSeed)
	needles := map[string][]byte{
		"PEM private key block": []byte("PRIVATE KEY"),
		"raw seed":              tfTestSeed,
		"hex seed":              []byte(hex.EncodeToString(tfTestSeed)),
		"base64 seed":           []byte(base64.StdEncoding.EncodeToString(tfTestSeed)),
		"base64 private key":    []byte(base64.StdEncoding.EncodeToString(key)),
	}
	check := func(where string, b []byte) {
		for name, n := range needles {
			if bytes.Contains(b, n) {
				t.Fatalf("%s contains the %s (TF05-R8)", where, name)
			}
		}
	}
	err := filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == e.priv {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		check(p, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range e.outputs {
		check("command output #"+strconv.Itoa(i), []byte(o))
	}
}

// TestTrustFreezeAcceptanceRefusals covers the refusals of the acceptance
// path: nothing is written when a mandatory input is missing (TF05-AC5), a
// blocked self-approval stops the approval (TF05-AC6), and expiry follows
// the injected clock (TF05-AC7).
func TestTrustFreezeAcceptanceRefusals(t *testing.T) {
	e := newTFEnv(t)
	cap1 := e.path("cap1")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1)
	before := tfHashTree(t, cap1)

	t.Run("capture without --output", func(t *testing.T) {
		code, _, errOut := e.run("capture", "--profile", "walking-skeleton")
		if code != exitUsage || !strings.Contains(errOut, "--output is required") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		e.runJSON(exitUsage, tfResultUsage, "capture", "--profile", "walking-skeleton")
	})

	approve := func(out string, drop string, extra ...string) []string {
		args := []string{"baseline", "approve", "--capture", cap1, "--output", out, "--key", e.priv}
		fields := map[string]string{"--reviewer": "alice", "--change-id": "CHG-0002", "--reason": "reviewed"}
		for _, f := range []string{"--reviewer", "--change-id", "--reason"} {
			if f != drop {
				args = append(args, f, fields[f])
			}
		}
		return append(args, extra...)
	}
	for _, missing := range []string{"--reviewer", "--change-id", "--reason"} {
		t.Run("approve without "+missing, func(t *testing.T) {
			out := e.path("base-no" + strings.TrimPrefix(missing, "--"))
			doc := e.runJSON(exitUsage, tfResultUsage, approve(out, missing)...)
			if msg, _ := doc["error"].(string); !strings.Contains(msg, strings.ReplaceAll(strings.TrimPrefix(missing, "--"), "-", "_")) {
				t.Fatalf("error %q does not name the missing field", msg)
			}
			tfMustNotExist(t, out)
		})
	}
	t.Run("approve with a blank reviewer", func(t *testing.T) {
		out := e.path("base-blank")
		e.runJSON(exitUsage, tfResultUsage, append(approve(out, "--reviewer"), "--reviewer", "  \t ")...)
		tfMustNotExist(t, out)
	})
	t.Run("self-approval block", func(t *testing.T) {
		out := e.path("base-blocked")
		doc := e.runJSON(exitGeneric, tfResultVerification, approve(out, "", "--self-approval", "block")...)
		if msg, _ := doc["error"].(string); !strings.Contains(msg, "self_approval_same_device") {
			t.Fatalf("error %q, want self_approval_same_device", msg)
		}
		tfMustNotExist(t, out)
	})
	t.Run("self-approval allow", func(t *testing.T) {
		out := e.path("base-allowed")
		doc := e.runJSON(exitOK, tfResultOK, approve(out, "", "--self-approval", "allow")...)
		if codes := tfWarningCodes(doc); len(codes) != 0 {
			t.Fatalf("allow mode warnings %v, want none", codes)
		}
	})
	t.Run("approve refuses an existing baseline", func(t *testing.T) {
		out := e.path("base-once")
		e.runJSON(exitOK, tfResultOK, approve(out, "")...)
		first := tfHashTree(t, out)
		e.runJSON(exitGeneric, tfResultExecution, approve(out, "")...)
		if !tfSameTree(first, tfHashTree(t, out)) {
			t.Fatal("a second approve changed an existing baseline")
		}
	})
	t.Run("expiry follows the injected clock", func(t *testing.T) {
		out := e.path("base-expiring")
		exp := tfTestTime.Add(time.Hour).Format(time.RFC3339)
		e.runJSON(exitOK, tfResultOK, approve(out, "", "--expires-at", exp)...)
		e.runJSON(exitOK, tfResultOK, "verify", "--bundle", out, "--trusted-key", e.pub)
		saved := e.deps.Clock
		defer func() { e.deps.Clock = saved }()
		e.deps.Clock = trustfreeze.FixedClock{T: tfTestTime.Add(time.Hour)}
		e.runJSON(exitOK, tfResultOK, "verify", "--bundle", out, "--trusted-key", e.pub)
		// Past expires_at the baseline is expired: the default expiry
		// tolerance is zero (seal.DefaultMaxExpirySkew), and the approval
		// tolerance does not reach this check (R-T2).
		e.deps.Clock = trustfreeze.FixedClock{T: tfTestTime.Add(time.Hour + time.Nanosecond)}
		doc := e.runJSON(exitGeneric, tfResultVerification, "verify", "--bundle", out, "--trusted-key", e.pub)
		if !tfHas(tfFailureReasons(doc), "expired") {
			t.Fatalf("failures %v, want expired", tfFailureReasons(doc))
		}
		e.deps.Clock = trustfreeze.FixedClock{T: tfTestTime.Add(time.Hour + seal.DefaultMaxClockSkew)}
		doc = e.runJSON(exitGeneric, tfResultVerification, "verify", "--bundle", out, "--trusted-key", e.pub)
		if !tfHas(tfFailureReasons(doc), "expired") {
			t.Fatalf("the approval tolerance extended the expiry: failures %v", tfFailureReasons(doc))
		}
	})
	t.Run("an incomplete capture exits 1 and is still written", func(t *testing.T) {
		out := e.path("cap-incomplete")
		doc := e.runJSON(exitGeneric, tfResultIncomplete, "capture", "--profile", "walking-skeleton", "--exclude-probe", "common.identity", "--output", out)
		if c, _ := doc["completeness"].(map[string]any); c["status"] != "incomplete" {
			t.Fatalf("completeness %v", doc["completeness"])
		}
		if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
			t.Fatalf("incomplete capture not written: %v", err)
		}
		// Diff against it: a required collection gap is critical and blocks
		// under the default policy (SPEC-0469 AC5).
		base := e.path("base-for-gap")
		e.runJSON(exitOK, tfResultOK, approve(base, "")...)
		doc = e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", out, "--trusted-key", e.pub)
		v, _ := doc["verdict"].(map[string]any)
		if v["highest_severity"] != "critical" {
			t.Fatalf("highest severity %v, want critical", v["highest_severity"])
		}
	})
	t.Run("a profile with unimplemented probes is incomplete", func(t *testing.T) {
		doc := e.runJSON(exitGeneric, tfResultIncomplete, "capture", "--profile", "agentic-workstation", "--output", e.path("cap-agentic"))
		probes, _ := doc["probes"].([]any)
		found := false
		for _, p := range probes {
			m, _ := p.(map[string]any)
			if m["status"] == "unsupported" && m["reason"] == trustfreeze.ReasonNotImplemented {
				found = true
			}
		}
		if !found {
			t.Fatalf("no probe recorded unsupported/not_implemented: %v", probes)
		}
	})
	t.Run("diff refuses a capture as baseline and a diff as current", func(t *testing.T) {
		e.runJSON(exitGeneric, tfResultVerification, "diff", "--baseline", cap1, "--current", cap1, "--trusted-key", e.pub)
		base := e.path("base-kinds")
		e.runJSON(exitOK, tfResultOK, approve(base, "")...)
		d := e.path("diff-kinds")
		e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", cap1, "--trusted-key", e.pub, "--output", d)
		doc := e.runJSON(exitGeneric, tfResultVerification, "diff", "--baseline", base, "--current", d, "--trusted-key", e.pub)
		if doc["input"] != "current" || !tfHas(tfFailureReasons(doc), "wrong_kind") {
			t.Fatalf("diff with a diff as current: %v", doc)
		}
	})

	if !tfSameTree(before, tfHashTree(t, cap1)) {
		t.Fatal("the refusals modified the capture directory")
	}
	tfScanKeyMaterial(t, e)
}
