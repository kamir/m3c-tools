package main

// Tests for the three contract gaps of `skillctl trust-freeze` (SPEC-0466
// section 5.9, SPEC-0470 sections 4.2 and 4.6, SPEC-0471 section 11.2):
// `capture --actor`, the clock-skew tolerance of `verify`, and the checks
// `doctor` really performs. Everything is injected: a fixed clock, a fake
// host, a fake command runner and a temp home; nothing real is read or run.

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/capture"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/seal"
)

// tfCheckRows returns the doctor checks by item.
func tfCheckRows(t *testing.T, doc map[string]any) map[string]map[string]any {
	t.Helper()
	rows, ok := doc["checks"].([]any)
	if !ok {
		t.Fatalf("doctor output has no checks list: %v", doc["checks"])
	}
	out := map[string]map[string]any{}
	for _, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("check row is not an object: %v", r)
		}
		item, _ := m["item"].(string)
		out[item] = m
	}
	return out
}

// tfRequireCheck asserts one check's status and returns its row.
func tfRequireCheck(t *testing.T, doc map[string]any, item, wantStatus string) map[string]any {
	t.Helper()
	row, ok := tfCheckRows(t, doc)[item]
	if !ok {
		t.Fatalf("doctor has no check %q; checks: %v", item, doc["checks"])
	}
	if got := row["status"]; got != wantStatus {
		t.Fatalf("check %s: status %v, want %s (row %v)", item, got, wantStatus, row)
	}
	if wantStatus == "not_checked" {
		if r, _ := row["reason"].(string); strings.TrimSpace(r) == "" {
			t.Fatalf("check %s is not_checked without a reason: %v", item, row)
		}
	}
	return row
}

// tfReadJSONFile decodes a bundle file.
func tfReadJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- Testpfad aus t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// tfToolProbe is a probe that names the executables it would use, so doctor
// can resolve them with LookPath without running anything.
type tfToolProbe struct {
	id    string
	tools []string
}

func (p tfToolProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID: p.id, Version: "1", Platforms: []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser, Sensitivity: trustfreeze.SensitivityPublic,
	}
}

func (p tfToolProbe) Support(context.Context, probe.HostContext) probe.SupportResult {
	return probe.Supported()
}

func (p tfToolProbe) Collect(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
}

// RequiredTools names the executables of this probe (capture.ToolUser).
func (p tfToolProbe) RequiredTools() []string { return p.tools }

// TestTrustFreezeCaptureActor: --actor records who ran the capture, the
// approval carries it, and the same-person half of the self-approval check
// then has an input (SPEC-0470 section 4.2, TF05-R7).
func TestTrustFreezeCaptureActor(t *testing.T) {
	e := newTFEnv(t)
	capDir := e.path("cap-actor")
	doc := e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir, "--actor", "alice")
	if doc["actor"] != "alice" {
		t.Fatalf("capture output actor %v, want alice", doc["actor"])
	}
	cap := tfReadJSONFile(t, filepath.Join(capDir, "capture.json"))
	meta, _ := cap["capture"].(map[string]any)
	if meta["actor"] != "alice" {
		t.Fatalf("capture.json capture.actor %v, want alice", meta["actor"])
	}

	base := e.path("base-actor")
	doc = e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capDir, "--output", base,
		"--reviewer", "alice", "--change-id", "CHG-0100", "--reason", "reviewed", "--key", e.priv)
	if !tfHas(tfWarningCodes(doc), "self_approval_same_person") {
		t.Fatalf("reviewer equals the capture actor but no same-person warning: %v", tfWarningCodes(doc))
	}
	app := tfReadJSONFile(t, filepath.Join(base, "approval.json"))
	ids, _ := app["identities"].(map[string]any)
	if ids["capture_actor"] != "alice" {
		t.Fatalf("approval identities.capture_actor %v, want alice", ids["capture_actor"])
	}
	e.runJSON(exitOK, tfResultOK, "verify", "--bundle", base, "--trusted-key", e.pub)

	// block refuses the same person.
	e.runJSON(exitGeneric, tfResultVerification, "baseline", "approve", "--capture", capDir,
		"--output", e.path("base-actor-blocked"), "--reviewer", "alice", "--change-id", "CHG-0101",
		"--reason", "reviewed", "--key", e.priv, "--self-approval", "block")
	if _, err := os.Stat(e.path("base-actor-blocked")); !os.IsNotExist(err) {
		t.Fatalf("blocked approval left a directory behind: %v", err)
	}

	// Another reviewer keeps the same-person check quiet.
	doc = e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capDir, "--output", e.path("base-actor-bob"),
		"--reviewer", "bob", "--change-id", "CHG-0102", "--reason", "reviewed", "--key", e.priv)
	if tfHas(tfWarningCodes(doc), "self_approval_same_person") {
		t.Fatalf("another reviewer must not be the same person: %v", tfWarningCodes(doc))
	}
}

// TestTrustFreezeCaptureActorValidated: the actor is an identifier
// (trustfreeze.ValidateIdentifier), refused with exit 2 before anything is
// written, because it enters the signed approval.
func TestTrustFreezeCaptureActorValidated(t *testing.T) {
	e := newTFEnv(t)
	for _, bad := range []string{"alice smith", "team/alice", "alice\u00a0smith", strings.Repeat("a", trustfreeze.MaxIdentifierLen+1)} {
		out := e.path("cap-bad-" + trustfreeze.SHA256Hex([]byte(bad))[:8])
		code, _, errOut := e.run("capture", "--profile", "walking-skeleton", "--output", out, "--actor", bad)
		if code != exitUsage {
			t.Fatalf("--actor %q: exit %d, want %d", bad, code, exitUsage)
		}
		if !strings.Contains(errOut, "--actor") {
			t.Fatalf("--actor %q: stderr does not name the flag: %s", bad, errOut)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("--actor %q wrote something: %v", bad, err)
		}
	}
	// No actor stays allowed and keeps today's behaviour.
	capDir := e.path("cap-no-actor")
	doc := e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	if _, ok := doc["actor"]; ok {
		t.Fatalf("capture without --actor reports an actor: %v", doc["actor"])
	}
	cap := tfReadJSONFile(t, filepath.Join(capDir, "capture.json"))
	meta, _ := cap["capture"].(map[string]any)
	if _, ok := meta["actor"]; ok {
		t.Fatalf("capture.json carries an actor without --actor: %v", meta)
	}
}

// TestTrustFreezeDoctorChecksClaudeRoots: doctor resolves the Claude
// configuration roots below the home root (read-only) and creates nothing
// (SPEC-0471 section 11.2).
func TestTrustFreezeDoctorChecksClaudeRoots(t *testing.T) {
	e := newTFEnv(t)
	home, err := e.deps.HomeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude", "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := tfHashTree(t, home)

	doc := e.runJSON(exitOK, tfResultOK, "doctor")
	row := tfRequireCheck(t, doc, "claude_roots", "ok")
	detail, _ := row["detail"].(string)
	for _, want := range []string{".claude", ".claude/skills"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("claude_roots detail %q does not name %s", detail, want)
		}
	}
	if !tfSameTree(before, tfHashTree(t, home)) {
		t.Fatal("doctor changed the home tree")
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "agents")); !os.IsNotExist(err) {
		t.Fatalf("doctor created a Claude root: %v", err)
	}
	for _, n := range tfNotCheckedItems(doc) {
		if n == "claude_roots" {
			t.Fatal("claude_roots is still reported as not_checked")
		}
	}
}

// tfNotCheckedItems returns the items doctor could not determine.
func tfNotCheckedItems(doc map[string]any) []string {
	var out []string
	rows, _ := doc["not_checked"].([]any)
	for _, r := range rows {
		m, _ := r.(map[string]any)
		s, _ := m["item"].(string)
		out = append(out, s)
	}
	return out
}

// TestTrustFreezeDoctorChecksOutputLocation: --output is tested for
// writability without writing a bundle, and doctor leaves nothing behind.
func TestTrustFreezeDoctorChecksOutputLocation(t *testing.T) {
	e := newTFEnv(t)

	// Without the flag there is nothing to check, honestly.
	doc := e.runJSON(exitOK, tfResultOK, "doctor")
	tfRequireCheck(t, doc, "output_location", "not_checked")

	// An existing, writable directory.
	dir := e.path("out-ok")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc = e.runJSON(exitOK, tfResultOK, "doctor", "--output", dir)
	tfRequireCheck(t, doc, "output_location", "ok")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("doctor left %d entries in the output location", len(entries))
	}

	// A target that does not exist yet, with an existing parent: the parent
	// is tested, and doctor does not create the target.
	missing := filepath.Join(dir, "bundle")
	doc = e.runJSON(exitOK, tfResultOK, "doctor", "--output", missing)
	tfRequireCheck(t, doc, "output_location", "ok")
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("doctor created the output location: %v", err)
	}

	// A target whose parent does not exist either: a problem, and nothing
	// above it is touched (O-T1).
	deep := filepath.Join(dir, "sub", "bundle")
	doc = e.runJSON(exitOK, tfResultOK, "doctor", "--output", deep)
	tfRequireCheck(t, doc, "output_location", "problem")
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("doctor wrote into the nearest existing ancestor: %v", entries)
	}

	// A target that is a file, not a directory.
	file := e.path("out-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc = e.runJSON(exitOK, tfResultOK, "doctor", "--output", file)
	tfRequireCheck(t, doc, "output_location", "problem")
}

// TestTrustFreezeDoctorChecksTools: per-probe tool availability is resolved
// with the runner's LookPath and nothing is executed.
func TestTrustFreezeDoctorChecksTools(t *testing.T) {
	e := newTFEnv(t)
	e.deps.Registry = func() (*probe.Registry, error) {
		reg := probe.NewRegistry()
		if err := reg.Register(tfToolProbe{id: "common.identity", tools: []string{"uname"}}); err != nil {
			return nil, err
		}
		return reg, nil
	}
	doc := e.runJSON(exitOK, tfResultOK, "doctor")
	row := tfRequireCheck(t, doc, "tools", "ok")
	if d, _ := row["detail"].(string); !strings.Contains(d, "uname") {
		t.Fatalf("tools detail %q does not name the resolved tool", d)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("doctor ran %d command(s); it must only resolve them", n)
	}

	// A tool that does not resolve is a problem, named with its probe.
	e.deps.Registry = func() (*probe.Registry, error) {
		reg := probe.NewRegistry()
		if err := reg.Register(tfToolProbe{id: "common.identity", tools: []string{"uname", "absent-tool"}}); err != nil {
			return nil, err
		}
		return reg, nil
	}
	doc = e.runJSON(exitOK, tfResultOK, "doctor")
	row = tfRequireCheck(t, doc, "tools", "problem")
	d, _ := row["detail"].(string)
	if !strings.Contains(d, "absent-tool") || !strings.Contains(d, "common.identity") {
		t.Fatalf("tools detail %q does not name the probe and its missing tool", d)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("doctor ran %d command(s); it must only resolve them", n)
	}
}

// TestTrustFreezeDoctorChecksFileRoots: doctor names everything a capture may
// open in ONE place, and says which reader each root belongs to.
//
// The capture has two file seams (review of T-03b, finding 3): the engine's
// restricted reader with capture.DefaultAllowedRoots, and the own reader of
// linux.executables with linux.ExecutableRoots, which the first list does not
// contain. An operator asking "what can this thing open" had to read the manual
// to learn about the second one.
func TestTrustFreezeDoctorChecksFileRoots(t *testing.T) {
	e := newTFEnv(t)
	doc := e.runJSON(exitOK, tfResultOK, "doctor")
	row := tfRequireCheck(t, doc, "file_roots", "ok")
	detail, _ := row["detail"].(string)
	reader := capture.DefaultAllowedRoots("linux")
	own := capture.ProbeOwnedRoots("linux")
	if len(reader) == 0 || len(own) == 0 {
		t.Fatalf("this test needs both root lists; reader %v, own %v", reader, own)
	}
	for _, want := range append(append([]string{}, reader...), own...) {
		if !strings.Contains(detail, want) {
			t.Errorf("file_roots detail %q does not name the root %s", detail, want)
		}
	}
	// The detail says WHICH reader the second list belongs to, or naming it
	// would be worse than not naming it: a reader would take it for a root of
	// the restricted reader.
	if !strings.Contains(detail, "linux.executables") {
		t.Errorf("file_roots detail %q does not say which probe opens the second list", detail)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("doctor ran %d command(s) for this check; it reads nothing", n)
	}
}

// TestTrustFreezeVerifyClockSkewFromTrustPolicy: the tolerance is a trust
// policy field, so `verify --trust-policy` carries it into the CLI path, and
// 0s restores the exact comparison (SPEC-0470 section 4.6).
func TestTrustFreezeVerifyClockSkewFromTrustPolicy(t *testing.T) {
	e := newTFEnv(t)
	capDir, base := e.path("cap-skew"), e.path("base-skew")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	exp := tfTestTime.Add(time.Hour).Format(time.RFC3339)
	e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capDir, "--output", base,
		"--reviewer", "bob", "--change-id", "CHG-0200", "--reason", "reviewed", "--key", e.priv, "--expires-at", exp)

	pubKey, err := os.ReadFile(e.pub)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pubKey)
	if block == nil {
		t.Fatal("public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519", pub)
	}
	writePolicy := func(name, field, skew string) string {
		p := e.path(name)
		body := "schema_version: trust-freeze/trust-policy/v1\n" +
			field + ": " + skew + "\n" +
			"trusted_keys:\n  - public_key: " + base64.StdEncoding.EncodeToString(raw) + "\n"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	wide := writePolicy("policy-wide.yaml", "max_expiry_skew", "2h")
	off := writePolicy("policy-off.yaml", "max_expiry_skew", "0s")
	approval := writePolicy("policy-approval.yaml", "max_clock_skew", "2h")

	saved := e.deps.Clock
	defer func() { e.deps.Clock = saved }()
	// One hour past expires_at: inside a two-hour expiry tolerance, outside
	// no tolerance at all. The approval tolerance does not reach the expiry
	// check, however wide it is (R-T2).
	e.deps.Clock = trustfreeze.FixedClock{T: tfTestTime.Add(2 * time.Hour)}
	e.runJSON(exitOK, tfResultOK, "verify", "--bundle", base, "--trust-policy", wide)
	for _, pol := range []string{off, approval} {
		doc := e.runJSON(exitGeneric, tfResultVerification, "verify", "--bundle", base, "--trust-policy", pol)
		if !tfHas(tfFailureReasons(doc), "expired") {
			t.Fatalf("%s: failures %v, want expired", filepath.Base(pol), tfFailureReasons(doc))
		}
	}
	// A negative tolerance is a usage error on either field: the policy does
	// not load.
	for _, field := range []string{"max_clock_skew", "max_expiry_skew"} {
		bad := writePolicy("policy-bad-"+field+".yaml", field, "-1s")
		if code, _, errOut := e.run("verify", "--bundle", base, "--trust-policy", bad); code != exitUsage {
			t.Fatalf("negative %s: exit %d, want %d (%s)", field, code, exitUsage, errOut)
		}
	}
}

// tfManualSkewDefault finds the default tolerance the manual states for
// max_clock_skew, and tfManualSkewExample the value of its policy example.
// tfManualExpiryDefault and tfManualExpiryExample do the same for the expiry
// tolerance, which is a separate setting with a separate default (R-T2).
var (
	tfManualSkewDefault   = regexp.MustCompile("`max_clock_skew` \\(default `([^`]+)`")
	tfManualSkewExample   = regexp.MustCompile(`(?m)^max_clock_skew:[ \t]+(\S+)`)
	tfManualExpiryDefault = regexp.MustCompile("`max_expiry_skew` \\(default `([^`]+)`")
	tfManualExpiryExample = regexp.MustCompile(`(?m)^max_expiry_skew:[ \t]+(\S+)`)
)

// TestTrustFreezeClockSkewDefaultIsDocumented: the default tolerance the code
// applies is the one the manual states, and the manual's own policy example
// shows it. A default only the code knows is not a documented default.
func TestTrustFreezeClockSkewDefaultIsDocumented(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "v2", "referenz", "manual-skillctl.md")
	b, err := os.ReadFile(path) // #nosec G304 -- fester Pfad auf das Manual im Repo
	if err != nil {
		t.Fatal(err)
	}
	manual := string(b)
	for _, tc := range []struct {
		what  string
		field string
		re    *regexp.Regexp
		want  time.Duration
	}{
		{"the documented default", "max_clock_skew", tfManualSkewDefault, seal.DefaultMaxClockSkew},
		{"the trust policy example", "max_clock_skew", tfManualSkewExample, seal.DefaultMaxClockSkew},
		{"the documented expiry default", "max_expiry_skew", tfManualExpiryDefault, seal.DefaultMaxExpirySkew},
		{"the trust policy expiry example", "max_expiry_skew", tfManualExpiryExample, seal.DefaultMaxExpirySkew},
	} {
		m := tc.re.FindStringSubmatch(manual)
		if m == nil {
			t.Fatalf("%s: the manual does not name %s (pattern %s)", tc.what, tc.field, tc.re)
		}
		got, err := time.ParseDuration(m[1])
		if err != nil {
			t.Fatalf("%s: the manual says %q, which is not a duration: %v", tc.what, m[1], err)
		}
		if got != tc.want {
			t.Fatalf("%s: the manual says %s, the code applies %s", tc.what, got, tc.want)
		}
		// The planted-occurrence control: a search that cannot fail proves
		// nothing, so the same pattern must miss a manual without the value.
		if tc.re.MatchString(strings.ReplaceAll(manual, tc.field, tc.field+"_x")) {
			t.Fatalf("%s: the pattern matches a manual that does not name the field", tc.what)
		}
	}
}
