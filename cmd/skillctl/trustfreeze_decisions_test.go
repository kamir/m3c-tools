package main

// Tests of the decision round after the walking-skeleton review: a subject
// mismatch in diff (SPEC-0469 section 4.2), not_applicable probes, probes
// that were not captured and their artifacts (SPEC-0469 sections 4.2 and
// 4.5), report as a pure projection (SPEC-0469 section 4.7), flag-named input
// files that fail to load (SPEC-0466 section 5.9) and the charset of reviewer
// and change ids (SPEC-0470 section 4.2). Same synthetic environment as the
// acceptance test (newTFEnv).

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/capture"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// tfUseHostname makes every later command of e observe another host name.
func tfUseHostname(e *tfTestEnv, name string) {
	orig := e.deps.Host
	e.deps.Host = func() probe.HostContext {
		h := orig()
		h.Hostname = func() (string, error) { return name, nil }
		return h
	}
}

// tfDiffChanges returns the changes of a diff JSON document keyed by
// "<kind>:<artifact id or probe id>" (subject_changed has neither: key
// "subject_changed:").
func tfDiffChanges(t *testing.T, doc map[string]any) map[string]map[string]any {
	t.Helper()
	df, ok := doc["diff"].(map[string]any)
	if !ok {
		t.Fatalf("no diff in %v", doc)
	}
	out := map[string]map[string]any{}
	changes, _ := df["changes"].([]any)
	for _, c := range changes {
		m, _ := c.(map[string]any)
		key, _ := m["artifact_id"].(string)
		if key == "" {
			key, _ = m["probe_id"].(string)
		}
		k, _ := m["kind"].(string)
		out[k+":"+key] = m
	}
	return out
}

// tfDiffKeys returns the sorted keys of tfDiffChanges.
func tfDiffKeys(t *testing.T, doc map[string]any) []string {
	t.Helper()
	var keys []string
	for k := range tfDiffChanges(t, doc) {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// tfVerdictFindings returns the findings of a diff JSON document as
// "<finding id>=<severity>@<rule id>".
func tfVerdictFindings(t *testing.T, doc map[string]any) []string {
	t.Helper()
	v, ok := doc["verdict"].(map[string]any)
	if !ok {
		t.Fatalf("no verdict in %v", doc)
	}
	var out []string
	fs, _ := v["findings"].([]any)
	for _, f := range fs {
		m, _ := f.(map[string]any)
		out = append(out, m["id"].(string)+"="+m["severity"].(string)+"@"+m["rule_id"].(string))
	}
	slices.Sort(out)
	return out
}

// R-A: a baseline of one device diffed against a capture of another device
// is a subject_changed finding, high under default-v0, so it blocks at the
// default threshold. --allow-subject-mismatch keeps the finding but rates it
// info and records the opt-in in the diff document.
func TestTrustFreezeDiffSubjectMismatch(t *testing.T) {
	e := newTFEnv(t)
	capA, base, capB := e.path("cap-a"), e.path("base-a"), e.path("cap-b")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capA)
	e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capA, "--output", base, "--key", e.priv,
		"--reviewer", "alice", "--change-id", "CHG-0007", "--reason", "reviewed")
	tfUseHostname(e, "host-b.example")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capB)
	subjA, subjB := trustfreeze.SubjectID("linux", tfTestHost), trustfreeze.SubjectID("linux", "host-b.example")

	doc := e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", capB, "--trusted-key", e.pub)
	if df, _ := doc["diff"].(map[string]any); df["allow_subject_mismatch"] != false {
		t.Fatalf("allow_subject_mismatch = %v, want false", df["allow_subject_mismatch"])
	}
	sc, ok := tfDiffChanges(t, doc)["subject_changed:"]
	if !ok {
		t.Fatalf("no subject_changed change: %q", tfDiffKeys(t, doc))
	}
	if sc["before_subject_id"] != subjA || sc["after_subject_id"] != subjB {
		t.Fatalf("subject_changed = %v, want %s -> %s", sc, subjA, subjB)
	}
	if got := tfVerdictFindings(t, doc); !slices.Contains(got, "subject_changed:"+subjB+"=high@TF-POL-SUBJECT-CHANGED") {
		t.Fatalf("findings %q, want a high TF-POL-SUBJECT-CHANGED finding", got)
	}

	doc = e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", capB, "--trusted-key", e.pub, "--allow-subject-mismatch")
	if df, _ := doc["diff"].(map[string]any); df["allow_subject_mismatch"] != true {
		t.Fatalf("allow_subject_mismatch = %v, want true", df["allow_subject_mismatch"])
	}
	if sc := tfDiffChanges(t, doc)["subject_changed:"]; sc == nil || sc["subject_mismatch_allowed"] != true {
		t.Fatalf("subject_changed with the opt-in = %v", sc)
	}
	if got := tfVerdictFindings(t, doc); !slices.Contains(got, "subject_changed:"+subjB+"=info@TF-POL-SUBJECT-CHANGED-ALLOWED") {
		t.Fatalf("findings %q, want an info TF-POL-SUBJECT-CHANGED-ALLOWED finding", got)
	}
	code, out, _ := e.run("diff", "--baseline", base, "--current", capB, "--trusted-key", e.pub, "--allow-subject-mismatch")
	if code != exitOK || !strings.Contains(out, "subject_changed") || !strings.Contains(out, "--allow-subject-mismatch") {
		t.Fatalf("text diff with the opt-in: exit %d\n%s", code, out)
	}

	// Same device with the opt-in: nothing to allow, the opt-in is recorded.
	doc = e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", capA, "--trusted-key", e.pub, "--allow-subject-mismatch")
	if df, _ := doc["diff"].(map[string]any); df["allow_subject_mismatch"] != true {
		t.Fatalf("allow_subject_mismatch = %v on the same subject", df["allow_subject_mismatch"])
	}
	if keys := tfDiffKeys(t, doc); len(keys) != 0 {
		t.Fatalf("same subject: changes %q, want none", keys)
	}
}

// tfScript drives tfScriptedProbe: per probe id the support result, the
// result status and reason, and the artifacts of the next capture.
type tfScript struct {
	mu sync.Mutex
	by map[string]tfScripted
}

type tfScripted struct {
	support probe.SupportResult
	status  trustfreeze.ProbeStatus
	reason  string
	arts    []trustfreeze.Artifact
}

func (s *tfScript) set(id string, v tfScripted) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.by[id] = v
}

func (s *tfScript) get(id string) tfScripted {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.by[id]
	if !ok {
		return tfScripted{support: probe.Supported(), status: trustfreeze.StatusCaptured}
	}
	return v
}

// tfScriptedProbe is a linux probe whose outcome the test scripts per run.
type tfScriptedProbe struct {
	id     string
	script *tfScript
}

func (p tfScriptedProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{ID: p.id, Version: "1", Platforms: []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser, Sensitivity: trustfreeze.SensitivityPublic}
}

func (p tfScriptedProbe) Support(context.Context, probe.HostContext) probe.SupportResult {
	return p.script.get(p.id).support
}

func (p tfScriptedProbe) Collect(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
	s := p.script.get(p.id)
	return trustfreeze.ProbeResult{Status: s.status, Reason: s.reason, NormalizedState: append([]trustfreeze.Artifact(nil), s.arts...)}
}

// tfScriptedEnv is newTFEnv with every non-identity probe of ubuntu-bastion
// registered as a scripted probe (captured without artifacts by default).
func tfScriptedEnv(t *testing.T) (*tfTestEnv, *tfScript) {
	e := newTFEnv(t)
	s := &tfScript{by: map[string]tfScripted{}}
	e.deps.Registry = func() (*probe.Registry, error) {
		reg, err := capture.DefaultRegistry()
		if err != nil {
			return nil, err
		}
		for _, id := range []string{"linux.packages", "linux.users", "linux.sudo", "linux.ssh.effective", "linux.systemd",
			"linux.network.listeners", "linux.firewall", "linux.mounts", "common.git", "common.containers", "common.claude"} {
			if err := reg.Register(tfScriptedProbe{id: id, script: s}); err != nil {
				return nil, err
			}
		}
		return reg, nil
	}
	return e, s
}

// tfArtifact is one observed synthetic artifact of probe source.
func tfArtifact(id, source string, attrs map[string]string) trustfreeze.Artifact {
	return trustfreeze.Artifact{
		ID: id, Type: "fixture", Scope: "device", Source: source, State: trustfreeze.StateObserved,
		Attributes:  attrs,
		Provenance:  trustfreeze.Provenance{Method: "command", Confidence: trustfreeze.ConfidenceProven, ObservedAt: trustfreeze.FormatTime(tfTestTime)},
		Sensitivity: trustfreeze.SensitivityPublic,
	}
}

func (e *tfTestEnv) approveBastion(capDir, out string) {
	e.t.Helper()
	e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capDir, "--output", out, "--key", e.priv,
		"--reviewer", "alice", "--change-id", "CHG-0008", "--reason", "reviewed")
}

// R-B: a required probe that is not_applicable with a reason is its own
// collection_gap with cause not_applicable, rated info by default-v0, so a
// baseline diffed against itself (and against the capture it was approved
// from) exits 0.
func TestTrustFreezeNotApplicableProbeDoesNotBlock(t *testing.T) {
	e, s := tfScriptedEnv(t)
	s.set("linux.sudo", tfScripted{support: probe.NotApplicable("sudo is not installed")})
	capDir, base := e.path("cap"), e.path("base")
	doc := e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", capDir)
	if c, _ := doc["completeness"].(map[string]any); c["status"] != "complete" {
		t.Fatalf("a not_applicable probe with a reason keeps the capture complete: %v", doc["completeness"])
	}
	e.approveBastion(capDir, base)

	for _, current := range []string{base, capDir} {
		doc = e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", current, "--trusted-key", e.pub)
		if keys := tfDiffKeys(t, doc); !slices.Equal(keys, []string{"collection_gap:linux.sudo"}) {
			t.Fatalf("diff against %s: changes %q, want the one not_applicable gap", filepath.Base(current), keys)
		}
		gap, _ := tfDiffChanges(t, doc)["collection_gap:linux.sudo"]["gap"].(map[string]any)
		if gap["cause"] != "not_applicable" || gap["status"] != "not_applicable" || gap["reason"] != "sudo is not installed" || gap["required"] != true {
			t.Fatalf("gap = %v, want cause not_applicable of a required probe", gap)
		}
		if got := tfVerdictFindings(t, doc); !slices.Equal(got, []string{"collection_gap:linux.sudo=info@TF-POL-GAP-NOT-APPLICABLE"}) {
			t.Fatalf("findings %q", got)
		}
	}

	// Planted control: the same probe failing is still critical.
	s.set("linux.sudo", tfScripted{support: probe.Unavailable("sudo binary missing")})
	failing := e.path("cap-failing")
	e.runJSON(exitGeneric, tfResultIncomplete, "capture", "--profile", "ubuntu-bastion", "--output", failing)
	doc = e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", failing, "--trusted-key", e.pub)
	if got := tfVerdictFindings(t, doc); !slices.Contains(got, "collection_gap:linux.sudo=critical@TF-POL-GAP-REQUIRED") {
		t.Fatalf("control: findings %q", got)
	}
}

// R-B: the artifacts of a probe that was not captured in the current bundle
// are not_observed, never removed or changed; changed names only attributes
// observed on both sides.
func TestTrustFreezeArtifactsOfUncapturedProbesAreNotObserved(t *testing.T) {
	e, s := tfScriptedEnv(t)
	mount := tfArtifact("linux/mount/root", "linux.mounts", map[string]string{"fstype": "ext4", "options": "rw"})
	user := tfArtifact("linux/user/alice", "linux.users", map[string]string{"uid": "1000", "shell": "/bin/bash"})
	s.set("linux.mounts", tfScripted{support: probe.Supported(), status: trustfreeze.StatusCaptured, arts: []trustfreeze.Artifact{mount}})
	s.set("linux.users", tfScripted{support: probe.Supported(), status: trustfreeze.StatusCaptured, arts: []trustfreeze.Artifact{user}})
	capDir, base, cur := e.path("cap"), e.path("base"), e.path("cur")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", capDir)
	e.approveBastion(capDir, base)

	// linux.mounts: the tool is missing now. linux.users: partial, the shell
	// was not read and the uid really changed.
	s.set("linux.mounts", tfScripted{support: probe.Unavailable("findmnt missing")})
	partial := tfArtifact("linux/user/alice", "linux.users", map[string]string{"uid": "1001"})
	s.set("linux.users", tfScripted{support: probe.Supported(), status: trustfreeze.StatusPartial, reason: "shell not read", arts: []trustfreeze.Artifact{partial}})
	e.runJSON(exitGeneric, tfResultIncomplete, "capture", "--profile", "ubuntu-bastion", "--output", cur)

	doc := e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", cur, "--trusted-key", e.pub)
	want := []string{
		"changed:linux/user/alice",
		"collection_gap:linux.mounts",
		"collection_gap:linux.users",
		"not_observed:linux/mount/root",
		"not_observed:linux/user/alice",
	}
	if got := tfDiffKeys(t, doc); !slices.Equal(got, want) {
		t.Fatalf("changes %q, want %q", got, want)
	}
	ch := tfDiffChanges(t, doc)
	if attrs, _ := ch["changed:linux/user/alice"]["changed_attributes"].([]any); len(attrs) != 1 || attrs[0] != "uid" {
		t.Fatalf("changed attributes %v, want [uid] (shell was not observed)", attrs)
	}
	if no := ch["not_observed:linux/user/alice"]; no["probe_id"] != "linux.users" || !slices.Equal(tfStrings(no["unobserved_attributes"]), []string{"shell"}) {
		t.Fatalf("not_observed alice = %v", no)
	}
	if no := ch["not_observed:linux/mount/root"]; no["probe_id"] != "linux.mounts" || no["after_digest"] != nil ||
		!slices.Equal(tfStrings(no["unobserved_attributes"]), []string{"fstype", "options"}) {
		t.Fatalf("not_observed mount = %v", no)
	}
}

// R-B: a probe that moves between captured and not_applicable is a real
// change and is reported in both directions.
func TestTrustFreezeApplicabilityChangeIsReported(t *testing.T) {
	e, s := tfScriptedEnv(t)
	fw := tfArtifact("linux/firewall/ufw", "linux.firewall", map[string]string{"active": "true"})
	s.set("linux.firewall", tfScripted{support: probe.Supported(), status: trustfreeze.StatusCaptured, arts: []trustfreeze.Artifact{fw}})
	capOn, baseOn, capOff, baseOff := e.path("cap-on"), e.path("base-on"), e.path("cap-off"), e.path("base-off")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", capOn)
	e.approveBastion(capOn, baseOn)
	s.set("linux.firewall", tfScripted{support: probe.NotApplicable("no firewall is installed")})
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", capOff)
	e.approveBastion(capOff, baseOff)

	doc := e.runJSON(exitOK, tfResultOK, "diff", "--baseline", baseOn, "--current", capOff, "--trusted-key", e.pub)
	want := []string{"applicability_changed:linux.firewall", "collection_gap:linux.firewall", "removed:linux/firewall/ufw"}
	if got := tfDiffKeys(t, doc); !slices.Equal(got, want) {
		t.Fatalf("captured to not_applicable: changes %q, want %q", got, want)
	}
	ac := tfDiffChanges(t, doc)["applicability_changed:linux.firewall"]
	if ac["before_status"] != "captured" || ac["after_status"] != "not_applicable" {
		t.Fatalf("applicability_changed = %v", ac)
	}
	if got := tfVerdictFindings(t, doc); !slices.Contains(got, "applicability_changed:linux.firewall=low@TF-POL-APPLICABILITY") {
		t.Fatalf("findings %q", got)
	}
	e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", baseOn, "--current", capOff, "--trusted-key", e.pub, "--fail-on", "low")

	doc = e.runJSON(exitOK, tfResultOK, "diff", "--baseline", baseOff, "--current", capOn, "--trusted-key", e.pub)
	want = []string{"added:linux/firewall/ufw", "applicability_changed:linux.firewall"}
	if got := tfDiffKeys(t, doc); !slices.Equal(got, want) {
		t.Fatalf("not_applicable to captured: changes %q, want %q", got, want)
	}
	ac = tfDiffChanges(t, doc)["applicability_changed:linux.firewall"]
	if ac["before_status"] != "not_applicable" || ac["after_status"] != "captured" {
		t.Fatalf("applicability_changed = %v", ac)
	}
}

func tfStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// R-D: report projects a baseline and evaluates neither signature, trust nor
// expiry: the report of an unchanged baseline is the same before and after
// its expiry, and says where the evaluation lives (verify).
func TestTrustFreezeReportIsAPureProjection(t *testing.T) {
	e := newTFEnv(t)
	capDir, base := e.path("cap"), e.path("base")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capDir, "--output", base, "--key", e.priv,
		"--reviewer", "alice", "--change-id", "CHG-0009", "--reason", "reviewed", "--expires-at", tfTestTime.Add(time.Hour).Format(time.RFC3339))

	var reports [][]byte
	for i, now := range []time.Time{tfTestTime, tfTestTime.Add(2 * time.Hour)} {
		e.deps.Clock = trustfreeze.FixedClock{T: now}
		out := e.path("report-" + string(rune('a'+i)) + ".json")
		doc := e.runJSON(exitOK, tfResultOK, "report", "--input", base, "--output", out)
		sig, _ := doc["signature"].(map[string]any)
		if sig["result"] != "not_evaluated" || sig["verify_with"] != "skillctl trust-freeze verify" {
			t.Fatalf("report signature section %v, want not_evaluated with a pointer to verify", sig)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, b)
	}
	if !bytes.Equal(reports[0], reports[1]) {
		t.Fatalf("the report of an unchanged baseline changed with the clock:\n%s\n---\n%s", reports[0], reports[1])
	}
	for _, word := range []string{"key_not_trusted", "expired", `"pass"`, `"fail"`} {
		if bytes.Contains(reports[0], []byte(word)) {
			t.Fatalf("report carries an evaluation (%s):\n%s", word, reports[0])
		}
	}
	code, out, _ := e.run("report", "--input", base, "--output", e.path("report-text.json"), "--format", "json")
	if code != exitOK || !strings.Contains(out, "not_evaluated") {
		t.Fatalf("report: exit %d\n%s", code, out)
	}

	// The report path of the CLI never reaches the seal package.
	f, err := parser.ParseFile(token.NewFileSet(), "trustfreeze_cmds.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || (fn.Name.Name != "tfReport" && fn.Name.Name != "tfReportTarget") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "seal" {
					t.Errorf("%s references seal.%s: report must not evaluate signatures", fn.Name.Name, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

// O-5: every flag-named input file that fails to load is a usage_error
// (exit 2): --key, --trusted-key, --trust-policy, --policy and --reason @file.
func TestTrustFreezeUnloadableFlagFilesAreUsageErrors(t *testing.T) {
	e := newTFEnv(t)
	capDir, base := e.path("cap"), e.path("base")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", capDir, "--output", base, "--key", e.priv,
		"--reviewer", "alice", "--change-id", "CHG-0010", "--reason", "reviewed")
	missing := e.path("absent.pem")
	garbage := e.path("garbage.pem")
	if err := os.WriteFile(garbage, []byte("this is not a key, a policy or a PEM block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	approve := func(out string, extra ...string) []string {
		args := []string{"baseline", "approve", "--capture", capDir, "--output", out,
			"--reviewer", "alice", "--change-id", "CHG-0011", "--reason", "reviewed"}
		return append(args, extra...)
	}
	type tc struct {
		name, flag string
		args       []string
		out        string
	}
	var cases []tc
	for _, bad := range []struct{ name, path string }{{"missing", missing}, {"garbage", garbage}} {
		out := e.path("base-" + bad.name)
		cases = append(cases,
			tc{"approve --key " + bad.name, "--key", approve(out, "--key", bad.path), out},
			tc{"approve --reason @" + bad.name, "--reason", approve(e.path("base-r-"+bad.name), "--key", e.priv, "--reason", "@"+bad.path+".absent"), e.path("base-r-" + bad.name)},
			tc{"verify --trusted-key " + bad.name, "--trusted-key", []string{"verify", "--bundle", base, "--trusted-key", bad.path}, ""},
			tc{"verify --trust-policy " + bad.name, "--trust-policy", []string{"verify", "--bundle", base, "--trust-policy", bad.path}, ""},
			tc{"diff --trusted-key " + bad.name, "--trusted-key", []string{"diff", "--baseline", base, "--current", capDir, "--trusted-key", bad.path}, ""},
			tc{"diff --trust-policy " + bad.name, "--trust-policy", []string{"diff", "--baseline", base, "--current", capDir, "--trusted-key", e.pub, "--trust-policy", bad.path}, ""},
			tc{"diff --policy " + bad.name, "--policy", []string{"diff", "--baseline", base, "--current", capDir, "--trusted-key", e.pub, "--policy", bad.path}, ""},
		)
	}
	if runtime.GOOS != "windows" {
		// A readable-by-others private key is refused by the signer's mode
		// check (no mode bits on Windows). Outside e.root: tfScanKeyMaterial
		// treats every file there as output.
		loose := filepath.Join(t.TempDir(), "loose.priv")
		b, err := os.ReadFile(e.priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(loose, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(loose, 0o644); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, tc{"approve --key with mode 0644", "--key", approve(e.path("base-loose"), "--key", loose), e.path("base-loose")})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := e.runJSON(exitUsage, tfResultUsage, c.args...)
			if msg, _ := doc["error"].(string); !strings.Contains(msg, c.flag) {
				t.Fatalf("error %q does not name %s", msg, c.flag)
			}
			if c.out != "" {
				tfMustNotExist(t, c.out)
			}
		})
	}
	tfScanKeyMaterial(t, e)
}

// O-3: reviewer and change ids use a conservative charset (ASCII letters,
// digits and ._-@+:) and a length limit; anything else is refused as a usage
// error before anything is signed or written.
func TestTrustFreezeApproveRefusesUnsafeIdentifiers(t *testing.T) {
	e := newTFEnv(t)
	capDir := e.path("cap")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capDir)
	before := tfHashTree(t, capDir)
	approve := func(out, reviewer, change string) []string {
		return []string{"baseline", "approve", "--capture", capDir, "--output", out, "--key", e.priv,
			"--reviewer", reviewer, "--change-id", change, "--reason", "reviewed"}
	}
	bad := []struct{ name, reviewer, change, field string }{
		{"reviewer with a space", "Alice Smith", "CHG-1", "reviewer"},
		{"reviewer with a slash", "corp/alice", "CHG-1", "reviewer"},
		{"reviewer not ASCII", "b\u00f8b", "CHG-1", "reviewer"},
		{"reviewer too long", strings.Repeat("a", 129), "CHG-1", "reviewer"},
		{"change id with a hash", "alice", "#1234", "change_id"},
		{"change id with a URL", "alice", "https://tickets.example/CHG-1", "change_id"},
		{"change id too long", "alice", strings.Repeat("1", 129), "change_id"},
	}
	for i, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			out := e.path("base-bad-" + string(rune('a'+i)))
			doc := e.runJSON(exitUsage, tfResultUsage, approve(out, c.reviewer, c.change)...)
			if msg, _ := doc["error"].(string); !strings.Contains(msg, c.field) {
				t.Fatalf("error %q does not name %s", msg, c.field)
			}
			tfMustNotExist(t, out)
		})
	}
	// The whole allowed charset, at the length limit, is accepted.
	good := "Az09._-@+:" + strings.Repeat("x", 118)
	e.runJSON(exitOK, tfResultOK, approve(e.path("base-good"), good, "id:"+good[:125])...)
	if !tfSameTree(before, tfHashTree(t, capDir)) {
		t.Fatal("approve modified the capture directory")
	}
}

// tfBareDecision matches a bare design decision number (a D and one or two
// digits) that is not qualified by a SPEC id (SPEC-0202 D1 names another
// SPEC's decision).
var tfBareDecision = regexp.MustCompile(`(^|[^A-Za-z0-9_-])D[0-9]{1,2}\b`)

var tfQualifiedDecision = regexp.MustCompile(`SPEC-[0-9]{4} D[0-9]{1,2}\b`)

// tfPrivateOrderRef matches a reference to the private order document by
// description instead of a SPEC section.
// The pattern is assembled from pieces so this file does not match itself.
var tfPrivateOrderRef = regexp.MustCompile(`(?i)\border` + ` sec` + `tion\b|\bthe or` + `der's\b`)

// O-6: code and test comments of the Trust Freeze tree cite SPEC sections
// (SPEC-0469 section 4.2), never bare decision numbers of the implementation
// playbook or sections of the private order.
func TestTrustFreezeCommentsCiteSpecSections(t *testing.T) {
	scan := func(name string, b []byte) []string {
		var hits []string
		for i, line := range strings.Split(string(b), "\n") {
			clean := tfQualifiedDecision.ReplaceAllString(line, "")
			if tfBareDecision.MatchString(clean) || tfPrivateOrderRef.MatchString(clean) {
				hits = append(hits, name+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return hits
	}
	// Planted occurrences must be found, or an empty result proves nothing.
	for _, planted := range []string{"// design decision D" + "18", "// (D" + "22)", "// order sec" + "tion 6.7", "// the or" + "der's CLI"} {
		if len(scan("planted", []byte(planted))) != 1 {
			t.Fatalf("the scan misses the planted %q", planted)
		}
	}
	for _, ok := range []string{"// SPEC-0202 D1, separate keys", "// SPEC-0469 section 4.2", "// TF04-AC7: the order of the input"} {
		if hits := scan("control", []byte(ok)); len(hits) != 0 {
			t.Fatalf("the scan flags %q", ok)
		}
	}
	var files []string
	cmdFiles, err := filepath.Glob("trustfreeze_*.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, cmdFiles...)
	root := filepath.Join("..", "..", "pkg", "skillctl", "trustfreeze")
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".go") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".json")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 50 {
		t.Fatalf("scanned only %d files; the scan is not looking at the tree", len(files))
	}
	var hits []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, scan(filepath.ToSlash(f), b)...)
	}
	if len(hits) > 0 {
		t.Fatalf("%d bare decision or private order references:\n%s", len(hits), strings.Join(hits, "\n"))
	}
	t.Logf("scanned %d files", len(files))
}
