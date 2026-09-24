package main

// Hardening tests of the trust-freeze CLI from the adversarial review of the
// walking skeleton: secret material in approval text, output locations inside
// existing bundles, result classes of refused inputs and usage errors in JSON
// mode. Same synthetic environment as the acceptance test (newTFEnv).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/common"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// TF05-R8, SPEC-0470 section 4.5: `--reason @<private key>` (the operator meant
// --key) and other secret-looking approval text are refused as usage errors
// before anything is signed or written, and no output echoes the key.
func TestTrustFreezeApproveRefusesSecretApprovalText(t *testing.T) {
	e := newTFEnv(t)
	cap1 := e.path("cap1")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1)
	before := tfHashTree(t, cap1)

	approve := func(out string, extra ...string) []string {
		args := []string{"baseline", "approve", "--capture", cap1, "--output", out, "--key", e.priv,
			"--reviewer", "alice", "--change-id", "CHG-0003", "--reason", "reviewed"}
		return append(args, extra...)
	}

	t.Run("reason file is the key file", func(t *testing.T) {
		out := e.path("base-keyreason")
		doc := e.runJSON(exitUsage, tfResultUsage, approve(out, "--reason", "@"+e.priv)...)
		if msg, _ := doc["error"].(string); !strings.Contains(msg, "--key file") {
			t.Fatalf("error %q, want the --key file refusal", msg)
		}
		tfMustNotExist(t, out)
	})
	t.Run("reason file is a copy of the key", func(t *testing.T) {
		// Outside e.root: tfScanKeyMaterial treats every file there as output.
		cp := filepath.Join(t.TempDir(), "notes.txt")
		b, err := os.ReadFile(e.priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cp, b, 0o600); err != nil {
			t.Fatal(err)
		}
		out := e.path("base-keycopy")
		doc := e.runJSON(exitUsage, tfResultUsage, approve(out, "--reason", "@"+cp)...)
		if msg, _ := doc["error"].(string); !strings.Contains(msg, "reason") || !strings.Contains(msg, "private_key") {
			t.Fatalf("error %q, want a reason refusal naming private_key", msg)
		}
		tfMustNotExist(t, out)
	})
	t.Run("change id with a token", func(t *testing.T) {
		out := e.path("base-token")
		doc := e.runJSON(exitUsage, tfResultUsage, approve(out, "--change-id", "CHG-1 https://t.example/x?token=abcdef0123456789")...)
		if msg, _ := doc["error"].(string); !strings.Contains(msg, "change_id") || strings.Contains(msg, "abcdef0123456789") {
			t.Fatalf("error %q, want a change_id refusal without the token", msg)
		}
		tfMustNotExist(t, out)
	})
	t.Run("reason with a password pair", func(t *testing.T) {
		out := e.path("base-password")
		e.runJSON(exitUsage, tfResultUsage, approve(out, "--reason", "ok password=hunter2hunter2")...)
		tfMustNotExist(t, out)
	})

	if !tfSameTree(before, tfHashTree(t, cap1)) {
		t.Fatal("the refusals modified the capture directory")
	}
	for i, o := range e.outputs {
		if strings.Contains(o, "hunter2hunter2") || strings.Contains(o, "abcdef0123456789") {
			t.Fatalf("command output #%d echoes a secret:\n%s", i, o)
		}
	}
	tfScanKeyMaterial(t, e)
}

// TF05-R2, SPEC-0466 section 5.7: no command writes into an existing bundle.
// diff, capture, baseline approve and report all refuse an output location
// inside a baseline or capture (execution_error, exit 1), and the enclosing
// bundle still verifies afterwards.
func TestTrustFreezeOutputNeverInsideABundle(t *testing.T) {
	e := newTFEnv(t)
	cap1, cap2, base, other := e.path("cap1"), e.path("cap2"), e.path("base1"), e.path("base-other")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1)
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap2)
	approve := func(capDir, out string) []string {
		return []string{"baseline", "approve", "--capture", capDir, "--output", out, "--key", e.priv,
			"--reviewer", "alice", "--change-id", "CHG-0004", "--reason", "reviewed"}
	}
	e.runJSON(exitOK, tfResultOK, approve(cap1, base)...)
	e.runJSON(exitOK, tfResultOK, approve(cap1, other)...)
	trees := map[string]map[string]string{}
	for _, d := range []string{cap1, cap2, base, other} {
		trees[d] = tfHashTree(t, d)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"diff output inside the baseline", []string{"diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--output", filepath.Join(base, "diff-out")}},
		{"diff output deep inside the baseline", []string{"diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--output", filepath.Join(base, "evidence", "d")}},
		{"diff output inside the current capture", []string{"diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--output", filepath.Join(cap2, "d")}},
		{"diff output inside an unrelated baseline", []string{"diff", "--baseline", base, "--current", cap2, "--trusted-key", e.pub, "--output", filepath.Join(other, "d")}},
		{"capture output inside a baseline", []string{"capture", "--profile", "walking-skeleton", "--output", filepath.Join(base, "state", "c")}},
		{"approve output inside another baseline", approve(cap2, filepath.Join(other, "state", "nested"))},
		{"report output inside another baseline", []string{"report", "--input", cap2, "--output", filepath.Join(other, "r.json")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := e.runJSON(exitGeneric, tfResultExecution, tc.args...)
			if msg, _ := doc["error"].(string); !strings.Contains(msg, "inside") {
				t.Fatalf("error %q does not explain the refusal", msg)
			}
		})
	}
	for d, before := range trees {
		if !tfSameTree(before, tfHashTree(t, d)) {
			t.Fatalf("%s was modified", d)
		}
	}
	e.runJSON(exitOK, tfResultOK, "verify", "--bundle", base, "--trusted-key", e.pub)
	e.runJSON(exitOK, tfResultOK, "verify", "--bundle", other, "--trusted-key", e.pub)
	e.runJSON(exitOK, tfResultOK, "verify", "--bundle", cap2)
}

// SPEC-0467 section 5.6: capture --force replaces only a trust-freeze
// capture that verifies; user files next to a copied manifest.json survive.
func TestTrustFreezeCaptureForceKeepsUserFiles(t *testing.T) {
	e := newTFEnv(t)
	cap1 := e.path("cap1")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1)
	mb, err := os.ReadFile(filepath.Join(cap1, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	victim := e.path("victim")
	for rel, b := range map[string][]byte{"precious.txt": []byte("keep"), "notes/todo.md": []byte("keep too"), "manifest.json": mb} {
		p := filepath.Join(victim, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := tfHashTree(t, victim)
	e.runJSON(exitGeneric, tfResultExecution, "capture", "--profile", "walking-skeleton", "--output", victim, "--force")
	if !tfSameTree(before, tfHashTree(t, victim)) {
		t.Fatal("capture --force changed a directory that is not a verified capture bundle")
	}
	// A real capture is still replaced.
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1, "--force")
}

// tfRemanifest plays a forger with write access: it rewrites files of a
// bundle and rebuilds its manifest so that integrity holds again.
func tfRemanifest(t *testing.T, dir string, rewrite func(dir string)) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, trustfreeze.ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	old, err := trustfreeze.ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	rewrite(dir)
	if err := os.Remove(filepath.Join(dir, trustfreeze.ManifestFile)); err != nil {
		t.Fatal(err)
	}
	created, err := trustfreeze.ParseTime(old.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, err := trustfreeze.BuildManifest(dir, trustfreeze.ManifestHeader{Kind: old.Kind, BundleID: old.BundleID, CreatedAt: created, Subject: old.Subject})
	if err != nil {
		t.Fatal(err)
	}
	mb, err := trustfreeze.MarshalFile(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, trustfreeze.ManifestFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := trustfreeze.VerifyDir(dir); !res.OK {
		t.Fatalf("forged bundle should pass integrity: %v", res.Err())
	}
}

// tfEditJSON rewrites one canonical JSON file of a bundle through its type.
func tfEditJSON[T any](t *testing.T, path string, edit func(*T)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc T
	if err := trustfreeze.UnmarshalCanonicalFile(b, &doc); err != nil {
		t.Fatal(err)
	}
	edit(&doc)
	out, err := trustfreeze.MarshalFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// SPEC-0466 section 5.9, SPEC-0470 section 4.1 step 1, TF01-AC6: an input that
// fails the capture checks of baseline approve is a verification_failure, as
// verify calls it: a baseline or a diff passed as --capture, a capture whose
// declared completeness contradicts its probe list, and a capture whose probe
// result contradicts its capture.json. The forged captures pass integrity;
// verify, diff and approve all refuse them.
func TestTrustFreezeRefusedInputsAreVerificationFailures(t *testing.T) {
	e := newTFEnv(t)
	cap1, base, d1 := e.path("cap1"), e.path("base1"), e.path("diff1")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", cap1)
	approve := func(capDir, out string) []string {
		return []string{"baseline", "approve", "--capture", capDir, "--output", out, "--key", e.priv,
			"--reviewer", "alice", "--change-id", "CHG-0005", "--reason", "reviewed", "--self-approval", "allow"}
	}
	e.runJSON(exitOK, tfResultOK, approve(cap1, base)...)
	e.runJSON(exitOK, tfResultOK, "diff", "--baseline", base, "--current", cap1, "--trusted-key", e.pub, "--output", d1)

	// capture.json says complete, the one required probe says failed.
	capCompl := e.path("cap-completeness")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capCompl)
	tfRemanifest(t, capCompl, func(dir string) {
		tfEditJSON(t, filepath.Join(dir, "capture.json"), func(doc *trustfreeze.CaptureDoc) {
			doc.Probes[0].Status = trustfreeze.StatusFailed
		})
	})
	// The probe result says permission_denied; capture.json still says
	// captured and complete (honesty-F2).
	capPD := e.path("cap-permission-denied")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "walking-skeleton", "--output", capPD)
	tfRemanifest(t, capPD, func(dir string) {
		tfEditJSON(t, filepath.Join(dir, "probes", "common.identity.json"), func(r *trustfreeze.ProbeResult) {
			r.Status = trustfreeze.StatusPermissionDenied
			r.Reason = "permission denied for os_name"
		})
	})

	for _, in := range []struct{ name, dir string }{
		{"a baseline as --capture", base},
		{"a diff bundle as --capture", d1},
		{"a capture with a completeness mismatch", capCompl},
		{"a capture whose probe result contradicts it", capPD},
	} {
		t.Run(in.name, func(t *testing.T) {
			out := e.path("base-from-" + filepath.Base(in.dir))
			e.runJSON(exitGeneric, tfResultVerification, approve(in.dir, out)...)
			tfMustNotExist(t, out)
		})
	}
	for _, forged := range []string{capCompl, capPD} {
		doc := e.runJSON(exitGeneric, tfResultVerification, "verify", "--bundle", forged)
		if !tfHas(tfFailureReasons(doc), "capture_invalid") {
			t.Fatalf("verify %s: failures %v, want capture_invalid", forged, tfFailureReasons(doc))
		}
		doc = e.runJSON(exitGeneric, tfResultVerification, "diff", "--baseline", base, "--current", forged, "--trusted-key", e.pub)
		if _, ok := doc["diff"]; ok || doc["input"] != "current" {
			t.Fatalf("diff compared a forged current bundle: %v", doc)
		}
	}
}

// tfStubProbe is a linux probe that always captures its artifacts.
type tfStubProbe struct {
	id   string
	arts []trustfreeze.Artifact
}

func (p tfStubProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{ID: p.id, Version: "1", Platforms: []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser, Sensitivity: trustfreeze.SensitivityPublic}
}

func (p tfStubProbe) Support(context.Context, probe.HostContext) probe.SupportResult {
	return probe.Supported()
}

func (p tfStubProbe) Collect(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured, NormalizedState: append([]trustfreeze.Artifact(nil), p.arts...)}
}

// SPEC-0469 section 4.2, TF04-R7: skipping an optional probe with
// --exclude-probe is recorded in the bundle, so diff judges it like any other
// collection gap (medium for an optional probe under default-v0) instead of
// seeing only the artifacts it would have reported go unobserved.
func TestTrustFreezeExcludedOptionalProbeIsAGap(t *testing.T) {
	e := newTFEnv(t)
	e.deps.Registry = func() (*probe.Registry, error) {
		// Only the identity probe is the real one; every other probe of the
		// profile is a stub here (see the decisions test).
		reg := probe.NewRegistry()
		if err := common.Register(reg); err != nil {
			return nil, err
		}
		for _, id := range []string{"linux.packages", "linux.users", "linux.sudo", "linux.ssh", "linux.systemd",
			"linux.executables", "linux.network.listeners", "linux.network.routes", "linux.dns", "linux.firewall",
			"linux.mounts", "linux.containers", "common.claude"} {
			if err := reg.Register(tfStubProbe{id: id}); err != nil {
				return nil, err
			}
		}
		git := tfStubProbe{id: "common.git", arts: []trustfreeze.Artifact{{
			ID: "project/git/abc", Type: "git", Scope: "project", Source: "common.git", State: trustfreeze.StateObserved,
			Attributes:  map[string]string{"remote": "origin"},
			Provenance:  trustfreeze.Provenance{Method: "command", Confidence: trustfreeze.ConfidenceProven, ObservedAt: trustfreeze.FormatTime(tfTestTime)},
			Sensitivity: trustfreeze.SensitivityPublic,
		}}}
		return reg, reg.Register(git)
	}
	full, excl, base := e.path("cap-full"), e.path("cap-excluded"), e.path("base")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", full)
	e.runJSON(exitOK, tfResultOK, "baseline", "approve", "--capture", full, "--output", base, "--key", e.priv,
		"--reviewer", "alice", "--change-id", "CHG-0006", "--reason", "reviewed")

	doc := e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--exclude-probe", "common.git", "--output", excl)
	recorded := false
	probes, _ := doc["probes"].([]any)
	for _, p := range probes {
		m, _ := p.(map[string]any)
		if m["probe_id"] == "common.git" {
			recorded = m["status"] == "unsupported" && m["reason"] == trustfreeze.ReasonExcludedByOperator
		}
	}
	if !recorded {
		t.Fatalf("capture does not record the excluded probe: %v", probes)
	}

	doc = e.runJSON(exitGeneric, tfResultDrift, "diff", "--baseline", base, "--current", excl, "--trusted-key", e.pub, "--fail-on", "medium")
	v, _ := doc["verdict"].(map[string]any)
	gap := false
	findings, _ := v["findings"].([]any)
	for _, f := range findings {
		m, _ := f.(map[string]any)
		if m["kind"] == "collection_gap" && m["probe_id"] == "common.git" && m["severity"] == "medium" {
			gap = true
		}
	}
	if !gap || v["highest_severity"] != "medium" {
		t.Fatalf("findings %v, want a medium collection_gap for common.git", findings)
	}
}

// SPEC-0466 section 5.9: every trust-freeze subsection of the manual documents
// its exit codes, doctor included (which exits 0 also when gaps are
// expected).
func TestTrustFreezeManualHasExitLinePerSubcommand(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "referenz", "manual-skillctl.md"))
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]string{}
	var current string
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "#### `trust-freeze "):
			name, _, _ := strings.Cut(strings.TrimPrefix(line, "#### `trust-freeze "), "`")
			current = name
		case strings.HasPrefix(line, "#"):
			current = ""
		case current != "":
			sections[current] += line + "\n"
		}
	}
	for _, sub := range []string{"doctor", "capture", "baseline approve", "verify", "diff", "report"} {
		body, ok := sections[sub]
		if !ok {
			t.Errorf("manual has no subsection for trust-freeze %s", sub)
			continue
		}
		if !strings.Contains(body, "\nExit: `0`") {
			t.Errorf("manual subsection trust-freeze %s has no Exit line", sub)
		}
	}
	if !strings.Contains(sections["doctor"], "also when gaps are expected") {
		t.Error("the doctor Exit line does not say that expected gaps still exit 0")
	}
}
