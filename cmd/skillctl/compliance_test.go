package main

// SPEC-0276 R5 — tests for `skillctl compliance report`.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// makeSkillDir creates <root>/<name>/ with a SKILL.md and, if govern != "", a
// .skillctl-offline.json carrying a BundleMeta at that governance level.
func makeSkillDir(t *testing.T, root, name, version, govern, author string) {
	t.Helper()
	d := filepath.Join(root, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte("# "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if govern == "" {
		return
	}
	om := install.OfflineMeta{
		BundleMeta: &registry.BundleMeta{
			Bundle:            map[string]any{"name": name, "version": version, "status": "admitted"},
			Signatures:        []registry.SignatureRow{{Role: "author", IdentityID: author, Status: "active"}},
			CurrentGovernance: govern,
		},
		Identities: map[string]*registry.Identity{},
		StashedAt:  "2026-06-22T10:00:00Z",
	}
	b, _ := json.MarshalIndent(om, "", "  ")
	if err := os.WriteFile(filepath.Join(d, ".skillctl-offline.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCompliance_JSONReport(t *testing.T) {
	root := t.TempDir()
	makeSkillDir(t, root, "alpha", "1.0.0", "green", "id:kamir@m3c")
	makeSkillDir(t, root, "beta", "", "", "") // present but unverified

	var out, errBuf bytes.Buffer
	code := runCompliance([]string{"report", "--framework", "nist-ai-rmf", "--skills-dir", root, "--format", "json"}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want 0, got %d; stderr=%s", code, errBuf.String())
	}
	var rep complianceReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if rep.Framework != "nist-ai-rmf" {
		t.Errorf("framework=%s", rep.Framework)
	}
	if rep.Summary["total"] != 2 || rep.Summary["green"] != 1 || rep.Summary["unknown"] != 1 || rep.Summary["offline_verifiable"] != 1 {
		t.Errorf("summary wrong: %+v", rep.Summary)
	}
	if len(rep.ControlMap) == 0 {
		t.Error("control map should not be empty")
	}
	// alpha sorts first; should be green + offline-verifiable + author present.
	a := rep.Skills[0]
	if a.Name != "alpha" || a.Governance != "green" || !a.OfflineVerifiable || a.Author != "id:kamir@m3c" {
		t.Errorf("alpha row wrong: %+v", a)
	}
}

func TestCompliance_MDHasDisclaimerAndControls(t *testing.T) {
	root := t.TempDir()
	makeSkillDir(t, root, "alpha", "1.0.0", "green", "id:kamir@m3c")

	var out, errBuf bytes.Buffer
	code := runCompliance([]string{"report", "--framework", "eu-ai-act", "--skills-dir", root}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want 0, got %d", code)
	}
	s := out.String()
	if !bytes.Contains(out.Bytes(), []byte("NOT a certification")) {
		t.Errorf("missing disclaimer; got:\n%s", s)
	}
	if !bytes.Contains(out.Bytes(), []byte("Art. 12")) {
		t.Errorf("missing EU AI Act control rows; got:\n%s", s)
	}
}

func TestCompliance_Art12PointsAtSignedTrail(t *testing.T) {
	home := t.TempDir()
	skillsDir := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Emit two device-signed invocation records into this home's trail.
	appendSignedInvocation(home, sampleInvocation())
	r2 := sampleInvocation()
	r2.EventID = "01HZTRAILEVENT00000000099"
	appendSignedInvocation(home, r2)

	var out, errBuf bytes.Buffer
	code := runCompliance([]string{"report", "--framework", "eu-ai-act", "--home", home, "--format", "json"}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want 0, got %d; stderr=%s", code, errBuf.String())
	}
	var rep complianceReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if rep.Trail == nil {
		t.Fatalf("report missing invocation_trail block")
	}
	if rep.Trail.Total != 2 || rep.Trail.Verified != 2 {
		t.Errorf("trail figures wrong: %+v", *rep.Trail)
	}
	// The Art.12 control row must carry the concrete signed-trail figures.
	var art12 string
	for _, c := range rep.ControlMap {
		if bytes.Contains([]byte(c.Control), []byte("Art. 12")) {
			art12 = c.Evidence
		}
	}
	if art12 == "" {
		t.Fatalf("Art.12 control row missing")
	}
	if !bytes.Contains([]byte(art12), []byte("2/2 invocation records device-signed & verified")) {
		t.Errorf("Art.12 evidence does not reflect the signed trail; got %q", art12)
	}
	if !bytes.Contains([]byte(art12), []byte("device:")) {
		t.Errorf("Art.12 evidence missing device key id; got %q", art12)
	}
}

func TestCompliance_Art12NoTrailYet(t *testing.T) {
	home := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runCompliance([]string{"report", "--framework", "eu-ai-act", "--home", home, "--format", "json"}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want 0, got %d", code)
	}
	var rep complianceReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Trail == nil || rep.Trail.Present {
		t.Errorf("expected an absent trail on a fresh home: %+v", rep.Trail)
	}
}

func TestCompliance_UnknownFramework(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCompliance([]string{"report", "--framework", "iso-9001", "--skills-dir", t.TempDir()}, &out, &errBuf)
	if code != exitUsage {
		t.Fatalf("want exitUsage, got %d", code)
	}
}

func TestCompliance_EmptyDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCompliance([]string{"report", "--framework", "soc2", "--skills-dir", t.TempDir(), "--format", "json"}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want 0, got %d", code)
	}
	var rep complianceReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary["total"] != 0 {
		t.Errorf("expected 0 skills, got %d", rep.Summary["total"])
	}
}
