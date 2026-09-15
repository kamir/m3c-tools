package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// Installing an agent (SPEC-0432 T-06). An agent is ONE file and lands in
// ~/.claude/agents/<name>.md, beside the skills rather than among them.

// makeAgentSkb builds an agent bundle the way Pack does: bundle.json at the
// top level, kind agent, schema v2, and exactly one content file.
func makeAgentSkb(t *testing.T, name string, extraFiles map[string]string, schema, kind string) []byte {
	t.Helper()
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	tw := tar.NewWriter(gw)

	man := map[string]any{"schema": schema, "name": name, "version": "1.0.0"}
	if kind != "" {
		man["kind"] = kind
	}
	raw, _ := json.Marshal(man)
	write := func(rel string, body []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: rel, Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
	}
	write("bundle.json", raw)
	write(name+".md", []byte("---\nname: "+name+"\n---\n\nDo the thing.\n"))
	for rel, body := range extraFiles {
		write(rel, []byte(body))
	}
	_ = tw.Close()
	_ = gw.Close()
	return gz.Bytes()
}

func stagedAgent(t *testing.T, name string, skb []byte) *StagedBundle {
	t.Helper()
	d := sha256.Sum256(skb)
	path := filepath.Join(t.TempDir(), "bundle.skb")
	if err := os.WriteFile(path, skb, 0o644); err != nil {
		t.Fatal(err)
	}
	return &StagedBundle{
		Name: name, Version: "1.0.0", Digest: "sha256:" + hex.EncodeToString(d[:]),
		Governance: "yellow", StagedSkbPath: path, AuthorIdentity: "id:test@m3c",
	}
}

// homeWith returns a skills dir inside a temp home, so agentsDirFor derives a
// sibling agents dir in the SAME temp home and no test can reach the real one.
func homeWith(t *testing.T) (skillsDir, agentsDir string) {
	t.Helper()
	home := t.TempDir()
	return filepath.Join(home, ".claude", "skills"), filepath.Join(home, ".claude", "agents")
}

// TestInstallAgentLandsBesideSkills is AC-2: the file is there, and it is a
// FILE, in the agents dir, not a directory among the skills.
func TestInstallAgentLandsBesideSkills(t *testing.T) {
	skillsDir, agentsDir := homeWith(t)
	skb := makeAgentSkb(t, "release-agent", nil, skillbundle.SchemaAgent, skillbundle.KindAgent)

	res, err := installOne(stagedAgent(t, "release-agent", skb), InstallOpts{SkillsDir: skillsDir})
	if err != nil {
		t.Fatalf("installOne: %v", err)
	}

	target := filepath.Join(agentsDir, "release-agent.md")
	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("agent not at %s: %v", target, err)
	}
	if st.IsDir() {
		t.Fatalf("%s is a directory; an agent is one file", target)
	}
	if res.SkillPath != target {
		t.Errorf("result path = %q, want %q", res.SkillPath, target)
	}
	if _, err := os.Stat(filepath.Join(skillsDir, "release-agent")); err == nil {
		t.Error("the agent was ALSO placed among the skills")
	}
}

// TestInstallAgentWritesProvenance: an agent must be no less traceable than a
// skill. Its sidecar lives in a dotted dir, invisible to the *.md glob that
// the agent loader uses.
func TestInstallAgentWritesProvenance(t *testing.T) {
	skillsDir, agentsDir := homeWith(t)
	skb := makeAgentSkb(t, "helper", nil, skillbundle.SchemaAgent, skillbundle.KindAgent)
	staged := stagedAgent(t, "helper", skb)

	res, err := installOne(staged, InstallOpts{SkillsDir: skillsDir})
	if err != nil {
		t.Fatalf("installOne: %v", err)
	}
	want := filepath.Join(agentsDir, ".provenance", "helper.json")
	if res.ProvenancePath != want {
		t.Errorf("provenance at %q, want %q", res.ProvenancePath, want)
	}
	side, err := loadProvenance(want)
	if err != nil {
		t.Fatalf("loadProvenance: %v", err)
	}
	if side.BundleDigest != staged.Digest {
		t.Errorf("sidecar digest = %q, want %q", side.BundleDigest, staged.Digest)
	}

	// The loader globs *.md; a dotted directory must not show up there.
	entries, _ := os.ReadDir(agentsDir)
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".md") {
			t.Errorf("stray non-md file beside the agents: %s", e.Name())
		}
	}
}

// TestInstallRefusesUnknownSchema: the fail-closed guard. A bundle written by
// a NEWER producer may put its content somewhere this build does not know, so
// installing it anyway would place the artifact wrongly and report success.
func TestInstallRefusesUnknownSchema(t *testing.T) {
	skillsDir, agentsDir := homeWith(t)
	skb := makeAgentSkb(t, "future", nil, "m3c-skill-bundle/v9", skillbundle.KindAgent)

	_, err := installOne(stagedAgent(t, "future", skb), InstallOpts{SkillsDir: skillsDir})
	if err == nil {
		t.Fatal("an unknown schema was installed")
	}
	for _, want := range []string{"m3c-skill-bundle/v9", "nothing was installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not carry %q", err, want)
		}
	}
	if _, statErr := os.Stat(agentsDir); statErr == nil {
		if entries, _ := os.ReadDir(agentsDir); len(entries) > 0 {
			t.Errorf("something was written despite the refusal: %v", entries)
		}
	}
}

// TestInstallRefusesAgentWithExtraFiles is AC-14 on the receiving side.
// Silently dropping the extra files would hide that the bundle was not built
// to this contract.
func TestInstallRefusesAgentWithExtraFiles(t *testing.T) {
	skillsDir, _ := homeWith(t)
	skb := makeAgentSkb(t, "fat", map[string]string{"extra.md": "x"},
		skillbundle.SchemaAgent, skillbundle.KindAgent)

	_, err := installOne(stagedAgent(t, "fat", skb), InstallOpts{SkillsDir: skillsDir})
	if err == nil {
		t.Fatal("an agent bundle with a second file was installed")
	}
	if !strings.Contains(err.Error(), "nothing was installed") {
		t.Errorf("error %q does not say nothing was installed", err)
	}
}

// TestInstallSkillUnaffected: the counter-probe. A bundle with no kind is a
// skill and still lands as a directory among the skills, exactly as before.
func TestInstallSkillUnaffected(t *testing.T) {
	skillsDir, agentsDir := homeWith(t)
	skb := makeSkbTGZ("plain-skill", "# plain\n")

	if _, err := installOne(stagedFor(t, "plain-skill", "1.0.0", skb),
		InstallOpts{SkillsDir: skillsDir}); err != nil {
		t.Fatalf("installOne: %v", err)
	}
	st, err := os.Stat(filepath.Join(skillsDir, "plain-skill"))
	if err != nil || !st.IsDir() {
		t.Fatalf("skill did not land as a directory under %s: %v", skillsDir, err)
	}
	if _, err := os.Stat(agentsDir); err == nil {
		t.Error("installing a skill created an agents dir")
	}
}

// TestPlanNamesTheAgentsDir. The G-23 two step asks a human to approve a plan
// before anything is written. While running T-08 that plan offered to put 19
// agents into ~/.claude/skills/, because PlanInstall did not know about kinds
// and only installOne did. The install would have been right and the review
// wrong, which is the worse of the two: a review of the wrong thing is not a
// review.
func TestPlanNamesTheAgentsDir(t *testing.T) {
	skillsDir, agentsDir := homeWith(t)
	plan, err := PlanInstall([]*StagedBundle{
		{Kind: skillbundle.KindAgent, Name: "release-agent", Version: "1.0.0", Digest: "sha256:a"},
		{Name: "plain-skill", Version: "1.0.0", Digest: "sha256:b"},
	}, skillsDir)
	if err != nil {
		t.Fatalf("PlanInstall: %v", err)
	}
	got := map[string]string{}
	for _, r := range append(append([]PlanRow{}, plan.Creates...), plan.Overwrites...) {
		got[r.Name] = r.SkillPath
	}
	if want := filepath.Join(agentsDir, "release-agent.md"); got["release-agent"] != want {
		t.Errorf("the plan sends the agent to %q, want %q", got["release-agent"], want)
	}
	if want := filepath.Join(skillsDir, "plain-skill"); got["plain-skill"] != want {
		t.Errorf("the plan sends the skill to %q, want %q", got["plain-skill"], want)
	}
}
