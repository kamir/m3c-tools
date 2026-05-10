// SPEC-0189 §6 trust cross-reference tests.
package scanner

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// makeBundleDir builds a Claude Code-conventional skill dir at <tier-root>/<name>
// with SKILL.md frontmatter, plus optionally a sibling .skb + .author.sig.
func makeBundleDir(t *testing.T, tierRoot, name string, withBundle, validSig bool) {
	t.Helper()
	skillDir := filepath.Join(tierRoot, name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n# "+name+"\n"), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	if !withBundle {
		return
	}
	// Make a fake .skb (just some bytes — content doesn't matter for the
	// digest-pattern check).
	skbContent := []byte("fake .skb content for " + name)
	skbPath := filepath.Join(tierRoot, name+"-1.0.0.skb")
	if err := os.WriteFile(skbPath, skbContent, 0o644); err != nil {
		t.Fatalf("write .skb: %v", err)
	}
	digest := sha256.Sum256(skbContent)
	const hex = "0123456789abcdef"
	hexDigest := make([]byte, len(digest)*2)
	for i, b := range digest {
		hexDigest[2*i] = hex[b>>4]
		hexDigest[2*i+1] = hex[b&0x0f]
	}
	sigPath := fmt.Sprintf("%s.%s.author.sig", skbPath, string(hexDigest))
	sigSize := 64
	if !validSig {
		sigSize = 32 // wrong size triggers TrustBroken
	}
	if err := os.WriteFile(sigPath, make([]byte, sigSize), 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
}

// TestAnnotateTrust_Verified — sibling .skb + correct-size sig → verified.
func TestAnnotateTrust_Verified(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDir(t, tmp, "fetch-contract", true, true)

	s := &Scanner{
		Roots:     []ScanRoot{{Path: tmp, Tier: TierUser}},
		WithTrust: true,
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(inv.Skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(inv.Skills))
	}
	sk := inv.Skills[0]
	if sk.Bundle == nil {
		t.Fatal("Bundle block missing — AnnotateTrust didn't run?")
	}
	if sk.Bundle.TrustChain != TrustVerified {
		t.Errorf("trust_chain = %q, want verified; err=%q", sk.Bundle.TrustChain, sk.Bundle.VerifierError)
	}
	if !sk.Bundle.Signed {
		t.Errorf("signed = false; want true for verified bundle")
	}
	if sk.Bundle.SKBPath == "" {
		t.Errorf("SKBPath empty")
	}
	if sk.Bundle.BundleDigest == "" || sk.Bundle.BundleDigest[:7] != "sha256:" {
		t.Errorf("BundleDigest = %q, want 'sha256:<hex>'", sk.Bundle.BundleDigest)
	}
}

// TestAnnotateTrust_Unverified — no sibling .skb → unverified.
func TestAnnotateTrust_Unverified(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDir(t, tmp, "hand-authored", false, false)

	s := &Scanner{
		Roots:     []ScanRoot{{Path: tmp, Tier: TierUser}},
		WithTrust: true,
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	sk := inv.Skills[0]
	if sk.Bundle == nil || sk.Bundle.TrustChain != TrustUnverified {
		t.Errorf("trust_chain = %v, want unverified", sk.Bundle)
	}
	if sk.Bundle.Signed {
		t.Errorf("signed = true; want false for hand-authored skill")
	}
}

// TestAnnotateTrust_Broken — sibling .skb but sig file wrong size → broken.
func TestAnnotateTrust_Broken(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDir(t, tmp, "tampered", true, false /* sig wrong size */)

	s := &Scanner{
		Roots:     []ScanRoot{{Path: tmp, Tier: TierUser}},
		WithTrust: true,
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	sk := inv.Skills[0]
	if sk.Bundle == nil || sk.Bundle.TrustChain != TrustBroken {
		t.Errorf("trust_chain = %v, want broken", sk.Bundle)
	}
	if sk.Bundle.VerifierError == "" {
		t.Errorf("VerifierError empty for broken bundle")
	}
}

// TestAnnotateTrust_NoTrust — without WithTrust=true, Bundle stays nil.
func TestAnnotateTrust_NoTrust(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDir(t, tmp, "untouched", true, true)

	s := &Scanner{
		Roots: []ScanRoot{{Path: tmp, Tier: TierUser}},
		// WithTrust: false (default)
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	sk := inv.Skills[0]
	if sk.Bundle != nil {
		t.Errorf("Bundle populated without WithTrust=true")
	}
}

// TestAnnotateTrust_CacheByContentHash — two skills with identical
// SKILL.md content share an answer (sanity check the cache path).
func TestAnnotateTrust_CacheByContentHash(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDir(t, tmp, "twin-a", false, false)
	makeBundleDir(t, tmp, "twin-b", false, false)
	// Twin SKILL.md content — overwrite to identical bytes.
	bytes := []byte("same content\n")
	_ = os.WriteFile(filepath.Join(tmp, "twin-a", "SKILL.md"), bytes, 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "twin-b", "SKILL.md"), bytes, 0o644)

	s := &Scanner{
		Roots:     []ScanRoot{{Path: tmp, Tier: TierUser}},
		WithTrust: true,
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(inv.Skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(inv.Skills))
	}
	for _, sk := range inv.Skills {
		if sk.Bundle == nil {
			t.Errorf("%s missing Bundle block", sk.Name)
		} else if sk.Bundle.TrustChain != TrustUnverified {
			t.Errorf("%s trust_chain = %q, want unverified", sk.Name, sk.Bundle.TrustChain)
		}
	}
	// Suppress unused-var warning.
	_ = model.SkillTypeClaudeCodeSkill
}
