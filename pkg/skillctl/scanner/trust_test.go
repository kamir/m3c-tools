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
// with SKILL.md frontmatter, plus optionally a sibling .skb + .author.sig in
// the hyphen spelling that `skillctl install` writes.
func makeBundleDir(t *testing.T, tierRoot, name string, withBundle, validSig bool) {
	t.Helper()
	makeBundleDirSep(t, tierRoot, name, "-", withBundle, validSig)
}

// makeBundleDirSep is makeBundleDir with the separator spelled out: "-" is what
// `install` writes, "@" is what `export-bundle`, `export-kit` and
// `publish --pack` write. Both are this tool's own output (BUG-0253).
func makeBundleDirSep(t *testing.T, tierRoot, name, sep string, withBundle, validSig bool) {
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
	// Make a fake .skb (just some bytes: content doesn't matter for the
	// digest-pattern check).
	skbContent := []byte("fake .skb content for " + name)
	skbPath := filepath.Join(tierRoot, name+sep+"1.0.0.skb")
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

// TestAnnotateTrust_SignaturePresent: sibling .skb + correct-size sig → verified.
func TestAnnotateTrust_SignaturePresent(t *testing.T) {
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
		t.Fatal("Bundle block missing: AnnotateTrust didn't run?")
	}
	if sk.Bundle.TrustChain != TrustSignaturePresent {
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

// TestAnnotateTrust_Unverified: no sibling .skb → unverified.
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

// TestAnnotateTrust_Broken: sibling .skb but sig file wrong size → broken.
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

// TestAnnotateTrust_NoTrust: without WithTrust=true, Bundle stays nil.
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

// TestAnnotateTrust_CacheByContentHash: two skills with identical
// SKILL.md content share an answer (sanity check the cache path).
func TestAnnotateTrust_CacheByContentHash(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDir(t, tmp, "twin-a", false, false)
	makeBundleDir(t, tmp, "twin-b", false, false)
	// Twin SKILL.md content: overwrite to identical bytes.
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

// TestFindSiblingSKB_Spellings pins the matcher itself: both separators this
// tool writes are found, and a bundle belonging to a LONGER skill name is not
// claimed by the shorter one. The last case is why the match cannot be a plain
// prefix: `review` and `review-plan` are both real skills that ship together.
func TestFindSiblingSKB_Spellings(t *testing.T) {
	cases := []struct {
		desc  string
		skill string
		files []string
		want  string // "" means: expect no match
	}{
		{
			desc:  "hyphen spelling as written by install",
			skill: "fetch-contract",
			files: []string{"fetch-contract-1.0.0.skb"},
			want:  "fetch-contract-1.0.0.skb",
		},
		{
			desc:  "at spelling as written by export-bundle and publish --pack",
			skill: "fetch-contract",
			files: []string{"fetch-contract@1.0.0.skb"},
			want:  "fetch-contract@1.0.0.skb",
		},
		{
			desc:  "staged digest form from install_bundle",
			skill: "fetch-contract",
			files: []string{"fetch-contract-sha256_deadbeef.skb"},
			want:  "fetch-contract-sha256_deadbeef.skb",
		},
		{
			desc:  "another skill's bundle is not claimed, at spelling",
			skill: "review",
			files: []string{"review-plan@0.0.0.skb", "review-spec@0.0.0.skb"},
			want:  "",
		},
		{
			desc:  "another skill's bundle is not claimed, hyphen spelling",
			skill: "deploy",
			files: []string{"deploy-verified-0.0.0.skb"},
			want:  "",
		},
		{
			desc:  "no bundle at all",
			skill: "hand-authored",
			files: nil,
			want:  "",
		},
		{
			desc:  "newest version wins across the two spellings",
			skill: "twin",
			files: []string{"twin-0.1.0.skb", "twin@9.9.9.skb"},
			want:  "twin@9.9.9.skb",
		},
		{
			desc:  "and the separator alone does not decide it",
			skill: "twin",
			files: []string{"twin-9.9.9.skb", "twin@0.1.0.skb"},
			want:  "twin-9.9.9.skb",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "skills")
			if err := os.MkdirAll(filepath.Join(parent, tc.skill), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(parent, f), []byte("bundle bytes"), 0o644); err != nil {
					t.Fatalf("write %s: %v", f, err)
				}
			}
			got, found := findSiblingSKB(parent, tc.skill)
			if tc.want == "" {
				if found {
					t.Fatalf("findSiblingSKB matched %q, want no match", got)
				}
				return
			}
			if !found {
				t.Fatalf("findSiblingSKB found nothing, want %q", tc.want)
			}
			if filepath.Base(got) != tc.want {
				t.Errorf("findSiblingSKB = %q, want %q", filepath.Base(got), tc.want)
			}
		})
	}
}

// TestAnnotateTrust_AtSpelling: the @-form reaches the same verdicts as the
// hyphen form. Before BUG-0253 the @-form fell out one step earlier, at "no
// sibling .skb on disk", and a bundle that was on disk read as absent.
func TestAnnotateTrust_AtSpelling(t *testing.T) {
	t.Run("signature present", func(t *testing.T) {
		tmp := t.TempDir()
		makeBundleDirSep(t, tmp, "fetch-contract", "@", true, true)

		s := &Scanner{Roots: []ScanRoot{{Path: tmp, Tier: TierUser}}, WithTrust: true}
		inv, err := s.Scan()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		sk := inv.Skills[0]
		if sk.Bundle == nil || sk.Bundle.TrustChain != TrustSignaturePresent {
			t.Fatalf("trust_chain = %+v, want verified", sk.Bundle)
		}
		if filepath.Base(sk.Bundle.SKBPath) != "fetch-contract@1.0.0.skb" {
			t.Errorf("SKBPath = %q, want the @-form bundle", sk.Bundle.SKBPath)
		}
	})

	t.Run("signature missing", func(t *testing.T) {
		// The state every locally exported bundle is actually in: the bundle
		// is there, the detached author signature never was.
		tmp := t.TempDir()
		makeBundleDirSep(t, tmp, "accept", "@", false, false)
		if err := os.WriteFile(filepath.Join(tmp, "accept@0.0.0.skb"), []byte("bundle bytes"), 0o644); err != nil {
			t.Fatalf("write skb: %v", err)
		}

		s := &Scanner{Roots: []ScanRoot{{Path: tmp, Tier: TierUser}}, WithTrust: true}
		inv, err := s.Scan()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		sk := inv.Skills[0]
		if sk.Bundle == nil || sk.Bundle.TrustChain != TrustBroken {
			t.Fatalf("trust_chain = %+v, want broken", sk.Bundle)
		}
		if sk.Bundle.BundleDigest == "" {
			t.Errorf("BundleDigest empty: the bundle was found, so it should have been hashed")
		}
	})
}

// TestAnnotateTrust_NeighbourBundleNotClaimed is the negative case end to end:
// `review` sits next to `review-plan`'s bundle and must still report
// unverified, not a digest computed over someone else's bytes.
func TestAnnotateTrust_NeighbourBundleNotClaimed(t *testing.T) {
	tmp := t.TempDir()
	makeBundleDirSep(t, tmp, "review", "@", false, false)
	makeBundleDirSep(t, tmp, "review-plan", "@", true, true)

	s := &Scanner{Roots: []ScanRoot{{Path: tmp, Tier: TierUser}}, WithTrust: true}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, sk := range inv.Skills {
		switch sk.Name {
		case "review":
			if sk.Bundle == nil || sk.Bundle.TrustChain != TrustUnverified {
				t.Errorf("review trust_chain = %+v, want unverified", sk.Bundle)
			}
			if sk.Bundle != nil && sk.Bundle.SKBPath != "" {
				t.Errorf("review claimed %q, which belongs to review-plan", sk.Bundle.SKBPath)
			}
		case "review-plan":
			if sk.Bundle == nil || sk.Bundle.TrustChain != TrustSignaturePresent {
				t.Errorf("review-plan trust_chain = %+v, want verified", sk.Bundle)
			}
		}
	}
}
