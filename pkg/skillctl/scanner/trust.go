// Trust cross-reference for SPEC-0189 §6 (`--with-trust`).
//
// For each scanned skill, look for a sibling <name>-<version>.skb in the
// same parent directory (or in ../.archive/) per Decision D1: the on-disk
// `.skb` is the canonical signal — there is no separate per-machine
// install ledger. Recompute the bundle digest, look for the matching
// detached author signature, and annotate the descriptor.
//
// "verified" — .skb present, digest matches the digest in the sig
// filename, and the sig file is the expected 64 raw bytes. The author
// signature itself is not cryptographically verified here (that needs
// a network round-trip to the registry to fetch the signer's pubkey,
// which is the v2 of `--with-trust`); but "matches its own digest
// envelope" is a strong local-only signal that nothing was tampered
// after install.
//
// "unverified" — no sibling .skb (skill was hand-authored, not
// installed via `skillctl install`).
//
// "broken" — .skb present but digest computation fails, sig file
// missing, or sig file wrong size.
package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// trust_chain values.
const (
	TrustVerified   = "verified"
	TrustUnverified = "unverified"
	TrustBroken     = "broken"
)

// AnnotateTrust walks every claude_code_skill in the inventory and
// populates the SkillDescriptor.Bundle block. Errors per skill are
// recorded on the descriptor (TrustChain="broken" + VerifierError);
// the function itself only returns an error if the inventory pointer
// is nil.
//
// Cache: results keyed by ContentHash; skills with the same SKILL.md
// hash share an answer (cheap protection against re-scanning a
// symlinked skill twice).
func AnnotateTrust(inv *model.Inventory) error {
	if inv == nil {
		return fmt.Errorf("nil inventory")
	}
	cache := map[string]*model.BundleAttestation{}
	for i := range inv.Skills {
		sk := &inv.Skills[i]
		if sk.Type != model.SkillTypeClaudeCodeSkill || sk.Tier == "" {
			continue
		}
		if cached, ok := cache[sk.ContentHash]; ok {
			// Clone so each descriptor has its own pointer (callers may
			// mutate, e.g. CLI `--verbose` annotations downstream).
			cp := *cached
			sk.Bundle = &cp
			continue
		}
		ba := annotateSkillTrust(sk)
		sk.Bundle = ba
		cache[sk.ContentHash] = ba
	}
	return nil
}

// annotateSkillTrust does the per-skill probe.
func annotateSkillTrust(sk *model.SkillDescriptor) *model.BundleAttestation {
	parent := filepath.Dir(sk.SourcePath) // ~/.claude/skills/<name>'s parent (skills/)
	skbPath, found := findSiblingSKB(parent, sk.Name)
	if !found {
		return &model.BundleAttestation{
			Signed:     false,
			TrustChain: TrustUnverified,
		}
	}

	digest, err := computeSKBDigest(skbPath)
	if err != nil {
		return &model.BundleAttestation{
			SKBPath:       skbPath,
			Signed:        false,
			TrustChain:    TrustBroken,
			VerifierError: fmt.Sprintf("digest compute failed: %v", err),
		}
	}

	// Look for sibling sig file: <skbPath>.<digest>.author.sig.
	expectedSig := fmt.Sprintf("%s.%s.author.sig", skbPath, digest)
	sigInfo, err := os.Stat(expectedSig)
	if err != nil {
		return &model.BundleAttestation{
			SKBPath:       skbPath,
			BundleDigest:  "sha256:" + digest,
			Signed:        false,
			TrustChain:    TrustBroken,
			VerifierError: fmt.Sprintf("expected sig file missing: %s", expectedSig),
		}
	}
	// Sig file must be exactly 64 raw bytes (ed25519 detached).
	if sigInfo.Size() != 64 {
		return &model.BundleAttestation{
			SKBPath:          skbPath,
			BundleDigest:     "sha256:" + digest,
			Signed:           false,
			TrustChain:       TrustBroken,
			VerifierExitCode: 11, // verify.ExitAuthorSigInvalid
			VerifierError:    fmt.Sprintf("sig file size = %d, expected 64", sigInfo.Size()),
		}
	}

	return &model.BundleAttestation{
		SKBPath:                skbPath,
		BundleDigest:           "sha256:" + digest,
		Signed:                 true,
		RegisteredInLocalTrust: false, // populated only when a registry round-trip is run
		TrustChain:             TrustVerified,
	}
}

// findSiblingSKB looks for `<name>-*.skb` in `parent` and `parent/../.archive/`.
// Returns the first match. If multiple versions exist, picks the
// lex-largest (a rough proxy for "newest" without parsing semver).
func findSiblingSKB(parent, name string) (string, bool) {
	candidates := []string{parent, filepath.Join(filepath.Dir(parent), ".archive")}
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + `-.*\.skb$`)

	var best string
	for _, dir := range candidates {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !pattern.MatchString(e.Name()) {
				continue
			}
			candidate := filepath.Join(dir, e.Name())
			if best == "" || strings.Compare(e.Name(), filepath.Base(best)) > 0 {
				best = candidate
			}
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// computeSKBDigest streams the file through SHA-256 and returns the
// lowercase hex digest (no `sha256:` prefix). 1 MiB chunks to avoid
// pulling a large bundle into memory.
func computeSKBDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	const hex = "0123456789abcdef"
	out := make([]byte, len(sum)*2)
	for i, b := range sum {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return string(out), nil
}
