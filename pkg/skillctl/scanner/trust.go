// Trust cross-reference for SPEC-0189 §6 (`--with-trust`).
//
// For each scanned skill, look for a sibling bundle in the same parent
// directory (or in ../.archive/) per Decision D1: the on-disk `.skb` is the
// canonical signal. There is no separate per-machine install ledger.
// Recompute the bundle digest, look for the matching detached author
// signature, and annotate the descriptor.
//
// Two spellings, one meaning (BUG-0253): `install` writes
// <name>-<version>.skb, while `export-bundle`, `export-kit` and
// `publish --pack` write <name>@<version>.skb. Both are this tool's own
// output, so the scanner reads both. Until 2026-09-13 it read only the
// hyphen form and reported every @-form bundle on disk as "no sibling
// .skb", which is why a machine full of bundles audited as UNVERIFIED.
//
// "verified": .skb present, digest matches the digest in the sig
// filename, and the sig file is the expected 64 raw bytes. The author
// signature itself is not cryptographically verified here (that needs
// a network round-trip to the registry to fetch the signer's pubkey,
// which is the v2 of `--with-trust`); but "matches its own digest
// envelope" is a strong local-only signal that nothing was tampered
// after install.
//
// "unverified", no sibling .skb (skill was hand-authored, not
// installed via `skillctl install`).
//
// "broken", .skb present but digest computation fails, sig file
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

// trust_chain values recorded by AnnotateTrust (the scan/audit DISPLAY layer).
//
// IMPORTANT: TrustSignaturePresent means only that a detached signature file of
// the correct length (64-byte ed25519) sits next to the .skb: it is NOT a
// cryptographic verification. The authenticating check (recompute the digest,
// verify the author/registry/governance signature chain against pinned roots)
// is pkg/skillctl/verify (`skillctl verify`), not this scanner. The string
// value stays "verified" for output/JSON compatibility.
const (
	TrustSignaturePresent = "verified" // sig file present + 64-byte length (NOT crypto-verified)
	TrustUnverified       = "unverified"
	TrustBroken           = "broken"
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
		TrustChain:             TrustSignaturePresent,
	}
}

// findSiblingSKB looks for `<name>-<version>.skb` or `<name>@<version>.skb`
// in `parent` and `parent/../.archive/`. Both separators are accepted because
// this tool writes both (BUG-0253); which one a file carries says only which
// command produced it, never anything about its trustworthiness.
//
// If several versions exist the lex-largest VERSION TOKEN wins, a rough proxy
// for "newest" without parsing semver. The comparison is on the token and not
// on the whole filename on purpose: `@` sorts above `-`, so comparing whole
// names would let `foo@0.0.1.skb` beat `foo-9.9.9.skb` on the separator alone.
// Equal tokens fall back to the filename so the result stays deterministic.
func findSiblingSKB(parent, name string) (string, bool) {
	candidates := []string{parent, filepath.Join(filepath.Dir(parent), ".archive")}
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + `[-@](.+)\.skb$`)

	var best, bestToken string
	for _, dir := range candidates {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			m := pattern.FindStringSubmatch(e.Name())
			if m == nil || !isSKBVersionToken(m[1]) {
				continue
			}
			token := m[1]
			candidate := filepath.Join(dir, e.Name())
			switch {
			case best == "":
			case strings.Compare(token, bestToken) > 0:
			case token == bestToken && strings.Compare(e.Name(), filepath.Base(best)) > 0:
			default:
				continue
			}
			best, bestToken = candidate, token
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// isSKBVersionToken reports whether tok, the part of a bundle filename between
// the separator and `.skb`, is a version or a digest rather than the
// continuation of a LONGER skill name.
//
// Without this guard a prefix match binds a skill to its neighbour's bundle:
// the skill `review` would claim `review-plan@0.0.0.skb`, and `deploy` would
// claim `deploy-verified@0.0.0.skb`. Both pairs exist in the shipped skill set,
// so this is not a theoretical case; it would have handed one skill a digest
// computed over another skill's bytes.
//
// The three writers in this tool produce exactly three token shapes: a semver
// (`0.0.0`, `1.2.3-rc1`), a `v`-prefixed semver (`v0.5.0`), and the sanitized
// digest `sha256_<hex>` that install stages. A skill-name continuation starts
// with a letter that is none of these.
func isSKBVersionToken(tok string) bool {
	if tok == "" {
		return false
	}
	if strings.HasPrefix(tok, "sha256_") {
		return len(tok) > len("sha256_")
	}
	c := tok[0]
	if c >= '0' && c <= '9' {
		return true
	}
	// `v1.2.3`, but not `verified`.
	if (c == 'v' || c == 'V') && len(tok) > 1 && tok[1] >= '0' && tok[1] <= '9' {
		return true
	}
	return false
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
