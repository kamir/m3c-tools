package main

// SPEC-0276 R4.3 — `skillctl export-verification-kit`.
//
// Packages a signed bundle into a portable, self-contained directory (and
// optional .zip) that a third party can verify OFFLINE with no access to our
// servers and no trust in us beyond a public key they confirm out-of-band:
//
//	kit/
//	  <name>@<ver>.skb            the signed bundle blob
//	  <name>@<ver>.skbmeta.json   BundleMeta envelope (author+registry+governance sigs)
//	  trust-roots.pinned.yaml     ONLY the pinned author + registry pubkeys needed
//	  revocations.json            signed revocation snapshot (optional)
//	  VERIFY.md                   one-command instructions + expected verdict + fingerprint
//	  verify.sh                   `skillctl verify --bundle … --trust-roots ./trust-roots.pinned.yaml`
//
// The export SELF-VALIDATES (runs the offline verify before writing) so we never
// ship a broken kit, and runs a hard secret-scrub over every generated text file
// so the kit is safe to email/publish.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// runExportKit implements `skillctl export-verification-kit [flags]`.
func runExportKit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export-verification-kit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	bundlePath := fs.String("bundle", "", "Path to the signed .skb bundle to package (required).")
	metaPath := fs.String("meta", "", "Path to the BundleMeta envelope JSON (default: the .skbmeta.json sidecar next to the .skb).")
	trustRootsPath := fs.String("trust-roots", "", "Trust-roots YAML to source pinned keys from (default: ~/.claude/skill-trust-roots.yaml). Must be pinned mode.")
	revocationsPath := fs.String("revocations", "", "Optional signed revocation list to include in the kit (validated against the pinned registry key before inclusion).")
	registryURL := fs.String("registry", "", "Registry URL to disambiguate when trust-roots pins multiple registries.")
	outDir := fs.String("out", "", "Output directory for the kit (required).")
	makeZip := fs.Bool("zip", false, "Also produce <out>.zip.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl export-verification-kit --bundle <file.skb> --out <dir> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Builds a portable, offline, trust-nothing verification kit (SPEC-0276 R4.3).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *bundlePath == "" || *outDir == "" {
		fs.Usage()
		return exitUsage
	}
	if st, err := os.Stat(*bundlePath); err != nil || st.IsDir() {
		fmt.Fprintf(stderr, "export-verification-kit: cannot read bundle %s\n", *bundlePath)
		return exitUsage
	}

	// Load the BundleMeta envelope (reuses the --bundle sidecar resolution).
	mp := *metaPath
	if mp == "" {
		mp = defaultMetaSidecar(*bundlePath)
	}
	meta, err := loadBundleMetaSidecar(mp)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Resolve the source trust-roots and pick the matching root. Must be pinned
	// so the emitted kit is verifiable with no registry.
	_, root, err := loadAndPickRootFromPath(*trustRootsPath, *registryURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if root.IdentityKeysAuthorized != "pinned" {
		fmt.Fprintf(stderr, "export-verification-kit: trust root %s must be identity_keys_authorized: pinned so the kit verifies offline (see SPEC-0276 R4.1).\n", root.RegistryURL)
		return exitGeneric
	}

	// Identify the bundle's author and its pinned key.
	authorID := authorIDOf(meta)
	if authorID == "" {
		fmt.Fprintln(stderr, "export-verification-kit: bundle has no author signature row; cannot build a kit.")
		return exitGeneric
	}
	authorKey := root.FindAuthor(authorID)
	if authorKey == nil {
		fmt.Fprintf(stderr, "export-verification-kit: author %s is not pinned in trust root %s; pin it first.\n", authorID, root.RegistryURL)
		return exitGeneric
	}

	// Self-validate: run the offline verify BEFORE writing anything, so we never
	// emit a kit that doesn't verify.
	res, verr := verify.Verify(verify.VerifyOpts{
		BundlePath:      *bundlePath,
		BundleMeta:      meta,
		TrustRoot:       root,
		IdentityFetcher: nil,
		Ctx:             context.Background(),
	})
	if verr != nil {
		fmt.Fprintf(stderr, "export-verification-kit: refusing to package a bundle that does not verify: %v\n", verr)
		return verify.ExitCode(verr)
	}

	// If a revocation list is supplied, validate it (and that it does NOT already
	// revoke this very bundle) before including it.
	if *revocationsPath != "" {
		revoked, rerr := checkBundleRevoked(*revocationsPath, root, res.Digest)
		if rerr != nil {
			fmt.Fprintf(stderr, "export-verification-kit: revocation list rejected: %v\n", rerr)
			return verify.ExitCode(rerr)
		}
		if revoked {
			fmt.Fprintf(stderr, "export-verification-kit: this bundle (%s) is already revoked by the supplied list; not packaging.\n", res.Digest)
			return exitBundleRevoked
		}
	}

	// Build the kit in a temp staging dir, scrub, then move into place — so a
	// scrub failure never leaves a half-written kit.
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "export-verification-kit: mkdir %s: %v\n", *outDir, err)
		return exitGeneric
	}

	skbName := filepath.Base(*bundlePath)
	metaName := filepath.Base(defaultMetaSidecar(skbName))
	hasRevocations := *revocationsPath != ""

	files := map[string][]byte{}

	// .skb blob — copied verbatim; NOT scrubbed (it is the signed artifact, its
	// integrity is cryptographically bound; an env-var NAME documented in a
	// SKILL.md is not a secret leak).
	skbBytes, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "export-verification-kit: read bundle: %v\n", err)
		return exitGeneric
	}

	metaBytes, err := os.ReadFile(mp)
	if err != nil {
		fmt.Fprintf(stderr, "export-verification-kit: read meta: %v\n", err)
		return exitGeneric
	}
	files[metaName] = metaBytes

	trYAML, err := minimalPinnedTrustRootsYAML(root, authorID)
	if err != nil {
		fmt.Fprintf(stderr, "export-verification-kit: build trust-roots: %v\n", err)
		return exitGeneric
	}
	files["trust-roots.pinned.yaml"] = trYAML

	if hasRevocations {
		revBytes, err := os.ReadFile(*revocationsPath)
		if err != nil {
			fmt.Fprintf(stderr, "export-verification-kit: read revocations: %v\n", err)
			return exitGeneric
		}
		files["revocations.json"] = revBytes
	}

	authorFP := pubkeyFingerprint(ed25519.PublicKey(authorKey.Pubkey))
	files["VERIFY.md"] = []byte(renderVerifyMD(res, skbName, authorID, authorFP, hasRevocations))
	verifyScript := renderVerifyScript(skbName, hasRevocations)
	files["verify.sh"] = []byte(verifyScript)

	// Hard secret-scrub over every generated text file.
	for name, data := range files {
		if err := scrubSecrets(name, data); err != nil {
			fmt.Fprintf(stderr, "export-verification-kit: refusing to emit — %v\n", err)
			return exitGeneric
		}
	}

	// Write everything.
	if err := os.WriteFile(filepath.Join(*outDir, skbName), skbBytes, 0o644); err != nil {
		fmt.Fprintf(stderr, "export-verification-kit: write skb: %v\n", err)
		return exitGeneric
	}
	for name, data := range files {
		mode := os.FileMode(0o644)
		if name == "verify.sh" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(*outDir, name), data, mode); err != nil {
			fmt.Fprintf(stderr, "export-verification-kit: write %s: %v\n", name, err)
			return exitGeneric
		}
	}

	if *makeZip {
		zipPath := strings.TrimRight(*outDir, "/") + ".zip"
		if err := zipDir(*outDir, zipPath); err != nil {
			fmt.Fprintf(stderr, "export-verification-kit: zip: %v\n", err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "kit: %s\nzip: %s\n", *outDir, zipPath)
	} else {
		fmt.Fprintf(stdout, "kit: %s\n", *outDir)
	}
	fmt.Fprintf(stdout, "verify with: (cd %s && bash verify.sh)  → expect: %s\n", *outDir, res.ChainSummary)
	return exitOK
}

// authorIDOf returns the author identity_id from a BundleMeta, or "".
func authorIDOf(meta *registry.BundleMeta) string {
	for _, s := range meta.Signatures {
		if s.Role == "author" && s.Status != "revoked" && s.IdentityID != "" {
			return s.IdentityID
		}
	}
	return ""
}

// minimalPinnedTrustRootsYAML builds a trust-roots YAML containing ONLY the
// matched registry's active keys and the single pinned author the bundle
// references — the least the kit needs to verify, and no more. Reuses
// verify.TrustRoots.Save so the YAML shape stays canonical.
func minimalPinnedTrustRootsYAML(root *verify.TrustRoot, authorID string) ([]byte, error) {
	ak := root.FindAuthor(authorID)
	if ak == nil {
		return nil, fmt.Errorf("author %s not pinned", authorID)
	}
	min := verify.TrustRoots{
		Roots: []verify.TrustRoot{{
			RegistryURL:            root.RegistryURL,
			RegistryKeys:           root.ActiveKeys(),
			IdentityKeysAuthorized: "pinned",
			Authors:                []verify.AuthorKey{*ak},
			GovernanceMinimum:      root.GovernanceMinimum,
		}},
	}
	// Marshal by Save-ing to a temp file (Save validates + emits canonical YAML),
	// then read it back. Keeps one source of truth for the on-disk format.
	tmp, err := os.CreateTemp("", "trust-roots-*.yaml")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)
	min.Path = tmpPath
	if err := min.Save(); err != nil {
		return nil, err
	}
	return os.ReadFile(tmpPath)
}

// renderVerifyMD produces the human VERIFY.md. It states the expected digest +
// chain summary (so the verifier compares against a known-good string) and
// instructs them to confirm the author fingerprint OUT-OF-BAND — the kit proves
// integrity; the out-of-band fingerprint proves identity.
func renderVerifyMD(res *verify.VerifyResult, skbName, authorID, authorFP string, hasRevocations bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Verification kit — %s\n\n", skbName)
	b.WriteString("This kit lets ANYONE verify this skill bundle **offline** — no network, and no\n")
	b.WriteString("trust in the publisher beyond a public key you confirm out-of-band.\n\n")
	b.WriteString("## One command\n\n```\nbash verify.sh\n```\n\n")
	fmt.Fprintf(&b, "Expected: exit code 0 and the line:\n\n    %s\n\n", res.ChainSummary)
	b.WriteString("## What it proves\n\n")
	fmt.Fprintf(&b, "- The bundle bytes match the signed digest: `%s`\n", res.Digest)
	fmt.Fprintf(&b, "- The author signature is valid for identity: `%s`\n", authorID)
	fmt.Fprintf(&b, "- A pinned registry key admitted it; governance level: `%s`\n\n", res.GovernanceLevel)
	b.WriteString("## Confirm identity out-of-band (important)\n\n")
	b.WriteString("The kit proves INTEGRITY. To also trust IDENTITY, confirm the author key\n")
	b.WriteString("fingerprint below through a SEPARATE channel (a call, Signal, a known web\n")
	b.WriteString("page) — NOT from this kit:\n\n")
	fmt.Fprintf(&b, "    author %s fingerprint: %s\n\n", authorID, authorFP)
	b.WriteString("If that fingerprint matches AND verify.sh exits 0, the bundle is authentic and unmodified.\n")
	if hasRevocations {
		b.WriteString("\n## Revocation\n\nThis kit includes a signed `revocations.json`; verify.sh enforces it offline.\n")
		b.WriteString("A revoked bundle exits 17; a forged/untrusted revocation list exits 12.\n")
	}
	b.WriteString("\n---\nGenerated by `skillctl export-verification-kit` (SPEC-0276).\n")
	return b.String()
}

// renderVerifyScript writes a POSIX verify.sh that resolves paths relative to
// itself so the kit is location-independent.
func renderVerifyScript(skbName string, hasRevocations bool) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n")
	b.WriteString("# Trustless offline verification — no network; trust only the pinned key.\n")
	b.WriteString("set -eu\n")
	b.WriteString("DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n")
	fmt.Fprintf(&b, "skillctl verify --bundle \"$DIR/%s\" --trust-roots \"$DIR/trust-roots.pinned.yaml\"", skbName)
	if hasRevocations {
		b.WriteString(" --revocations \"$DIR/revocations.json\"")
	}
	b.WriteString("\n")
	return b.String()
}

// secretPatterns is a conservative, low-false-positive set. Substring matches
// are case-insensitive; the goal is to catch a private key or live token that a
// generated kit file should never contain.
var secretPatterns = []string{
	"-----begin", // any PEM key block
	"private key",
	"x-api-key",
	"er1_api_key",
	"device_token_secret",
	"authorization: bearer",
	"sk_live_", "sk_test_", "ghp_", "xoxb-", "aws_secret_access_key",
}

// scrubSecrets refuses a kit file whose bytes contain an obvious secret. The
// .skb blob is exempt (see runExportKit) — this scans only the text artifacts
// the kit GENERATES, which must be safe to email/publish (SPEC-0276 R4.3.2).
func scrubSecrets(name string, data []byte) error {
	lower := bytes.ToLower(data)
	for _, pat := range secretPatterns {
		if bytes.Contains(lower, []byte(pat)) {
			return fmt.Errorf("secret-scrub: %s appears to contain a secret (matched %q); refusing to package", name, pat)
		}
	}
	return nil
}

// zipDir writes every file in dir to zipPath, preserving verify.sh's exec bit.
func zipDir(dir, zipPath string) error {
	zf, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	defer zw.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		hdr := &zip.FileHeader{Name: e.Name(), Method: zip.Deflate}
		if e.Name() == "verify.sh" {
			hdr.SetMode(0o755)
		} else {
			hdr.SetMode(0o644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}
