package install

// offline_verify.go — network-free §7 verification (SPEC-0247 P1.x).
//
// VerifyInstalled (install.go) re-fetches BundleMeta + the author identity from
// the registry on every call. For a per-invocation gate that is too slow and
// fails whenever the laptop is offline. This file lets the verifier run with NO
// network by stashing the registry's metadata at install time and reading it
// back from disk.
//
// It also defines the content-binding shared by EVERY managed-verify path:
// verify.Verify checks the .skb's OWN signature + digest, but NOT that the
// extracted on-disk files (the SKILL.md Claude actually loads) still match that
// signed .skb. So editing the body post-install would pass verify alone.
// verifyExtractedMatchesBlob re-reads the signature-verified .skb and asserts
// every on-disk file byte-matches it — making "edited body → exit 10"
// (SPEC-0247 AC-1) actually hold. SEC-M4: install.VerifyInstalled (the ONLINE
// path) now calls it unconditionally too, so the binding is enforced online +
// offline + sidecar.
//
// Offline tradeoff: a revocation or governance change posted AFTER install is
// not seen (the stashed identity's RevokedAt is frozen at install). The online
// path (SessionStart sweep) remains the revocation authority; offline is the
// fast per-invocation gate + the offline-resilience fallback.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// offlineMetaFile is the stash written next to the .skb in the installed dir.
const offlineMetaFile = ".skillctl-offline.json"

// ErrNoOfflineMeta means the install predates offline-verify (or the stash was
// removed): callers should fall back to the online path.
var ErrNoOfflineMeta = errors.New("no stashed offline metadata")

// OfflineMeta is the on-disk stash: the registry envelope plus the identities
// (author) the verifier needs to check the author signature offline.
type OfflineMeta struct {
	BundleMeta *registry.BundleMeta          `json:"bundle_meta"`
	Identities map[string]*registry.Identity `json:"identities"`
	StashedAt  string                        `json:"stashed_at"`
}

// identityResolver is the subset of *registry.Client StashOfflineMeta needs.
type identityResolver interface {
	GetIdentity(ctx context.Context, id string) (*registry.Identity, error)
}

// staticIdentityFetcher serves identities from the stash — satisfies the
// verify package's identityFetcher interface with no network.
type staticIdentityFetcher struct{ m map[string]*registry.Identity }

func (s staticIdentityFetcher) GetIdentity(_ context.Context, id string) (*registry.Identity, error) {
	if v, ok := s.m[id]; ok && v != nil {
		return v, nil
	}
	return nil, fmt.Errorf("offline: identity %q not stashed", id)
}

// StashOfflineMeta writes BundleMeta + the author identity into the installed
// dir. Best-effort: callers log-and-continue on error (offline verify then
// falls back to online).
func StashOfflineMeta(ctx context.Context, resolver identityResolver, target string, meta *registry.BundleMeta, now func() time.Time) error {
	if meta == nil {
		return errors.New("stash: nil BundleMeta")
	}
	if now == nil {
		now = time.Now
	}
	idents := map[string]*registry.Identity{}
	for _, s := range meta.Signatures {
		if s.Role == "author" && s.IdentityID != "" {
			id, err := resolver.GetIdentity(ctx, s.IdentityID)
			if err != nil {
				return fmt.Errorf("stash: fetch author identity %s: %w", s.IdentityID, err)
			}
			idents[s.IdentityID] = id
		}
	}
	om := OfflineMeta{BundleMeta: meta, Identities: idents, StashedAt: now().UTC().Format(time.RFC3339)}
	b, err := json.MarshalIndent(om, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(target, offlineMetaFile), b, 0o644)
}

func readOfflineMeta(target string) (*OfflineMeta, error) {
	b, err := os.ReadFile(filepath.Join(target, offlineMetaFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoOfflineMeta
	}
	if err != nil {
		return nil, err
	}
	var om OfflineMeta
	if err := json.Unmarshal(b, &om); err != nil {
		return nil, fmt.Errorf("offline meta parse: %w", err)
	}
	if om.BundleMeta == nil {
		return nil, ErrNoOfflineMeta
	}
	return &om, nil
}

// VerifyInstalledOffline re-runs §7 against an installed skill with NO network,
// then binds the extracted content to the signed .skb. Returns ErrNoOfflineMeta
// when there is no stash (caller should fall back to VerifyInstalled).
func VerifyInstalledOffline(opts Opts) (*verify.VerifyResult, error) {
	if opts.Name == "" {
		return nil, errors.New("verify-offline: Name is required")
	}
	if opts.TrustRoot == nil {
		return nil, errors.New("verify-offline: TrustRoot is required")
	}
	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(homeDir, installRoot, sanitizeFilename(opts.Name))
	skbPath, err := findStashedSkb(target)
	if err != nil {
		return nil, err
	}
	om, err := readOfflineMeta(target)
	if err != nil {
		return nil, err
	}

	res, err := verify.Verify(verify.VerifyOpts{
		BundlePath:      skbPath,
		BundleMeta:      om.BundleMeta,
		TrustRoot:       opts.TrustRoot,
		IdentityFetcher: staticIdentityFetcher{m: om.Identities},
		Ctx:             context.Background(),
		GovernanceMin:   opts.GovernanceMin,
		AllowYellow:     opts.AllowYellow,
		Tenant:          opts.Tenant,
		Logger:          opts.Logger,
	})
	if err != nil {
		return nil, err
	}
	// Content-binding: the .skb is now signature-verified, so its contents are
	// canonical. The extracted on-disk files MUST match them.
	if err := verifyExtractedMatchesBlob(skbPath, target); err != nil {
		return nil, err
	}
	return res, nil
}

// VerifyInstalledSidecar verifies a skill installed via the self/ER1 pull path
// (SPEC-0225) — which writes a `.m3c-provenance.json` sidecar rather than the
// SPEC-0188 registry envelope. With no signature bytes on hand (the sidecar
// stores only fingerprints), the offline checks available are:
//
//   - content-binding: the stashed .skb is the canonical body, and the
//     extracted on-disk files MUST byte-match it → catches tampering (exit 10).
//     This is MANDATORY: a sidecar with NO stashed .skb has a fully unverified
//     body, so it FAILS CLOSED (exit 10) rather than passing on governance +
//     fingerprint alone (SEC-M5);
//   - governance floor: the attested level MUST meet the trust-root minimum
//     (exit 13).
//
// Returns registry.ErrNoSidecar when there is no sidecar (caller falls back).
func VerifyInstalledSidecar(opts Opts) error {
	if opts.Name == "" {
		return errors.New("verify-sidecar: Name is required")
	}
	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return err
	}
	target := filepath.Join(homeDir, installRoot, sanitizeFilename(opts.Name))

	b, err := os.ReadFile(filepath.Join(target, registry.ProvenanceSidecarName))
	if errors.Is(err, os.ErrNotExist) {
		return registry.ErrNoSidecar
	}
	if err != nil {
		return err
	}
	var side registry.ProvenanceSidecar
	if err := json.Unmarshal(b, &side); err != nil {
		return fmt.Errorf("verify-sidecar: parse provenance: %w", err)
	}

	// SEC-M5: content-binding is MANDATORY for any sidecar PASS. Without a
	// stashed .skb the on-disk body is fully unverified — there is no canonical
	// blob to compare against — so we FAIL CLOSED (exit 10) instead of trusting
	// governance + fingerprint alone. A present .skb is byte-matched against the
	// extraction; any mismatch is verify.ErrDigestMismatch.
	skbPath, err := findStashedSkb(target)
	if err != nil {
		return fmt.Errorf("verify-sidecar: no stashed .skb to bind the on-disk body to (body unverified, refusing): %w", verify.ErrDigestMismatch)
	}
	if err := verifyExtractedMatchesBlob(skbPath, target); err != nil {
		return err // verify.ErrDigestMismatch
	}

	// Registry-trust gate (SPEC-0247 OQ-5): the provenance records the
	// trust-roots fingerprint the bundle was pulled under; it MUST match a
	// currently-pinned self trust-root. A mismatch means the skill was pulled
	// under a root that is no longer the trusted one (rotation / different
	// machine) → ErrRegistryNotTrusted. If the local self trust-roots are
	// absent/unreadable we cannot compare → skip (content-binding still guards
	// integrity); we never fail merely because the config isn't where expected.
	if side.TrustRootsFingerprint != "" {
		trPath := opts.SelfTrustRootsPath
		if trPath == "" {
			trPath = filepath.Join(homeDir, ".claude", "trust-roots.yaml")
		}
		if str, lerr := registry.LoadSelfTrustRoots(trPath); lerr == nil && str.Fingerprint != "" {
			if str.Fingerprint != side.TrustRootsFingerprint {
				return fmt.Errorf("verify-sidecar: provenance trust-roots fp %s does not match pinned %s: %w",
					side.TrustRootsFingerprint, str.Fingerprint, verify.ErrRegistryNotTrusted)
			}
		}
	}

	// Governance floor.
	floor := opts.GovernanceMin
	if floor == "" && opts.TrustRoot != nil {
		floor = opts.TrustRoot.GovernanceMinimum
	}
	if floor == "" {
		floor = "green"
	}
	if govRank(side.GovernanceLevel) < govRank(floor) {
		return fmt.Errorf("verify-sidecar: governance %q below floor %q: %w",
			side.GovernanceLevel, floor, verify.ErrGovernanceBelowMin)
	}
	return nil
}

// govRank orders governance levels; unknown/empty is lowest (fail-closed).
func govRank(level string) int {
	switch level {
	case "green":
		return 2
	case "yellow":
		return 1
	default:
		return 0
	}
}

func findStashedSkb(target string) (string, error) {
	st, err := os.Stat(target)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("verify-offline: %s is not a directory", target)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".skb") {
			return filepath.Join(target, e.Name()), nil
		}
	}
	return "", fmt.Errorf("verify-offline: no .skb in %s", target)
}

// verifyExtractedMatchesBlob asserts every regular file in the signed .skb
// byte-matches the on-disk extraction, and that no unexpected regular file was
// added. Any mismatch / missing / extra maps to verify.ErrDigestMismatch (exit
// 10) — i.e. "the body Claude would load is not what was signed."
//
// SEC-M1/M6: this runs on the HOT per-invocation gate path (every skill use),
// so the gzip+tar walk MUST be bounded against a decompression bomb. Each entry
// is read through an io.LimitReader against a running total with a 100 MiB
// ceiling (MaxExtractedBytes) plus a file-count cap (MaxExtractedFiles), the
// same caps install.go's extractTGZ enforces. An overrun aborts with
// verify.ErrDigestMismatch (the body cannot be what was signed).
func verifyExtractedMatchesBlob(skbPath, target string) error {
	blob, err := os.ReadFile(skbPath)
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("%w: gzip: %v", verify.ErrDigestMismatch, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	// Pass 1: stream every regular bundle entry through a capped reader, hashing
	// it. We key the resulting digests by the cleaned tar path; the on-disk
	// reconciliation (and any top-level-dir stripping) happens after, once we
	// know all entries. Hashes are 32 bytes each, so the map is bounded by the
	// file-count cap — the byte ceiling guards the per-entry reads themselves.
	var read int64
	var entries int
	bundleDigests := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: tar: %v", verify.ErrDigestMismatch, err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		entries++
		if entries > MaxExtractedFiles {
			return fmt.Errorf("%w: bundle entry count exceeds %d (likely a tar bomb)", verify.ErrDigestMismatch, MaxExtractedFiles)
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("%w: bundle entry %q escapes", verify.ErrDigestMismatch, hdr.Name)
		}

		// Cap this entry's read against the remaining global budget. LimitReader
		// to remaining+1 so we can detect (n > remaining) → overrun, exactly as
		// install.go's extractTGZ does.
		remaining := MaxExtractedBytes - read
		if remaining <= 0 {
			return fmt.Errorf("%w: extracted size exceeds %d bytes (likely a gzip bomb)", verify.ErrDigestMismatch, MaxExtractedBytes)
		}
		want := sha256.New()
		n, err := io.Copy(want, io.LimitReader(tr, remaining+1))
		if err != nil {
			return fmt.Errorf("%w: read bundle entry %q: %v", verify.ErrDigestMismatch, clean, err)
		}
		if n > remaining {
			return fmt.Errorf("%w: extracted size exceeds %d bytes (likely a gzip bomb)", verify.ErrDigestMismatch, MaxExtractedBytes)
		}
		read += n
		bundleDigests[clean] = want.Sum(nil)
	}

	// SPEC §3.1 tars carry a single top-level <name>-<version>/ dir, which the
	// installer strips when it renames the bundle into place (resolveBundleTopLevel).
	// Mirror that here so the bundle paths line up with the flat on-disk layout;
	// flat bundles (no common top-level dir) are left untouched.
	prefix := commonTopLevelDir(bundleDigests)
	expected := make(map[string]bool, len(bundleDigests))
	for name, want := range bundleDigests {
		rel := name
		if prefix != "" {
			rel = filepath.Clean(strings.TrimPrefix(name, prefix+string(filepath.Separator)))
		}
		expected[rel] = true
		got, err := fileSHA(filepath.Join(target, rel))
		if err != nil {
			return fmt.Errorf("%w: installed file %q missing/unreadable: %v", verify.ErrDigestMismatch, rel, err)
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("%w: installed file %q does not match the signed bundle", verify.ErrDigestMismatch, rel)
		}
	}

	// Extra-file check: a regular file on disk that is NOT in the bundle (and
	// is not the .skb or the offline stash) is tampering.
	return filepath.WalkDir(target, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == offlineMetaFile || base == registry.ProvenanceSidecarName || base == ".DS_Store" || strings.HasSuffix(base, ".skb") {
			return nil
		}
		rel, _ := filepath.Rel(target, p)
		if !expected[filepath.Clean(rel)] {
			return fmt.Errorf("%w: unexpected installed file %q not in the signed bundle", verify.ErrDigestMismatch, rel)
		}
		return nil
	})
}

// commonTopLevelDir returns the single top-level directory component shared by
// every bundle path, or "" when there is none (a flat bundle, or entries spread
// across multiple top-level dirs). This mirrors install.go's resolveBundleTopLevel
// so content-binding compares against the same flat layout the installer wrote.
func commonTopLevelDir(paths map[string][]byte) string {
	if len(paths) == 0 {
		return ""
	}
	prefix := ""
	for name := range paths {
		first := name
		if i := strings.IndexRune(name, filepath.Separator); i >= 0 {
			first = name[:i]
		} else {
			// A file sitting at the bundle root → no shared top-level dir.
			return ""
		}
		if prefix == "" {
			prefix = first
		} else if prefix != first {
			return ""
		}
	}
	return prefix
}

func fileSHA(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
