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
	"bytes"
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

	"github.com/kamir/m3c-tools/pkg/skillbundle"
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
	canon, err := CanonicalSkillName(opts.Name) // SEC F12: same fixed point the gate/loader use
	if err != nil {
		return nil, err
	}
	target := filepath.Join(homeDir, installRoot, canon)
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
	canon, err := CanonicalSkillName(opts.Name) // SEC F12: same fixed point the gate/loader use
	if err != nil {
		return err
	}
	target := filepath.Join(homeDir, installRoot, canon)

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

	trPath := opts.SelfTrustRootsPath
	if trPath == "" {
		trPath = filepath.Join(homeDir, ".claude", "trust-roots.yaml")
	}

	// SPEC-0266 F2/F19: re-anchor to the PINNED key. Content-binding above proves
	// the on-disk body matches the stashed .skb, but NOT that that .skb is the one
	// a pinned key signed — a local-write attacker can repack a self-consistent
	// .skb + sidecar (and flip governance). When the SIGNED attestation stash is
	// present we replay the pull gates against the pinned self trust-root: a
	// repacked .skb fails (no valid signature over its bytes) and governance is
	// taken from the SIGNED attestation, never the attacker-writable sidecar.
	//
	// governanceLevel defaults to the (unsigned) sidecar value only on the LEGACY
	// path (installs predating the re-anchor) — those WARN + reinstall-to-anchor.
	governanceLevel := side.GovernanceLevel
	if ac, aerr := registry.ReadAttestationStash(target); aerr == nil {
		// Trust-roots are MANDATORY to re-anchor (policy: parity with the HTTP
		// path, which errors when the root is nil). Fail closed if absent.
		str, lerr := registry.LoadSelfTrustRoots(trPath)
		if lerr != nil || str == nil || len(str.PubKey()) == 0 {
			return fmt.Errorf("verify-sidecar: self trust-roots required to re-anchor %q but unavailable (%v): %w",
				opts.Name, lerr, verify.ErrRegistryNotTrusted)
		}
		skbBytes, rerr := os.ReadFile(skbPath)
		if rerr != nil {
			return fmt.Errorf("verify-sidecar: read stashed .skb: %w", rerr)
		}
		level, verr := ac.Reverify(str.PubKey(), skbBytes)
		if verr != nil {
			// Repacked .skb or forged governance → the body Claude would load is
			// not what the pinned key signed. Map to a digest mismatch (exit 10).
			return fmt.Errorf("%w: re-anchor: %v", verify.ErrDigestMismatch, verr)
		}
		governanceLevel = level // SIGNED governance level (F19)
	} else if errors.Is(aerr, registry.ErrNoAttestationStash) {
		// Legacy install (predates the re-anchor): WARN + content-binding only,
		// and keep the optional fingerprint check below. Reinstall re-anchors it.
		if opts.Logger != nil {
			fmt.Fprintf(opts.Logger, "verify-sidecar: WARN %q is not re-anchored (no signed attestation stash) — verified by content-binding only; run `skillctl install %s` to re-anchor (SPEC-0266)\n", opts.Name, opts.Name)
		}
		// Registry-trust gate (SPEC-0247 OQ-5), legacy path: if the provenance
		// records a fingerprint and local self trust-roots exist, they MUST match
		// (rotation / wrong-machine guard). Absent trust-roots → skip (legacy
		// installs predate the mandatory requirement; content-binding still guards).
		if side.TrustRootsFingerprint != "" {
			if str, lerr := registry.LoadSelfTrustRoots(trPath); lerr == nil && str.Fingerprint != "" {
				if str.Fingerprint != side.TrustRootsFingerprint {
					return fmt.Errorf("verify-sidecar: provenance trust-roots fp %s does not match pinned %s: %w",
						side.TrustRootsFingerprint, str.Fingerprint, verify.ErrRegistryNotTrusted)
				}
			}
		}
	} else {
		return fmt.Errorf("verify-sidecar: read attestation stash: %w", aerr)
	}

	// Governance floor — checked against the SIGNED level when re-anchored.
	floor := opts.GovernanceMin
	if floor == "" && opts.TrustRoot != nil {
		floor = opts.TrustRoot.GovernanceMinimum
	}
	if floor == "" {
		floor = "green"
	}
	if govRank(governanceLevel) < govRank(floor) {
		return fmt.Errorf("verify-sidecar: governance %q below floor %q: %w",
			governanceLevel, floor, verify.ErrGovernanceBelowMin)
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
// SPEC-0252 C3: this runs on the HOT per-invocation gate path (every skill
// use), and the gzip/tar walk, the decompression-bomb caps, the path-escape
// proof, and the wrapper-strip are all skillbundle.Unpack's now. The payoff is
// not just dedup: the integrity check and the installer (registry.extractSkb /
// install.extractTGZ) that wrote these files now share ONE wrapper rule and ONE
// sanitiser, so they can no longer disagree on which files belong to the
// bundle. StripWrapper mirrors the flat on-disk layout the installer renames
// into place; any walk/cap/escape failure maps to ErrDigestMismatch.
func verifyExtractedMatchesBlob(skbPath, target string) error {
	blob, err := os.ReadFile(skbPath)
	if err != nil {
		return err
	}
	entries, err := skillbundle.Unpack(blob, skillbundle.UnpackOptions{StripWrapper: true})
	if err != nil {
		return fmt.Errorf("%w: %v", verify.ErrDigestMismatch, err)
	}

	expected := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		expected[e.Rel] = true
		want := sha256.Sum256(e.Content)
		onDisk, err := skillbundle.SafeJoin(target, e.Rel)
		if err != nil {
			return fmt.Errorf("%w: bundle entry %q: %v", verify.ErrDigestMismatch, e.Rel, err)
		}
		got, err := fileSHA(onDisk)
		if err != nil {
			return fmt.Errorf("%w: installed file %q missing/unreadable: %v", verify.ErrDigestMismatch, e.Rel, err)
		}
		if !bytes.Equal(want[:], got) {
			return fmt.Errorf("%w: installed file %q does not match the signed bundle", verify.ErrDigestMismatch, e.Rel)
		}
	}

	// Extra-file check: a regular file on disk that is NOT in the bundle (and
	// is not the .skb or the offline stash) is tampering. expected keys are
	// slash-form (Unpack's Rel), so normalise the walked path before lookup.
	return filepath.WalkDir(target, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == offlineMetaFile || base == registry.ProvenanceSidecarName || base == registry.AttestationStashName || base == ".DS_Store" || strings.HasSuffix(base, ".skb") {
			return nil
		}
		rel, _ := filepath.Rel(target, p)
		if !expected[filepath.ToSlash(filepath.Clean(rel))] {
			return fmt.Errorf("%w: unexpected installed file %q not in the signed bundle", verify.ErrDigestMismatch, rel)
		}
		return nil
	})
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
