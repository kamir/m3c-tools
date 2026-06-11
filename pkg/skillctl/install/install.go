// Package install implements the SPEC-0188 §7 client install pipeline.
//
// The pipeline composes pkg/skillctl/registry (HTTP client) and
// pkg/skillctl/verify (the §7 algorithm) and adds the side-effecting
// steps the verifier deliberately stays clear of:
//
//   - Stage the bundle in ~/.claude/skills/.tmp/<name>-<digest>/
//   - Run Verify(). Any failure → cleanup .tmp; refuse to write the
//     real ~/.claude/skills/<name>/.
//   - Extract gzip+tar with hardened path validation (no traversal, no
//     symlinks, no oversized payloads).
//   - Validate CHECKSUMS if present.
//   - Atomic rename .tmp → ~/.claude/skills/<name>/. If a previous version
//     exists, archive it to ~/.claude/skills/.archive/<name>-<old-digest>/
//     first.
//
// The order matters: Verify runs BEFORE extraction. We never expose
// untrusted file content to the filesystem outside .tmp, and even .tmp is
// scrubbed on every failure. The atomic rename only fires on full success.
package install

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// MaxExtractedBytes / MaxExtractedFiles are the install-package spelling of the
// canonical extraction caps, which now live in pkg/skillbundle (SPEC-0252 §3.3 —
// one source of truth). Aliases, not duplicate literals; the gzip/tar-bomb
// guards in skillbundle.Unpack enforce them. MaxExtractedBytes stays the default
// for Opts.MaxExtractedBytes (0 → this); kept so existing call sites and tests
// read the same number.
const (
	MaxExtractedBytes int64 = skillbundle.DefaultMaxExtractedBytes
	MaxExtractedFiles       = skillbundle.DefaultMaxExtractedFiles
)

// installRoot is the user's skills install dir, relative to $HOME. The
// per-machine state lives at <home>/<installRoot>; the helpers below all
// derive paths off this single anchor. We deliberately keep it loose
// (just a string) so tests can supply an alternate root via Opts.HomeDir.
const installRoot = ".claude/skills"

// Opts is the input bag for Install. The CLI populates this from flags;
// tests supply a temp HomeDir, an injected Client, and a fake clock.
type Opts struct {
	// Name is the bundle name to install (e.g. "fetch-contract").
	// Required.
	Name string

	// Version is the human version string ("1.0.0") OR a digest pin
	// ("sha256:abc..."). Empty means "newest admitted version" via
	// ResolveByName.
	Version string

	// Client is the registry HTTP client. Tests inject an
	// httptest-backed Client; the CLI builds one from --registry +
	// trust-roots.
	Client *registry.Client

	// TrustRoot is the matched trust-root entry that pins the registry
	// keys + governance minimum.
	TrustRoot *verify.TrustRoot

	// HomeDir is the install anchor. Defaults to os.UserHomeDir() when
	// empty. Tests pass a temp dir.
	HomeDir string

	// SelfTrustRootsPath overrides the SPEC-0225 self trust-roots location
	// (default ~/.claude/trust-roots.yaml) used by VerifyInstalledSidecar's
	// registry-trust check (SPEC-0247 OQ-5). Empty = default. Tests inject one.
	SelfTrustRootsPath string

	// MaxExtractedBytes overrides the gzip-bomb cap. 0 = use default.
	MaxExtractedBytes int64

	// GovernanceMin overrides TrustRoot.GovernanceMinimum.
	GovernanceMin string

	// AllowYellow / IgnoreDeps mirror the verifier flags. The audit
	// (overrides.go) runs BEFORE Verify when either is set.
	AllowYellow bool
	IgnoreDeps  bool

	// Tenant is the resolved tenant scope for this install/verify call
	// (SPEC-0188 §7 step 5.5, G-18 closure 2026-05-06). The CLI resolves
	// this from `--tenant <id>` with fallback to TrustRoots.TenantScope.
	// Empty = untenanted; the verifier's tenant-block check is a no-op.
	// Non-empty triggers a scan of BundleMeta.Attestations for tenant-
	// scoped red verdicts; any match fails closed with verify.ErrTenantBlocked
	// (exit code 16).
	Tenant string

	// AuditPoster, if non-nil, is called when AllowYellow or IgnoreDeps
	// is set so the override is durably logged before the install
	// proceeds. Production wires this to PostAuditEntry (overrides.go);
	// tests can supply a stub. SPEC-0188 §11 mandates the audit happens
	// BEFORE the override takes effect.
	AuditPoster func(ctx context.Context, entry AuditEntry) error

	// Logger captures structured log lines from each install + verify
	// step. The CLI passes os.Stderr behind --verbose.
	Logger io.Writer

	// Now is the wall clock; defaults to time.Now. Pulled out for
	// deterministic test output (audit timestamps).
	Now func() time.Time

	// Ctx scopes the registry roundtrips. context.Background() is used
	// when zero.
	Ctx context.Context
}

// Result is what a successful install returns to the CLI for printing.
type Result struct {
	// Verify is the underlying chain summary the verifier produced.
	Verify *verify.VerifyResult

	// InstalledPath is the absolute path the bundle was extracted to,
	// e.g. /Users/me/.claude/skills/fetch-contract.
	InstalledPath string

	// ArchivedPath is the path the previous version was moved to, if
	// any. Empty when no prior install existed.
	ArchivedPath string
}

// Install runs the full §7 client pipeline end-to-end.
//
// Returns a Result on success; on failure returns an error whose ExitCode
// (verify.ExitCode) is the numeric process exit code. The CLI is expected
// to call os.Exit(verify.ExitCode(err)).
//
// On any failure the staging dir is removed; ~/.claude/skills/<name>/ is
// never touched in a partial state. The atomic rename only fires after
// Verify succeeds AND extraction validates.
func Install(opts Opts) (*Result, error) {
	if err := validateOpts(&opts); err != nil {
		return nil, err
	}
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	// ----- audit overrides BEFORE proceeding -----
	// SPEC-0188 §11: --allow-yellow and --ignore-deps require an
	// auditable trail. Failure to record the audit is a refuse-to-install
	// signal; we don't want to ship "yellow override happened, but the
	// audit row never landed" — that's exactly the silent footgun the
	// gate is supposed to prevent.
	if opts.AllowYellow || opts.IgnoreDeps {
		if opts.AuditPoster == nil {
			return nil, errors.New("install: --allow-yellow / --ignore-deps require an AuditPoster (refusing to override silently)")
		}
		entry := AuditEntry{
			Action:      overrideAction(opts),
			Name:        opts.Name,
			Version:     opts.Version,
			AllowYellow: opts.AllowYellow,
			IgnoreDeps:  opts.IgnoreDeps,
			RecordedAt:  now().UTC().Format(time.RFC3339),
			Origin:      "skillctl",
			RegistryURL: opts.TrustRoot.RegistryURL,
		}
		if err := opts.AuditPoster(ctx, entry); err != nil {
			return nil, fmt.Errorf("install: audit POST failed (refusing to honor override): %w", err)
		}
		logStep(opts.Logger, "override_audited", "allow_yellow=%v ignore_deps=%v", opts.AllowYellow, opts.IgnoreDeps)
	}

	// ----- resolve <name>@<version> -----
	digest, resolvedVersion, err := resolveDigest(ctx, opts.Client, opts.Name, opts.Version)
	if err != nil {
		return nil, err
	}
	logStep(opts.Logger, "resolved", "digest=%s version=%s", digest, resolvedVersion)

	// ----- stage -----
	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	stagingDir, err := makeStagingDir(homeDir, opts.Name, digest)
	if err != nil {
		return nil, err
	}
	cleanedUp := false
	defer func() {
		// Belt-and-braces: if the function returns early, scrub the
		// staging dir. The happy path manually removes it after the
		// atomic rename moves the contents out; in that case the
		// directory is already gone and RemoveAll is a no-op.
		if !cleanedUp {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	// ----- fetch blob to staging -----
	blob, err := opts.Client.GetBundle(ctx, digest)
	if err != nil {
		// 404 on the blob path → ErrBlobMissing per S7 brief.
		if errors.Is(err, registry.ErrNotFound) {
			return nil, fmt.Errorf("install: blob %s: %w", digest, verify.ErrBlobMissing)
		}
		return nil, fmt.Errorf("install: fetch blob: %w", err)
	}
	blobPath := filepath.Join(stagingDir, sanitizeFilename(opts.Name)+"-"+sanitizeFilename(resolvedVersion)+".skb")
	if err := os.WriteFile(blobPath, blob, 0o644); err != nil {
		return nil, fmt.Errorf("install: write staged blob: %w", err)
	}
	logStep(opts.Logger, "staged_blob", "path=%s size=%d", blobPath, len(blob))

	// ----- fetch metadata -----
	meta, err := opts.Client.GetBundleMeta(ctx, digest)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return nil, fmt.Errorf("install: meta %s: %w", digest, verify.ErrBlobMissing)
		}
		return nil, fmt.Errorf("install: fetch meta: %w", err)
	}

	// ----- verify -----
	verifyOpts := verify.VerifyOpts{
		BundlePath:      blobPath,
		BundleMeta:      meta,
		TrustRoot:       opts.TrustRoot,
		IdentityFetcher: opts.Client,
		Ctx:             ctx,
		GovernanceMin:   opts.GovernanceMin,
		AllowYellow:     opts.AllowYellow,
		IgnoreDeps:      opts.IgnoreDeps,
		Tenant:          opts.Tenant,
		Logger:          opts.Logger,
	}
	verRes, err := verify.Verify(verifyOpts)
	if err != nil {
		return nil, err
	}

	// ----- extract -----
	extractDir := filepath.Join(stagingDir, "extracted")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return nil, fmt.Errorf("install: mkdir extract dir: %w", err)
	}
	cap := opts.MaxExtractedBytes
	if cap <= 0 {
		cap = MaxExtractedBytes
	}
	if err := extractTGZ(blob, extractDir, cap); err != nil {
		return nil, err
	}
	logStep(opts.Logger, "extracted", "dir=%s", extractDir)

	// ----- validate CHECKSUMS if present -----
	if err := validateChecksumsIfPresent(extractDir); err != nil {
		return nil, err
	}

	// ----- atomic install + archive prior version if any -----
	target := filepath.Join(homeDir, installRoot, sanitizeFilename(opts.Name))
	archivedPath, err := atomicInstall(extractDir, target, homeDir, opts.Name, digest)
	if err != nil {
		return nil, err
	}

	// Stash the original .skb inside the install target so that
	// `skillctl verify <name>` can recompute the digest later without
	// re-fetching from the registry. We copy bytes (rather than rename
	// the staged file) because the staging dir is about to be removed.
	stashedSkb := filepath.Join(target, filepath.Base(blobPath))
	if err := os.WriteFile(stashedSkb, blob, 0o644); err != nil {
		return nil, fmt.Errorf("install: stash .skb in target: %w", err)
	}

	// Stash BundleMeta + author identity for network-free re-verification
	// (SPEC-0247). Best-effort: a failure here just means offline verify
	// falls back to the online path; the install itself still succeeded.
	if err := StashOfflineMeta(ctx, opts.Client, target, meta, now); err != nil {
		logStep(opts.Logger, "offline_meta_warn", "offline verify will fall back to online: %v", err)
	}

	cleanedUp = true
	// Best-effort cleanup of the staging dir (the extract sub-dir was
	// renamed away, so what's left is just the .skb blob plus the
	// staging dir itself).
	_ = os.RemoveAll(stagingDir)

	logStep(opts.Logger, "installed", "path=%s archived=%s", target, archivedPath)
	return &Result{
		Verify:        verRes,
		InstalledPath: target,
		ArchivedPath:  archivedPath,
	}, nil
}

// VerifyInstalled re-runs the §7 chain against an already-installed skill.
// Reads the .skb stashed under <name>/, fetches fresh metadata from the
// registry, and runs Verify. Useful for "did the registry revoke this?"
// checks.
//
// Returns a *verify.VerifyResult on success; the CLI prints the chain
// summary. The function is read-only; nothing on disk is moved or removed.
func VerifyInstalled(opts Opts) (*verify.VerifyResult, error) {
	if opts.Name == "" {
		return nil, errors.New("verify-installed: --name is required")
	}
	if opts.Client == nil {
		return nil, errors.New("verify-installed: Client is required")
	}
	if opts.TrustRoot == nil {
		return nil, errors.New("verify-installed: TrustRoot is required")
	}
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(homeDir, installRoot, sanitizeFilename(opts.Name))
	st, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("verify-installed: %s: %w", target, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("verify-installed: %s is not a directory", target)
	}

	// Find the .skb at the top level.
	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, fmt.Errorf("verify-installed: read %s: %w", target, err)
	}
	var skbPath string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".skb") {
			skbPath = filepath.Join(target, e.Name())
			break
		}
	}
	if skbPath == "" {
		return nil, fmt.Errorf("verify-installed: no .skb found in %s (was this skill installed by skillctl install?)", target)
	}

	// Recompute digest from the on-disk blob; then fetch fresh metadata.
	// We don't trust the local meta (if any) — the whole point of verify
	// is to ask the registry.
	dRaw, dStr, err := computeDigestForVerify(skbPath)
	if err != nil {
		return nil, err
	}
	_ = dRaw // verify.Verify recomputes it independently
	meta, err := opts.Client.GetBundleMeta(ctx, dStr)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return nil, fmt.Errorf("verify-installed: registry no longer has bundle %s: %w", dStr, verify.ErrBlobMissing)
		}
		return nil, fmt.Errorf("verify-installed: fetch meta %s: %w", dStr, err)
	}

	verifyOpts := verify.VerifyOpts{
		BundlePath:      skbPath,
		BundleMeta:      meta,
		TrustRoot:       opts.TrustRoot,
		IdentityFetcher: opts.Client,
		Ctx:             ctx,
		GovernanceMin:   opts.GovernanceMin,
		AllowYellow:     opts.AllowYellow,
		IgnoreDeps:      opts.IgnoreDeps,
		Tenant:          opts.Tenant,
		Logger:          opts.Logger,
	}
	res, err := verify.Verify(verifyOpts)
	if err != nil {
		return nil, err
	}
	// SEC-M4: content-binding is UNCONDITIONAL on EVERY managed-verify path.
	// verify.Verify proved the .skb's own signature + digest, but NOT that the
	// extracted on-disk files (the SKILL.md Claude actually loads) still match
	// that signed .skb. Re-assert the binding here so an edited body on the
	// ONLINE path is caught as verify.ErrDigestMismatch (exit 10) — the same
	// guarantee the offline / sidecar tiers already enforce.
	if err := verifyExtractedMatchesBlob(skbPath, target); err != nil {
		return nil, err
	}
	return res, nil
}

// ----- helpers -----

func validateOpts(opts *Opts) error {
	if opts.Name == "" {
		return errors.New("install: --name is required")
	}
	if opts.Client == nil {
		return errors.New("install: Client is required")
	}
	if opts.TrustRoot == nil {
		return errors.New("install: TrustRoot is required")
	}
	return nil
}

func resolveHomeDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install: resolve home dir: %w", err)
	}
	return h, nil
}

// resolveDigest turns <name>@<version> into a concrete sha256 digest.
//
// Cases:
//   - version == "" → ResolveByName, pick newest "admitted" version.
//   - version starts with "sha256:" → use as-is (immutable pin).
//   - otherwise → ResolveByName, pick the entry whose Version matches.
//
// Returns (digest, resolved-version-string).
func resolveDigest(ctx context.Context, c *registry.Client, name, version string) (string, string, error) {
	if strings.HasPrefix(version, "sha256:") {
		return version, version, nil
	}
	versions, err := c.ResolveByName(ctx, name)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return "", "", fmt.Errorf("install: skill %q not in registry: %w", name, err)
		}
		return "", "", fmt.Errorf("install: resolve %q: %w", name, err)
	}
	if len(versions) == 0 {
		return "", "", fmt.Errorf("install: skill %q has no admitted versions", name)
	}
	if version == "" {
		// Pick newest admitted. Server returns newest-first per S5 contract.
		for _, v := range versions {
			if v.Status == "" || v.Status == "admitted" {
				return v.Digest, v.Version, nil
			}
		}
		return "", "", fmt.Errorf("install: skill %q has no admitted versions", name)
	}
	for _, v := range versions {
		if v.Version == version {
			if v.Status != "" && v.Status != "admitted" {
				return "", "", fmt.Errorf("install: %s@%s status %q (not admitted): %w", name, version, v.Status, verify.ErrBlobMissing)
			}
			return v.Digest, v.Version, nil
		}
	}
	return "", "", fmt.Errorf("install: %s@%s: no matching version", name, version)
}

// makeStagingDir creates ~/.claude/skills/.tmp/<name>-<digest>/.
func makeStagingDir(homeDir, name, digest string) (string, error) {
	tmpRoot := filepath.Join(homeDir, installRoot, ".tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return "", fmt.Errorf("install: mkdir tmp root: %w", err)
	}
	stage := filepath.Join(tmpRoot, sanitizeFilename(name)+"-"+sanitizeDigest(digest))
	// If a prior failed install left the dir behind, scrub it.
	if err := os.RemoveAll(stage); err != nil {
		return "", fmt.Errorf("install: clean stale staging dir %s: %w", stage, err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return "", fmt.Errorf("install: mkdir staging: %w", err)
	}
	return stage, nil
}

// sanitizeFilename strips path-traversal-shaped characters from a string
// before using it as a single path segment. Conservative: anything that
// isn't alnum / dash / underscore / dot is dropped.
//
// We never derive paths from registry-supplied names without going through
// this — the Name field comes from the registry, which we DON'T trust to
// have validated it (defense-in-depth).
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "_"
	}
	// Refuse leading dot to keep the result a non-hidden segment.
	for strings.HasPrefix(out, ".") {
		out = "_" + out[1:]
	}
	return out
}

// sanitizeDigest strips the "sha256:" prefix so the staging path stays
// short and safe across filesystems that disallow ":" (Windows, some FUSE
// drivers).
func sanitizeDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") {
		return "sha256_" + d[len("sha256:"):]
	}
	return sanitizeFilename(d)
}

// extractTGZ decompresses + untars blob into destDir via the ONE hardened core
// (skillbundle.Unpack + ExtractTo): a single decompression pass, the byte
// ceiling + file-count cap, the path-escape proof, symlink/hardlink/device
// refusal, O_EXCL fail-closed writes, and the single scripts/*-0755-else-0644
// mode policy.
//
// SPEC-0252 C4: StripWrapper is FALSE here on purpose. The HTTP install path
// extracts WITH any single top-level wrapper dir and relocates the bundle
// afterwards via resolveBundleTopLevel + the atomic rename into place — unlike
// registry.extractSkb, which strips the wrapper inline. Keeping StripWrapper
// off preserves that flow exactly. maxBytes is the caller's per-install override
// (0 → the core default); the blob bytes are passed directly so we don't re-read
// the staged file.
func extractTGZ(blob []byte, destDir string, maxBytes int64) error {
	entries, err := skillbundle.Unpack(blob, skillbundle.UnpackOptions{MaxBytes: maxBytes})
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return skillbundle.ExtractTo(entries, destDir)
}

// validateChecksumsIfPresent reads the bundle's CHECKSUMS file (if it
// exists) and verifies every entry's SHA-256 against the on-disk content.
//
// Format: each line is "<sha256-hex>  <relative-path>" (two spaces, per
// the GNU coreutils sha256sum convention SPEC §3.1 follows). Lines with a
// '#' prefix or empty lines are skipped.
//
// Missing CHECKSUMS file → success (some bundles may omit it). Mismatches
// → ErrDigestMismatch (per SPEC §7 step 8).
func validateChecksumsIfPresent(extractDir string) error {
	// SPEC §3.1 puts CHECKSUMS at the bundle ROOT — but the tar has the
	// bundle's <name>-<version>/ as its top-level dir. Walk one level
	// down to find it.
	root := extractDir
	if entries, err := os.ReadDir(extractDir); err == nil && len(entries) == 1 && entries[0].IsDir() {
		root = filepath.Join(extractDir, entries[0].Name())
	}
	checksumPath := filepath.Join(root, "CHECKSUMS")
	f, err := os.Open(checksumPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("install: open CHECKSUMS: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept "<hex>  <path>" or "<hex> <path>" (one or two spaces).
		var wantHex, rel string
		if i := strings.Index(line, "  "); i >= 0 {
			wantHex = line[:i]
			rel = strings.TrimSpace(line[i+2:])
		} else if i := strings.Index(line, " "); i >= 0 {
			wantHex = line[:i]
			rel = strings.TrimSpace(line[i+1:])
		} else {
			return fmt.Errorf("install: CHECKSUMS malformed line %q: %w", line, verify.ErrDigestMismatch)
		}
		if rel == "" {
			return fmt.Errorf("install: CHECKSUMS missing path on line %q: %w", line, verify.ErrDigestMismatch)
		}
		// Refuse path-traversal on relative paths inside CHECKSUMS too.
		cleanRel := filepath.Clean(rel)
		if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			return fmt.Errorf("install: CHECKSUMS entry %q escapes root: %w", rel, verify.ErrDigestMismatch)
		}
		if cleanRel == "CHECKSUMS" {
			continue
		}
		fp := filepath.Join(root, cleanRel)
		got, err := fileSHA256Hex(fp)
		if err != nil {
			return fmt.Errorf("install: hash %s: %w", fp, errors.Join(verify.ErrDigestMismatch, err))
		}
		if !strings.EqualFold(got, wantHex) {
			return fmt.Errorf("install: CHECKSUMS mismatch for %s (got %s, want %s): %w", rel, got, wantHex, verify.ErrDigestMismatch)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("install: read CHECKSUMS: %w", err)
	}
	return nil
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// atomicInstall moves extractDir to ~/.claude/skills/<name>/. If a prior
// install exists at the target, archives it to ~/.claude/skills/.archive/
// <name>-<old-name>-<timestamp>/ first.
//
// Returns the archived path (empty if no prior install existed).
//
// Atomicity: the inner content lives in <extractDir>/<name>-<version>/
// per SPEC §3.1's tar layout. We rename that single directory into place;
// the parent extractDir gets cleaned up by the caller.
func atomicInstall(extractDir, target, homeDir, name, digest string) (string, error) {
	// Resolve the tar's top-level dir.
	source, err := resolveBundleTopLevel(extractDir)
	if err != nil {
		return "", err
	}
	// Make sure the parent of `target` exists.
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", fmt.Errorf("install: mkdir target parent: %w", err)
	}

	archived := ""
	if st, err := os.Stat(target); err == nil {
		if !st.IsDir() {
			return "", fmt.Errorf("install: target %s exists and is not a directory", target)
		}
		// Archive prior install.
		archDir := filepath.Join(homeDir, installRoot, ".archive")
		if err := os.MkdirAll(archDir, 0o755); err != nil {
			return "", fmt.Errorf("install: mkdir archive dir: %w", err)
		}
		ts := time.Now().UTC().Format("20060102T150405")
		archived = filepath.Join(archDir, sanitizeFilename(name)+"-"+ts)
		if err := os.Rename(target, archived); err != nil {
			return "", fmt.Errorf("install: archive prior install %s → %s: %w", target, archived, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("install: stat target: %w", err)
	}

	if err := os.Rename(source, target); err != nil {
		// Best-effort: restore the archived prior install if we just
		// archived it but the new install rename failed.
		if archived != "" {
			_ = os.Rename(archived, target)
		}
		return "", fmt.Errorf("install: rename %s → %s: %w", source, target, err)
	}
	return archived, nil
}

func resolveBundleTopLevel(extractDir string) (string, error) {
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return "", fmt.Errorf("install: readdir %s: %w", extractDir, err)
	}
	// SPEC §3.1: tar has exactly one top-level dir <name>-<version>/.
	// We don't enforce the name here — we just take the single entry if
	// there is one.
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(extractDir, entries[0].Name()), nil
	}
	// If the bundle's tar didn't follow the layout (legacy or non-S1
	// producer), install the extractDir itself.
	return extractDir, nil
}

// computeDigestForVerify is a small wrapper around signing.ComputeBundleDigest
// kept here so install.go doesn't pull in the signing package directly
// (avoids a fan-out import that becomes painful when signing's API
// stabilizes further). Returns (raw, "sha256:<hex>").
func computeDigestForVerify(path string) ([sha256.Size]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [sha256.Size]byte{}, "", err
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, "sha256:" + hex.EncodeToString(out[:]), nil
}

// httpClientOf is a tiny helper so callers building an Opts.Client for
// the CLI don't redefine the timeout knobs.
func httpClientOf(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = registry.DefaultTimeout
	}
	return &http.Client{Timeout: timeout}
}

// HTTPClientOf is exported for the CLI to share the same default-timeout
// HTTP client without duplicating constants.
func HTTPClientOf(timeout time.Duration) *http.Client {
	return httpClientOf(timeout)
}

// logStep mirrors verify.logStep — kept private here so install lines are
// labeled "install step=..." rather than "verify step=...".
func logStep(w io.Writer, event, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "install step=%s", event)
	if format != "" {
		fmt.Fprint(w, " ")
		fmt.Fprintf(w, format, args...)
	}
	fmt.Fprintln(w)
}
