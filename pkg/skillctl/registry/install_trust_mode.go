package registry

// Trust-mode install for the `self` tenant (SPEC-0225 P3).
//
// Takes a verified, staged .skb (output of PullBundles) and writes it into
// ~/.claude/skills/<name>/ together with a .m3c-provenance.json sidecar. The
// sidecar is what `skillctl audit` re-reads later to confirm the bytes on
// disk are still the trusted bytes — the bridge to SPEC-0202 runtime
// verification.
//
// Overwriting an existing skill follows the G-23 two-step destructive-op
// convention: `--dry-run-install` emits a plan + HMAC token; `--confirm-install
// --dry-run-install-token <sig>` re-derives the same plan, verifies the HMAC,
// and only then writes. Drift in either set ⇒ refuse. Pattern source: SPEC-0188
// §11b; reference impls: `skillctl awareness reset`, `skillctl audit --cleanup`.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// MaxExtractedBytes / MaxExtractedFiles are the registry-package spelling of the
// canonical extraction caps, which now live in pkg/skillbundle (SPEC-0252 §3.3 —
// one source of truth). They are aliases, not duplicate literals: the value is
// defined once in skillbundle and the gzip/tar-bomb guards in skillbundle.Unpack
// enforce it. Retained so existing call sites and tests read the same number.
const (
	MaxExtractedBytes int64 = skillbundle.DefaultMaxExtractedBytes
	MaxExtractedFiles       = skillbundle.DefaultMaxExtractedFiles
)

// ProvenanceSchemaVersion is the schema_version stamped into .m3c-provenance.json.
const ProvenanceSchemaVersion = "1.0.0"

// ProvenanceSidecarName is the per-skill sidecar filename.
const ProvenanceSidecarName = ".m3c-provenance.json"

// ProvenanceSidecar mirrors SPEC-0225 §9.3.
type ProvenanceSidecar struct {
	SchemaVersion         string             `json:"schema_version"`
	Skill                 string             `json:"skill"`
	Version               string             `json:"version"`
	BundleDigest          string             `json:"bundle_digest"`
	Registry              string             `json:"registry"`
	SourceER1ItemID       string             `json:"source_er1_item_id"`
	SourceER1Context      string             `json:"source_er1_context"`
	PulledAt              string             `json:"pulled_at"`
	PulledOnHost          string             `json:"pulled_on_host"`
	TrustRootsFingerprint string             `json:"trust_roots_fingerprint"`
	Signatures            []SignatureSidecar `json:"signatures"`
	GovernanceLevel       string             `json:"governance_level"`
	AttestationER1ItemID  string             `json:"attestation_er1_item_id,omitempty"`
}

// SignatureSidecar carries the per-role identity + fingerprint, NOT the
// signature bytes (those live in the source ER1 item; the sidecar's job is
// to record what was verified, not duplicate it).
type SignatureSidecar struct {
	Role              string `json:"role"`
	IdentityID        string `json:"identity_id"`
	PubKeyFingerprint string `json:"pubkey_fingerprint"`
}

// InstallOpts describes a trust-mode install.
type InstallOpts struct {
	StagedSkbPath         string // path under M3C_SKILL_CACHE_DIR (output of PullBundles)
	Bundle                *StagedBundle
	SkillsDir             string // override; default ~/.claude/skills
	TrustRootsFingerprint string
	ContextID             string
	AllowDowngrade        bool
}

// InstallResult reports what changed.
type InstallResult struct {
	SkillPath      string // ~/.claude/skills/<name>
	ProvenancePath string
	CreatedFresh   bool   // true if no <name>/ existed before
	OverwroteOld   bool   // true if an existing <name>/ was replaced
	OldDigest      string // if OverwroteOld, the previous sidecar's bundle_digest (or "" if unknown)
}

// G-23 destructive-op convention: overwriting an existing skill requires a
// two-step plan → token-consuming-confirm dance. PlanInstall builds the plan
// and the token; ConfirmInstall consumes the token and writes.

// InstallPlan is the dry-run-install output.
type InstallPlan struct {
	Creates    []PlanRow `json:"creates"`
	Overwrites []PlanRow `json:"overwrites"`
	IssuedAt   int64     `json:"issued_at"` // unix seconds; the token TTL anchor
	Token      string    `json:"token"`     // opaque base64; clients pass it verbatim to ConfirmInstall
}

// PlanRow is one skill entry in the plan.
type PlanRow struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	NewDigest  string `json:"new_digest"`
	OldDigest  string `json:"old_digest,omitempty"`
	SkillPath  string `json:"skill_path"`
	NewSize    int64  `json:"new_size"`
	OldVersion string `json:"old_version,omitempty"`
}

// TokenTTL bounds how long a dry-run-install token is valid (5 minutes —
// SPEC-0188 §11b convention).
const TokenTTL = 5 * time.Minute

// PlanInstall computes the create/overwrite plan for a set of staged
// bundles. It does NOT touch disk beyond reading existing sidecars to
// recover the old digest.
func PlanInstall(bundles []*StagedBundle, skillsDir string) (*InstallPlan, error) {
	if skillsDir == "" {
		skillsDir = defaultSkillsDir()
	}
	plan := &InstallPlan{IssuedAt: time.Now().UTC().Unix()}
	for _, b := range bundles {
		target := filepath.Join(skillsDir, b.Name)
		row := PlanRow{
			Name:      b.Name,
			Version:   b.Version,
			NewDigest: b.Digest,
			SkillPath: target,
		}
		if info, err := os.Stat(filepath.Join(target, ProvenanceSidecarName)); err == nil && info.Mode().IsRegular() {
			if pre, err := loadProvenance(filepath.Join(target, ProvenanceSidecarName)); err == nil {
				row.OldDigest = pre.BundleDigest
				row.OldVersion = pre.Version
			}
			plan.Overwrites = append(plan.Overwrites, row)
		} else if _, err := os.Stat(target); err == nil {
			// Skill dir exists but no sidecar — treat as overwrite (untracked).
			plan.Overwrites = append(plan.Overwrites, row)
		} else {
			plan.Creates = append(plan.Creates, row)
		}
		// Best-effort new-size from the staged .skb.
		if st, err := os.Stat(b.StagedSkbPath); err == nil {
			row.NewSize = st.Size()
		}
	}
	tok, err := mintInstallToken(plan)
	if err != nil {
		// SEC-L6: no usable HMAC key ⇒ no token ⇒ the G-23 overwrite cannot be
		// confirmed. Fail closed rather than emitting an unsigned/forgeable plan.
		return nil, err
	}
	plan.Token = tok
	return plan, nil
}

// ConfirmInstall re-derives the plan from the current state, verifies the
// caller's token matches, and only then writes. Drift in the create/overwrite
// set ⇒ refuse with ErrPlanDrift. Stale token ⇒ refuse with ErrTokenExpired.
func ConfirmInstall(bundles []*StagedBundle, providedToken string, opts InstallOpts) ([]*InstallResult, error) {
	// SEC-M9: reject path-traversal / unsafe bundle names BEFORE the G-23
	// overwrite/token gate. PlanInstall joins each name onto the skills dir, so a
	// traversal name (e.g. "..") resolves to an existing parent dir and lands in
	// plan.Overwrites — which would otherwise trip ErrTokenRequired and mask the
	// real ErrUnsafeBundleName. Sanitizing first makes the name guard fail closed
	// the instant a crafted name is seen, regardless of token state.
	for _, b := range bundles {
		if err := sanitizeBundleName(b.Name); err != nil {
			return nil, err
		}
	}
	plan, err := PlanInstall(bundles, opts.SkillsDir)
	if err != nil {
		return nil, err
	}
	if providedToken == "" {
		// If the plan has zero overwrites, the token is not required (creating
		// a fresh skill is non-destructive). Otherwise it IS required.
		if len(plan.Overwrites) > 0 {
			return nil, fmt.Errorf("%w: %d overwrite(s) require --dry-run-install-token", ErrTokenRequired, len(plan.Overwrites))
		}
	} else {
		if err := verifyInstallToken(plan, providedToken); err != nil {
			return nil, err
		}
	}
	// Token check OK (or not needed). Write each.
	var out []*InstallResult
	for _, b := range bundles {
		r, err := installOne(b, opts)
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Errors specific to the G-23 path.
var (
	ErrTokenRequired = errors.New("install: this would overwrite an existing skill — pass the --dry-run-install-token issued by --dry-run-install")
	ErrTokenInvalid  = errors.New("install: --dry-run-install-token is malformed (expected <unix-seconds>.<base64url-signature> from --dry-run-install)")
	ErrTokenExpired  = errors.New("install: --dry-run-install-token has expired (tokens live 5 minutes — re-run --dry-run-install)")
	ErrPlanDrift     = errors.New("install: --dry-run-install-token does not match this install plan — it was forged/tampered, or the plan changed since --dry-run-install")
)

// mintInstallToken HMACs the canonical plan summary with a process-stable key,
// prepends the issued_at unix seconds, and base64-encodes. The token shape:
//
//	<issued_at_unix_secs>.<base64-of-HMAC-SHA256(planSummary)>
//
// `planSummary` deliberately excludes NewSize (unstable across stat races) —
// we sign over the set of (name, version, new_digest, old_digest, skill_path)
// rows, sorted by skill_path for determinism.
func mintInstallToken(plan *InstallPlan) (string, error) {
	key, err := installTokenKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(planSummary(plan)))
	sig := mac.Sum(nil)
	return fmt.Sprintf("%d.%s", plan.IssuedAt, base64.RawURLEncoding.EncodeToString(sig)), nil
}

func verifyInstallToken(plan *InstallPlan, provided string) error {
	parts := strings.SplitN(provided, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: malformed (need <issued_at>.<sig>)", ErrTokenInvalid)
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: bad issued_at: %v", ErrTokenInvalid, err)
	}
	if time.Now().UTC().Unix()-issued > int64(TokenTTL.Seconds()) {
		return fmt.Errorf("%w (issued %ds ago, ttl %ds)", ErrTokenExpired, time.Now().UTC().Unix()-issued, int64(TokenTTL.Seconds()))
	}
	expectedPlan := *plan
	expectedPlan.IssuedAt = issued // verify against the issued_at the client carries
	key, err := installTokenKey()
	if err != nil {
		// SEC-L6: no usable key ⇒ we cannot verify ⇒ refuse (fail closed).
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(planSummary(&expectedPlan)))
	wantSig := mac.Sum(nil)
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: bad signature base64: %v", ErrTokenInvalid, err)
	}
	if !hmac.Equal(gotSig, wantSig) {
		return ErrPlanDrift
	}
	return nil
}

func planSummary(p *InstallPlan) string {
	rows := append([]PlanRow{}, p.Creates...)
	rows = append(rows, p.Overwrites...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].SkillPath < rows[j].SkillPath })
	var b bytes.Buffer
	fmt.Fprintf(&b, "issued_at=%d\n", p.IssuedAt)
	for _, r := range rows {
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s\n", r.SkillPath, r.Name, r.Version, r.NewDigest, r.OldDigest)
	}
	return b.String()
}

// installTokenKey returns the HMAC key the install path uses to sign the
// G-23 dry-run-install token. The two-step is intentionally cross-process —
// `--dry-run-install` mints the token in one CLI invocation and prints it, and
// a SEPARATE `--confirm-install` invocation verifies it. A per-process random
// key therefore made the token impossible to validate across the two calls
// (ErrPlanDrift on every overwrite). We instead persist a per-user key (0600)
// so both invocations share it. Replay is bounded by the 5-minute TTL AND by
// the token binding to the exact plan rows (planSummary): a captured token
// only re-validates for an identical install plan inside the window.
//
// SEC-L6: minting a fresh key requires real entropy. If crypto/rand fails we
// FAIL CLOSED (return ErrInstallTokenKey) instead of degrading to a hardcoded,
// world-known fallback key — a known key would let an attacker forge the
// overwrite token and defeat the destructive-op guard. With no usable key the
// token cannot be minted/verified, so the overwrite is refused.
var installTokenKeyValue []byte

// installTokenRand is the entropy source for minting a fresh install-token key.
// It is a package var (defaulting to the OS CSPRNG) so the SEC-L6 fail-closed
// path can be exercised by a test that injects a failing reader. Production
// always uses crypto/rand.Reader.
var installTokenRand io.Reader = rand.Reader

// ErrInstallTokenKey is returned when the install-token HMAC key cannot be
// established — specifically when the OS CSPRNG (crypto/rand) fails while
// minting a fresh per-user key. SEC-L6: we FAIL CLOSED here. The install token
// guards a DESTRUCTIVE overwrite (G-23 two-step); if we cannot mint a key with
// real entropy we must NOT fall back to a hardcoded, world-known sentinel —
// that would let any attacker forge a valid token and defeat the overwrite
// guard. With no usable key the token cannot be minted or verified, so the
// overwrite is refused.
var ErrInstallTokenKey = errors.New("install: cannot establish install-token HMAC key (crypto/rand failed) — refusing to mint/verify a token (overwrite is refused; fail-closed)")

func installTokenKey() ([]byte, error) {
	if installTokenKeyValue != nil {
		return installTokenKeyValue, nil
	}
	home := userHome()
	dir := filepath.Join(home, ".cache", "m3c")
	keyPath := filepath.Join(dir, "install-token.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
		installTokenKeyValue = b
		return installTokenKeyValue, nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(installTokenRand, key); err != nil {
		// SEC-L6: fail closed. NO hardcoded fallback key — a world-known key
		// would let anyone forge the overwrite token. Propagate the error so
		// the destructive overwrite is refused.
		return nil, fmt.Errorf("%w: %v", ErrInstallTokenKey, err)
	}
	installTokenKeyValue = key
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(keyPath, installTokenKeyValue, 0o600)
	return installTokenKeyValue, nil
}

// ErrUnsafeBundleName is returned when a staged bundle's Name would escape the
// skills directory if joined into a path (SEC-M9 path-traversal guard).
var ErrUnsafeBundleName = errors.New("install: bundle name is unsafe (path separators, traversal, or absolute path)")

// sanitizeBundleName fail-closed-rejects a bundle name that could escape the
// skills directory when passed to filepath.Join. Mirrors the gate's name guard
// (registry.validateNameSafe): no '/', '\\', NUL, '..' segments, no absolute
// path, no leading dot-dot. The name must be a single safe path component.
func sanitizeBundleName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrUnsafeBundleName)
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("%w: %q contains a path separator or NUL", ErrUnsafeBundleName, name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %q contains control characters", ErrUnsafeBundleName, name)
		}
	}
	if name == ".." || name == "." || strings.HasPrefix(name, "..") {
		return fmt.Errorf("%w: %q is a traversal segment", ErrUnsafeBundleName, name)
	}
	if filepath.IsAbs(name) {
		return fmt.Errorf("%w: %q is an absolute path", ErrUnsafeBundleName, name)
	}
	// Defense in depth: a cleaned name must remain a single component that does
	// not climb out of a directory.
	if clean := filepath.Clean(name); clean != name || strings.Contains(clean, string(filepath.Separator)) {
		return fmt.Errorf("%w: %q does not clean to a single safe component", ErrUnsafeBundleName, name)
	}
	return nil
}

// installOne does the actual unpack + sidecar write for one staged bundle.
func installOne(b *StagedBundle, opts InstallOpts) (*InstallResult, error) {
	// SEC-M9: refuse an unsanitized bundle name before any filepath.Join so a
	// crafted name (e.g. "../../etc") cannot write outside the skills dir.
	if err := sanitizeBundleName(b.Name); err != nil {
		return nil, err
	}
	skillsDir := opts.SkillsDir
	if skillsDir == "" {
		skillsDir = defaultSkillsDir()
	}
	target := filepath.Join(skillsDir, b.Name)

	// Optional downgrade gate.
	if !opts.AllowDowngrade {
		if pre, err := loadProvenance(filepath.Join(target, ProvenanceSidecarName)); err == nil {
			if compareSemver(b.Version, pre.Version) < 0 {
				return nil, fmt.Errorf("install: refusing to downgrade %s: have %s, new %s (use --allow-downgrade)", b.Name, pre.Version, b.Version)
			}
		}
	}

	skb, err := os.ReadFile(b.StagedSkbPath)
	if err != nil {
		return nil, fmt.Errorf("install: read staged .skb: %w", err)
	}

	// Extract into a temp dir, then atomically rename onto target.
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		return nil, fmt.Errorf("install: mkdir %s: %w", skillsDir, err)
	}
	tmp, err := os.MkdirTemp(skillsDir, ".install-"+b.Name+"-*")
	if err != nil {
		return nil, fmt.Errorf("install: mktmp: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	if err := extractSkb(skb, tmp); err != nil {
		cleanup()
		return nil, fmt.Errorf("install: extract: %w", err)
	}

	// Write the sidecar inside the unpacked dir.
	side := ProvenanceSidecar{
		SchemaVersion:         ProvenanceSchemaVersion,
		Skill:                 b.Name,
		Version:               b.Version,
		BundleDigest:          b.Digest,
		Registry:              "self",
		SourceER1ItemID:       b.SourceDocID,
		SourceER1Context:      opts.ContextID,
		PulledAt:              time.Now().UTC().Format(time.RFC3339),
		PulledOnHost:          hostnameShort(),
		TrustRootsFingerprint: opts.TrustRootsFingerprint,
		// For the `self` tenant the author and registry roles share the
		// single K-self key, so both pubkey_fingerprints equal the
		// trust-roots fingerprint that just verified the bundle. (A
		// future multi-key registry will record per-signature
		// fingerprints from the bundle event's signatures[] array.)
		Signatures: []SignatureSidecar{
			{Role: "author", IdentityID: b.AuthorIdentity, PubKeyFingerprint: opts.TrustRootsFingerprint},
			{Role: "registry", IdentityID: b.AuthorIdentity, PubKeyFingerprint: opts.TrustRootsFingerprint},
		},
		GovernanceLevel: b.Governance,
	}
	if err := writeProvenance(filepath.Join(tmp, ProvenanceSidecarName), side); err != nil {
		cleanup()
		return nil, fmt.Errorf("install: write provenance: %w", err)
	}

	// Stash the verified .skb alongside the extracted content so the SPEC-0247
	// gate recognises this pull-installed skill as managed and can byte-bind the
	// on-disk body to the signed bundle (catches post-install tampering). The
	// gate finds any top-level *.skb; the name is cosmetic.
	skbName := strings.ReplaceAll(b.Name, string(filepath.Separator), "_") + ".skb"
	if err := os.WriteFile(filepath.Join(tmp, skbName), skb, 0o644); err != nil {
		cleanup()
		return nil, fmt.Errorf("install: stash .skb: %w", err)
	}

	// SPEC-0266 F2/F19: stash the SIGNED attestation context so the runtime gate
	// can re-verify the bundle against the PINNED key (envelope + bundle sigs +
	// digest) and read governance from the SIGNED attestation — not the
	// attacker-writable sidecar. Best-effort: a legacy/dry-run path with no
	// attestation still installs; the gate then WARNs + content-binds.
	if b.Attestation != nil && b.Attestation.AdmitEvent != nil {
		if err := WriteAttestationStash(tmp, b.Attestation); err != nil {
			cleanup()
			return nil, fmt.Errorf("install: stash attestation: %w", err)
		}
	}

	res := &InstallResult{
		SkillPath:      target,
		ProvenancePath: filepath.Join(target, ProvenanceSidecarName),
	}
	// Atomic swap: if target exists, move it aside; rename tmp → target.
	var oldDigest string
	if old, err := os.Stat(target); err == nil && old.IsDir() {
		if pre, err := loadProvenance(filepath.Join(target, ProvenanceSidecarName)); err == nil {
			oldDigest = pre.BundleDigest
		}
		backup := target + ".old-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
		if err := os.Rename(target, backup); err != nil {
			cleanup()
			return nil, fmt.Errorf("install: rename old → backup: %w", err)
		}
		res.OverwroteOld = true
		res.OldDigest = oldDigest
		defer os.RemoveAll(backup) // cleanup the backup once the new install is in place
	} else {
		res.CreatedFresh = true
	}
	if err := os.Rename(tmp, target); err != nil {
		cleanup()
		return nil, fmt.Errorf("install: rename tmp → target: %w", err)
	}
	return res, nil
}

// extractSkb extracts a SPEC-0188 §3.1-shaped bundle (gzip + tar) into `target`.
// Per pkg/skillbundle/pack.go the archive is FLAT — SKILL.md, bundle.json,
// CHECKSUMS, scripts/…, references/… live at the archive root — but some
// producers wrap everything in one top-level dir; StripWrapper collapses that.
// CanonicalizeMD normalizes a stored "skill.md" to the canonical "SKILL.md" so
// Claude Code and the scanner (exact-match, case-sensitive on Linux) load the
// skill; normalizing only the written filename leaves the verified bundle
// bytes/digest untouched.
//
// SPEC-0252 C2: the gzip/tar walk, the bomb caps (one decompression pass,
// running byte ceiling + file-count cap, per-entry io.LimitReader), the
// symlink/hardlink/device refusal, the path-containment proof, and the O_EXCL
// fail-closed write all live in the ONE hardened core now — this is a thin
// adapter over skillbundle.Unpack + ExtractTo. (Convergence note: scripts/* are
// now written 0755 to match the producer's canonical mode and the HTTP install
// path, where the old self/ER1 walk dropped them to 0644 — a fix, not a
// weakening; content-binding compares bytes, not mode.)
func extractSkb(skb []byte, target string) error {
	entries, err := skillbundle.Unpack(skb, skillbundle.UnpackOptions{
		StripWrapper:   true,
		CanonicalizeMD: true,
	})
	if err != nil {
		return err
	}
	return skillbundle.ExtractTo(entries, target)
}

func defaultSkillsDir() string {
	return filepath.Join(userHome(), ".claude", "skills")
}

func hostnameShort() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

func loadProvenance(path string) (*ProvenanceSidecar, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s ProvenanceSidecar
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeProvenance(path string, side ProvenanceSidecar) error {
	out, err := json.MarshalIndent(side, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// compareSemver does a small loose-semver comparison: split on '.', compare
// each numeric part; non-numeric or short forms fall back to lexicographic.
// Returns -1 (a < b), 0 (a == b), +1 (a > b).
func compareSemver(a, b string) int {
	if a == b {
		return 0
	}
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	for i := 0; i < len(ap) || i < len(bp); i++ {
		var ai, bi int
		if i < len(ap) {
			ai, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			bi, _ = strconv.Atoi(bp[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// AuditProvenance re-computes the skill-directory digest and compares it to
// the sidecar's bundle_digest. Returns nil if they match, an error if drifted.
// Skill dirs without a sidecar return ErrNoSidecar (caller decides whether
// that's an error in their context).
func AuditProvenance(skillDir string) error {
	sidePath := filepath.Join(skillDir, ProvenanceSidecarName)
	side, err := loadProvenance(sidePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNoSidecar
		}
		return fmt.Errorf("audit: read sidecar: %w", err)
	}
	got, err := skillDirDigest(skillDir)
	if err != nil {
		return fmt.Errorf("audit: digest %s: %w", skillDir, err)
	}
	if got != side.BundleDigest {
		return fmt.Errorf("audit: digest drift in %s (recorded %s, on-disk %s)", skillDir, side.BundleDigest, got)
	}
	return nil
}

// ErrNoSidecar is returned by AuditProvenance for skill dirs that aren't
// trust-mode-installed. The caller surfaces this as ℹ️ "untracked provenance"
// in `skillctl audit` (it's not an error condition — locally-authored skills
// are fine).
var ErrNoSidecar = errors.New("audit: no .m3c-provenance.json sidecar (not trust-mode-installed)")

// skillDirDigest computes the canonical SHA-256 of the skill directory's
// content, mirroring the digest the original `.skb` would have produced. The
// canonicalisation: sort files by path; for each, hash <path>\n<bytes>\n; hash
// the concatenation. (Matches the spirit of pkg/skillbundle.buildChecksums;
// not byte-identical, but stable per-version under unchanged content. A
// follow-up can swap in the exact pkg/skillbundle scheme if needed.)
func skillDirDigest(dir string) (string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if name == ProvenanceSidecarName {
			return nil // exclude the sidecar from its own digest
		}
		rel, _ := filepath.Rel(dir, path)
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, rel := range files {
		fmt.Fprintf(h, "%s\n", rel)
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return "", err
		}
		h.Write(b)
		h.Write([]byte("\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
