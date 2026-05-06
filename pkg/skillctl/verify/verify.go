package verify

// SPEC-0188 §7 verifier algorithm.
//
// Each step is a small, independently-testable function. The top-level
// `Verify` orchestrates them in fixed order and short-circuits on the first
// failure so the highest-priority sentinel surfaces (digest mismatch beats
// signature failure beats trust-roots beats governance, etc.).
//
// Why each step is wrapped:
//
//   - The CLI translates `error` → numeric exit code via ExitCode (errors.go).
//     `errors.Is(err, ErrDigestMismatch)` only works if every wrap path
//     preserves that sentinel. We `fmt.Errorf("…: %w", ErrXxx)` everywhere
//     so context survives without breaking the type chain.
//
//   - Tests assert on the sentinel, not on the message. Step boundaries map
//     1:1 to test cases.
//
// Why we re-fetch identities here even when BundleMeta carries pubkey hints:
// SPEC §4.4 says "trust the registry's identity table" (identity_keys_authorized:
// from-registry). The signature-row-embedded fingerprint is a UX hint only —
// we re-resolve via GetIdentity so a key rotation that touches the identity
// table (but hasn't yet propagated into older signature rows) still verifies.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// Identity-fetcher injection point — lets tests hand a deterministic
// fixture without spinning an httptest.Server. Prod callers pass a
// *registry.Client; the type matches because Client has a method with
// this exact signature.
type identityFetcher interface {
	GetIdentity(ctx context.Context, id string) (*registry.Identity, error)
}

// VerifyOpts is the input bag for the §7 algorithm. All fields are owned
// by the caller; Verify does not mutate any of them.
type VerifyOpts struct {
	// BundlePath is the on-disk location of the staged blob whose digest
	// is being verified. The verifier reads this file ONCE — see
	// step 1 (digest recomputation).
	BundlePath string

	// BundleMeta is the registry's metadata envelope: the bundle's
	// advertised digest + signatures + attestations + the binding
	// CurrentGovernance verdict. Required.
	BundleMeta *registry.BundleMeta

	// TrustRoot is the matched trust-root entry (registry URL +
	// pinned RegistryKeys + GovernanceMinimum override). Required.
	TrustRoot *TrustRoot

	// IdentityFetcher resolves an identity_id to its current
	// {pubkey, revoked_at} document. Production wires this to
	// *registry.Client; tests substitute a fixture.
	IdentityFetcher identityFetcher

	// Ctx scopes registry calls (currently only GetIdentity). Falls
	// back to context.Background() if zero.
	Ctx context.Context

	// GovernanceMin overrides TrustRoot.GovernanceMinimum when non-empty.
	// "" means "use trust-root default". The CLI surfaces this via
	// `--governance-min`.
	GovernanceMin string

	// AllowYellow lets the operator override a green-required trust root
	// to admit a yellow bundle (still must be at least yellow). Audited
	// at the install layer BEFORE Verify runs (SPEC-0188 §11). Verify
	// itself just respects the flag.
	AllowYellow bool

	// IgnoreDeps skips the depends_on resolution step. Audited at the
	// install layer. v1 of Verify treats step 6 as a no-op regardless,
	// but the flag is preserved on the API for forward-compat with
	// future Python-wheel resolution.
	IgnoreDeps bool

	// Tenant is the resolved tenant scope for this verification (SPEC-0188
	// §7 step 5.5, G-18 closure 2026-05-06). Empty means "untenanted /
	// global" and step 5.5 is a no-op. The CLI resolves this from the
	// `--tenant <id>` flag with fallback to TrustRoots.TenantScope from
	// `~/.claude/skill-trust-roots.yaml`.
	//
	// When non-empty, the verifier scans BundleMeta.Attestations for any
	// row with TenantScope == Tenant and Level == "red" and fails closed
	// with ErrTenantBlocked.
	Tenant string

	// Logger receives one structured-log line per step when non-nil.
	// `--verbose` in the CLI wires this to stderr; tests capture into a
	// strings.Builder. Failure messages are returned as errors regardless.
	Logger io.Writer
}

// VerifyResult is what a successful verification returns. It's the
// material the install layer prints back to the user as the "chain
// summary" one-liner (SPEC §11 success path) and folds into the local
// install record.
type VerifyResult struct {
	// Digest is the canonical "sha256:<hex>" of the recomputed blob
	// (NOT the value advertised by the registry — see step 1).
	Digest string

	// AuthorIdentity is the verified author's identity_id.
	AuthorIdentity string

	// RegistryKeyID is the trust-root key ID that admitted the bundle.
	// Useful for forensic reasoning about which rotation key signed.
	RegistryKeyID string

	// GovernanceLevel is the binding verdict: "green" | "yellow" | "red".
	// Always at or above the effective minimum (the verifier short-circuits
	// otherwise).
	GovernanceLevel string

	// ChainSummary is a human-readable one-liner suitable for stdout.
	ChainSummary string
}

// Verify runs the SPEC-0188 §7 client-side algorithm end-to-end.
//
// Returns nil on success; on failure returns a sentinel-wrapped error that
// the CLI maps to a numeric exit code via ExitCode (errors.go).
//
// The function is read-only with respect to the filesystem (it reads
// opts.BundlePath but never writes anywhere). The install layer is
// responsible for staging/atomic-rename/cleanup. Separating verify from
// install is what lets `skillctl verify <name>` re-run the chain check
// against an already-installed skill without disturbing it.
func Verify(opts VerifyOpts) (*VerifyResult, error) {
	if err := validateOpts(opts); err != nil {
		return nil, err
	}
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Step 1 — recompute digest from the staged blob.
	digestRaw, digestStr, err := stepRecomputeDigest(opts.BundlePath)
	if err != nil {
		return nil, err
	}
	logStep(opts.Logger, "digest_ok", "digest=%s", digestStr)

	// Step 1b — compare to advertised digest (constant-time slice cmp).
	if err := stepCompareDigest(digestRaw, opts.BundleMeta); err != nil {
		return nil, err
	}
	logStep(opts.Logger, "digest_match_ok", "digest=%s", digestStr)

	// Step 7 — bundle status must be "admitted". (SPEC §7 step 7 is a
	// late check, but `status: revoked` is cheap to short-circuit before
	// we reach for crypto. Wrap as ErrBlobMissing since "this bundle is
	// not currently admissible" is the spirit of the existing sentinel.)
	if err := stepCheckBundleStatus(opts.BundleMeta); err != nil {
		return nil, err
	}
	logStep(opts.Logger, "bundle_admitted_ok", "")

	// Step 2/3 — verify author signature against identity pubkey.
	authorID, err := stepVerifyAuthor(ctx, digestRaw, opts.BundleMeta, opts.IdentityFetcher, opts.Logger)
	if err != nil {
		return nil, err
	}
	logStep(opts.Logger, "author_sig_ok", "author=%s", authorID)

	// Step 4 — verify registry signature against any non-retired trust-root key.
	regKeyID, err := stepVerifyRegistry(digestRaw, opts.BundleMeta, opts.TrustRoot)
	if err != nil {
		return nil, err
	}
	logStep(opts.Logger, "registry_sig_ok", "key=%s", regKeyID)

	// Step 5.5 — tenant-block check (SPEC-0188 §7 step 5.5, G-18 closure
	// 2026-05-06). When a tenant scope is in effect, look for any tenant-
	// scoped attestation with governance_level=red for this bundle. If
	// present, fail closed with ErrTenantBlocked (exit 16). This is how
	// SPEC-0192 CISO-console block verdicts propagate to the client
	// verifier; the global chain may validate but the tenant CISO has
	// withdrawn admission for THIS tenant.
	//
	// Order: AFTER registry signature verification (we don't want to
	// surface tenant-block errors to a chain that didn't even pass the
	// registry signature gate) and BEFORE the governance-minimum check
	// (so a global yellow + tenant red still surfaces as tenant_blocked,
	// which is the more actionable diagnostic for an operator).
	if err := stepTenantBlockCheck(opts.BundleMeta, opts.Tenant); err != nil {
		return nil, err
	}
	if opts.Tenant != "" {
		logStep(opts.Logger, "tenant_block_ok", "tenant=%s", opts.Tenant)
	}

	// Step 5 — governance gate.
	govLevel, err := stepCheckGovernance(opts.BundleMeta, opts.TrustRoot, opts.GovernanceMin, opts.AllowYellow)
	if err != nil {
		return nil, err
	}
	logStep(opts.Logger, "governance_ok", "level=%s", govLevel)

	// Step 6 — depends_on resolution. v1 is a no-op (bundles in tree
	// shape rather than DAG; Python-wheel resolution lives behind a
	// future feature flag). The flag is honored either way for
	// forward-compat with the CLI surface.
	if !opts.IgnoreDeps {
		if err := stepResolveDeps(opts.BundleMeta); err != nil {
			return nil, err
		}
	}
	logStep(opts.Logger, "deps_ok", "ignore_deps=%v", opts.IgnoreDeps)

	res := &VerifyResult{
		Digest:          digestStr,
		AuthorIdentity:  authorID,
		RegistryKeyID:   regKeyID,
		GovernanceLevel: govLevel,
		ChainSummary: fmt.Sprintf(
			"%s: signed by %s, admitted by %s, attested %s",
			digestStr, authorID, regKeyID, govLevel,
		),
	}
	return res, nil
}

// validateOpts catches misuse early so each step doesn't have to
// re-check pointer hygiene.
func validateOpts(opts VerifyOpts) error {
	if opts.BundlePath == "" {
		return errors.New("verify: BundlePath is required")
	}
	if opts.BundleMeta == nil {
		return errors.New("verify: BundleMeta is required")
	}
	if opts.TrustRoot == nil {
		return errors.New("verify: TrustRoot is required")
	}
	if opts.IdentityFetcher == nil {
		return errors.New("verify: IdentityFetcher is required")
	}
	return nil
}

// stepRecomputeDigest streams the staged blob through SHA-256 and returns
// both the raw 32-byte digest and the canonical "sha256:<hex>" form.
//
// We DELIBERATELY ignore any digest field embedded in the registry
// metadata or the bundle's manifest. The value the registry advertises
// (`bundle.bundle_digest`) is checked in stepCompareDigest against this
// recomputation; trusting the advertised value would defeat the whole
// chain.
func stepRecomputeDigest(path string) ([sha256.Size]byte, string, error) {
	raw, err := signing.ComputeBundleDigest(path)
	if err != nil {
		// Treat any digest computation failure as a digest-mismatch
		// equivalent: we can't know the digest, so we can't trust it.
		// Wrap with ErrDigestMismatch so ExitCode maps to 10.
		return raw, "", fmt.Errorf("verify: recompute digest %s: %w", path, errors.Join(ErrDigestMismatch, err))
	}
	str := "sha256:" + hexLower(raw[:])
	return raw, str, nil
}

// stepCompareDigest constant-time-compares the recomputed digest against
// the digest the registry advertises in `bundle.bundle_digest`.
//
// Constant-time matters less here than for HMACs (digests aren't secret),
// but using subtle.ConstantTimeCompare is free and removes a class of
// timing-side-channel reasoning we don't want to redo every time someone
// reads this file.
func stepCompareDigest(recomputed [sha256.Size]byte, meta *registry.BundleMeta) error {
	advertised, ok := stringField(meta.Bundle, "bundle_digest")
	if !ok || advertised == "" {
		return fmt.Errorf("verify: registry response missing bundle.bundle_digest: %w", ErrDigestMismatch)
	}
	rawAdv, err := decodeShaHexDigest(advertised)
	if err != nil {
		return fmt.Errorf("verify: advertised digest %q: %w", advertised, errors.Join(ErrDigestMismatch, err))
	}
	if subtle.ConstantTimeCompare(recomputed[:], rawAdv) != 1 {
		return fmt.Errorf("verify: digest mismatch (recomputed=sha256:%s, advertised=%s): %w",
			hexLower(recomputed[:]), advertised, ErrDigestMismatch)
	}
	return nil
}

// stepCheckBundleStatus rejects bundles whose registry status is anything
// other than "admitted". Maps to ErrBlobMissing per SPEC §7 step 7.
func stepCheckBundleStatus(meta *registry.BundleMeta) error {
	status, _ := stringField(meta.Bundle, "status")
	// Treat empty status as admitted for forward-compat: the S5 contract
	// makes status optional and a registry that omits it is implicitly
	// serving an admitted bundle (revoked bundles must be tagged so
	// explicitly per §11).
	if status == "" || status == "admitted" {
		return nil
	}
	return fmt.Errorf("verify: bundle status %q (not admitted): %w", status, ErrBlobMissing)
}

// stepVerifyAuthor extracts the author signature from BundleMeta, fetches
// the author identity, decodes the pubkey, and runs ed25519.Verify against
// the recomputed digest.
//
// Returns the verified author identity_id on success.
//
// Failures map to ErrAuthorSigInvalid:
//   - missing/multiple author rows
//   - identity not found / revoked
//   - pubkey malformed (length, base64)
//   - ed25519.Verify says no
func stepVerifyAuthor(ctx context.Context, digest [sha256.Size]byte, meta *registry.BundleMeta, fetcher identityFetcher, logger io.Writer) (string, error) {
	row, err := pickSingleSignature(meta.Signatures, "author")
	if err != nil {
		return "", fmt.Errorf("verify: %w: %w", ErrAuthorSigInvalid, err)
	}

	if row.IdentityID == "" {
		return "", fmt.Errorf("verify: author signature has empty identity_id: %w", ErrAuthorSigInvalid)
	}

	ident, err := fetcher.GetIdentity(ctx, row.IdentityID)
	if err != nil {
		return "", fmt.Errorf("verify: fetch identity %s: %w", row.IdentityID, errors.Join(ErrAuthorSigInvalid, err))
	}
	if ident == nil {
		return "", fmt.Errorf("verify: identity %s: nil response: %w", row.IdentityID, ErrAuthorSigInvalid)
	}
	if ident.IsRevoked() {
		return "", fmt.Errorf("verify: author identity %s revoked at %s: %w", ident.ID, ident.RevokedAt, ErrAuthorSigInvalid)
	}
	if ident.AuthSource == "" {
		// auth_source is a binding contract once OIDC ships (SPEC §D4).
		// In Phase 1 it's set to "manual"; an empty value is suspicious
		// enough to refuse.
		return "", fmt.Errorf("verify: identity %s has empty auth_source: %w", ident.ID, ErrAuthorSigInvalid)
	}

	pub, err := decodePubkeyB64(ident.PubkeyB64)
	if err != nil {
		return "", fmt.Errorf("verify: decode pubkey for %s: %w", ident.ID, errors.Join(ErrAuthorSigInvalid, err))
	}

	sig, err := decodeSignatureB64(row.SignatureB64)
	if err != nil {
		return "", fmt.Errorf("verify: decode author signature: %w", errors.Join(ErrAuthorSigInvalid, err))
	}

	// ed25519.Verify is constant-time on the signature comparison per
	// stdlib docs. Don't roll our own.
	if !ed25519.Verify(pub, digest[:], sig) {
		return "", fmt.Errorf("verify: ed25519 author signature failed for identity %s: %w", ident.ID, ErrAuthorSigInvalid)
	}

	logStep(logger, "author_identity", "id=%s auth_source=%s", ident.ID, ident.AuthSource)
	return ident.ID, nil
}

// stepVerifyRegistry locates the registry signature in BundleMeta and
// verifies it against any non-retired key in the matched TrustRoot.
//
// Returns the matched RegistryKey.ID on success. Failures map to
// ErrRegistryNotTrusted.
func stepVerifyRegistry(digest [sha256.Size]byte, meta *registry.BundleMeta, root *TrustRoot) (string, error) {
	row, err := pickSingleSignature(meta.Signatures, "registry")
	if err != nil {
		return "", fmt.Errorf("verify: %w: %w", ErrRegistryNotTrusted, err)
	}

	sig, err := decodeSignatureB64(row.SignatureB64)
	if err != nil {
		return "", fmt.Errorf("verify: decode registry signature: %w", errors.Join(ErrRegistryNotTrusted, err))
	}

	active := root.ActiveKeys()
	if len(active) == 0 {
		return "", fmt.Errorf("verify: trust root %s has no active registry keys: %w", root.RegistryURL, ErrRegistryNotTrusted)
	}

	// Try each active key. ed25519.Verify is constant-time per attempt;
	// the loop is short (rotation-overlap windows pin 1-2 keys typically).
	for _, k := range active {
		if len(k.Pubkey) != ed25519.PublicKeySize {
			// Defensive — Load already validates this. Skip rather
			// than abort so a single corrupt key can't break a
			// healthy second key during rotation.
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(k.Pubkey), digest[:], sig) {
			return k.ID, nil
		}
	}
	return "", fmt.Errorf("verify: registry signature did not match any active key in %s: %w", root.RegistryURL, ErrRegistryNotTrusted)
}

// stepCheckGovernance enforces the trust-root's governance_minimum (or
// the per-invocation override) against BundleMeta.CurrentGovernance.
//
// Mapping:
//
//	level rank: green=2, yellow=1, red=0, "" (missing)=0 (= red, fail-closed)
//	min rank:   green=2, yellow=1
//	bundle level >= effective min → ok
//
// `--allow-yellow` lowers the effective minimum from green to yellow when
// the trust-root says green. Red bundles are NEVER admitted, regardless
// of override.
func stepCheckGovernance(meta *registry.BundleMeta, root *TrustRoot, override string, allowYellow bool) (string, error) {
	level := strings.ToLower(strings.TrimSpace(meta.CurrentGovernance))
	if level == "" {
		// Fail-closed: a registry that didn't compute a verdict is
		// treated as red.
		return "", fmt.Errorf("verify: bundle has no current_governance (treated as red): %w", ErrGovernanceBelowMin)
	}

	min := override
	if min == "" {
		min = root.GovernanceMinimum
	}
	min = strings.ToLower(strings.TrimSpace(min))
	if min == "" {
		// Defensive — Load already enforces this; surface clearly
		// rather than panic.
		return "", fmt.Errorf("verify: trust root %s has no governance_minimum: %w", root.RegistryURL, ErrGovernanceBelowMin)
	}

	if allowYellow && min == "green" {
		min = "yellow"
	}

	bundleRank := governanceRank(level)
	if bundleRank < 0 {
		return "", fmt.Errorf("verify: unknown governance level %q: %w", level, ErrGovernanceBelowMin)
	}
	minRank := governanceRank(min)
	if minRank < 0 {
		return "", fmt.Errorf("verify: invalid governance_minimum %q: %w", min, ErrGovernanceBelowMin)
	}

	if bundleRank < minRank {
		return "", fmt.Errorf("verify: bundle governance %q below minimum %q: %w", level, min, ErrGovernanceBelowMin)
	}
	return level, nil
}

// stepTenantBlockCheck implements SPEC-0188 §7 step 5.5: when the consumer
// is pinned to a tenant (via --tenant <id> or TrustRoots.TenantScope), scan
// BundleMeta.Attestations for any active row whose tenant_scope matches the
// consumer's tenant AND whose governance_level is "red". If found, fail
// closed with ErrTenantBlocked (exit code 16).
//
// Behavior contract:
//   - tenant == "" → no-op, returns nil. Untenanted installs never see this
//     gate.
//   - rows with empty tenant_scope are GLOBAL and ignored here; the global
//     gate is stepCheckGovernance via CurrentGovernance.
//   - rows with status=="revoked" are skipped (revocation supersedes the
//     verdict).
//   - rows with tenant_scope != tenant are ignored (that's another tenant's
//     CISO's decision).
//   - any matching row with level=="red" fails closed; the error message
//     cites attestation_id, reviewer_id, attested_at so an operator can
//     trace the block back to a specific verdict in the SPEC-0192 console.
//
// We surface the FIRST matching red row in the error message; if a tenant
// has multiple red verdicts on the same bundle the first one is enough to
// identify the policy lineage. The verifier short-circuits on the first
// failure either way.
func stepTenantBlockCheck(meta *registry.BundleMeta, tenant string) error {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		// No tenant pinned — step 5.5 is a no-op per SPEC §7.
		return nil
	}
	for _, att := range meta.Attestations {
		if att.Status == "revoked" {
			continue
		}
		// Trim both sides: registry-supplied JSON might include surrounding
		// whitespace from a hand-edited document. The CLI flag is trimmed
		// in install_cmds.go's resolution helper.
		if strings.TrimSpace(att.TenantScope) != tenant {
			continue
		}
		if strings.ToLower(strings.TrimSpace(att.Level)) != "red" {
			// Tenant-scoped green / yellow attestations are advisory at
			// this gate — they document approval, they don't block.
			continue
		}
		return fmt.Errorf(
			"verify: tenant %q is blocked by attestation %s (signed_by=%s, signed_at=%s): %w",
			tenant,
			nonEmpty(att.AttestationID, "<unknown>"),
			nonEmpty(att.ReviewerID, "<unknown>"),
			nonEmpty(att.AttestedAt, "<unknown>"),
			ErrTenantBlocked,
		)
	}
	return nil
}

// nonEmpty returns s when s != "", else fallback. Used to keep error
// messages readable when a registry omits an optional attestation field.
func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// stepResolveDeps checks the manifest's `depends_on` field for obvious
// problems. v1 is conservative — we don't actually run pip install — but
// we DO refuse a bundle whose depends_on is structurally malformed so
// downstream tooling has something to react to.
//
// IgnoreDeps short-circuits this entirely (the audit row is written by
// the install layer before Verify runs).
func stepResolveDeps(meta *registry.BundleMeta) error {
	deps, ok := meta.Manifest["depends_on"]
	if !ok || deps == nil {
		// No deps or manifest omitted → nothing to resolve.
		return nil
	}
	list, ok := deps.([]any)
	if !ok {
		return fmt.Errorf("verify: manifest depends_on is not a list: %w", ErrDepsUnsatisfied)
	}
	// v1 contract: each entry is a {kind, name, constraint} object. We
	// validate the shape but don't yet resolve. A future implementation
	// will plug pip / system-tool resolution here.
	for i, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("verify: depends_on[%d] is not an object: %w", i, ErrDepsUnsatisfied)
		}
		if name, _ := obj["name"].(string); name == "" {
			return fmt.Errorf("verify: depends_on[%d] missing name: %w", i, ErrDepsUnsatisfied)
		}
		if kind, _ := obj["kind"].(string); kind == "" {
			return fmt.Errorf("verify: depends_on[%d] missing kind: %w", i, ErrDepsUnsatisfied)
		}
	}
	return nil
}

// ----- helpers -----

// pickSingleSignature returns the unique signature row of the given role.
// Refuses if zero or >1 rows match — a bundle with two author signatures
// is not a configuration we want to silently pick from.
//
// Status-filter: rows with `status: "revoked"` are skipped.
func pickSingleSignature(rows []registry.SignatureRow, role string) (*registry.SignatureRow, error) {
	var hit *registry.SignatureRow
	count := 0
	for i := range rows {
		if rows[i].Role != role {
			continue
		}
		if rows[i].Status == "revoked" {
			continue
		}
		hit = &rows[i]
		count++
	}
	switch count {
	case 0:
		return nil, fmt.Errorf("no %s signature in registry response", role)
	case 1:
		return hit, nil
	default:
		return nil, fmt.Errorf("found %d active %s signatures (want exactly 1)", count, role)
	}
}

// stringField reads a string from a map[string]any, returning ("", false)
// if absent or non-string. Used to dig into BundleMeta.Bundle without
// committing to a typed model on the wire.
func stringField(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// decodeShaHexDigest parses "sha256:<hex>" → 32 raw bytes. Refuses any
// other algorithm prefix or wrong length.
func decodeShaHexDigest(s string) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("digest %q missing %q prefix", s, prefix)
	}
	hex := s[len(prefix):]
	if len(hex) != 2*sha256.Size {
		return nil, fmt.Errorf("digest hex length %d (want %d)", len(hex), 2*sha256.Size)
	}
	out := make([]byte, sha256.Size)
	for i := 0; i < sha256.Size; i++ {
		hi, err := hexNibble(hex[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(hex[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return 10 + c - 'a', nil
	case c >= 'A' && c <= 'F':
		return 10 + c - 'A', nil
	default:
		return 0, fmt.Errorf("non-hex digit %q in digest", string(c))
	}
}

// hexLower formats a byte slice as lowercase hex without depending on
// encoding/hex (avoids the import in this file's hot path).
func hexLower(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hex[v>>4]
		out[2*i+1] = hex[v&0x0f]
	}
	return string(out)
}

// decodePubkeyB64 decodes a base64 pubkey string into a 32-byte ed25519.PublicKey.
func decodePubkeyB64(s string) (ed25519.PublicKey, error) {
	if s == "" {
		return nil, errors.New("pubkey_b64 is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// decodeSignatureB64 decodes a base64 signature string into 64 raw bytes.
func decodeSignatureB64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("signature_b64 is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, want %d", len(raw), ed25519.SignatureSize)
	}
	return raw, nil
}

// governanceRank maps "green"|"yellow"|"red" to a numeric level. -1 means
// "unknown" so callers can refuse without ambiguity. The rank scheme is
// intentionally tiny: red < yellow < green.
func governanceRank(level string) int {
	switch level {
	case "red":
		return 0
	case "yellow":
		return 1
	case "green":
		return 2
	default:
		return -1
	}
}

// logStep writes one structured-log line to logger if non-nil. Format is
// "verify step=<event> <kv-pairs>" so a grep-friendly forensic trail is
// always available behind --verbose.
//
// We compose the prefix and the kv-pairs separately so the variadic args
// only feed the kv-pairs format. Mixing the event into a single format
// string would require prepending it to args, which is fiddle-prone.
func logStep(w io.Writer, event, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "verify step=%s", event)
	if format != "" {
		fmt.Fprint(w, " ")
		fmt.Fprintf(w, format, args...)
	}
	fmt.Fprintln(w)
}
