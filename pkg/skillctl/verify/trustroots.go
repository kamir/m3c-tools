package verify

// Trust-roots loader for ~/.claude/skill-trust-roots.yaml.
//
// Schema (per SPEC-0188 §4.4 + the multi-entry overlap clarification):
//
//	trust_roots:
//	  - registry_url: https://aims.example.com/api/skills
//	    registry_keys:
//	      - id: aims-core-dev
//	        pubkey: <base64 of raw 32-byte ed25519 pubkey>
//	        issued: 2026-05-05
//	        # retired: 2026-12-31    # OPTIONAL — retired keys are inert
//	    identity_keys_authorized: from-registry
//	    governance_minimum: green   # green | yellow
//
// Multiple `registry_keys` per registry support overlap-window rotation:
// publish key N+1 alongside key N for some days, then mark key N retired.
// The verifier accepts ANY non-retired key during overlap.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"crypto/ed25519"
	"crypto/sha256"

	"github.com/kamir/m3c-tools/pkg/skillctl/govlevel"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/statemachine"
	"gopkg.in/yaml.v3"
)

// DefaultTrustRootsPath is the conventional location of the trust-roots
// file relative to the user's home dir. Resolve via DefaultPath() to get
// an absolute path with `~` expanded.
const DefaultTrustRootsPath = ".claude/skill-trust-roots.yaml"

// pubkeyRawSize is the ed25519 public key size in bytes. Anything that
// decodes to a different length is rejected — there is no useful "lenient
// mode" for a key length check.
const pubkeyRawSize = ed25519.PublicKeySize // 32

// validIdentityModes is the closed set of accepted values for
// `identity_keys_authorized`.
//
//   - "from-registry" — author pubkeys are resolved from the registry's
//     identity table at verify time (the v1 default; requires a network call
//     or a stashed identity).
//   - "pinned" — author pubkeys are pinned LOCALLY in this trust root's
//     `authors:` list, so the author signature is verified with NO registry
//     call. This is the primitive that makes third-party, offline, "no trust
//     in the registry" verification possible (SPEC-0276 R4.1).
var validIdentityModes = map[string]struct{}{
	"from-registry": {},
	"pinned":        {},
}

// RegistryKey is one pinned ed25519 public key for a registry. A registry
// may have multiple keys live at once (during a rotation overlap window);
// retired keys parse but IsActive returns false so the verifier rejects
// them.
type RegistryKey struct {
	// ID is a human-friendly label for the key. Used in error messages
	// only — never matched against signature material.
	ID string `yaml:"id"`

	// Pubkey is the raw 32-byte ed25519 public key. The on-disk
	// encoding is base64 of the raw bytes (NOT PEM, NOT DER); the
	// loader decodes once and stores raw bytes here so callers don't
	// re-decode per verification.
	Pubkey []byte `yaml:"-"`

	// PubkeyB64 is the base64 form preserved verbatim from the YAML so
	// Save() round-trips the file losslessly. The loader populates
	// both PubkeyB64 (string form) and Pubkey (raw bytes) for symmetry.
	PubkeyB64 string `yaml:"pubkey"`

	// Issued is the ISO-8601 date the key was first published. Stored
	// as a free-form string — verification doesn't currently use it
	// (rotation policy is encoded in `retired`, not in date math) but
	// admins reading the file want to see when each key entered service.
	Issued string `yaml:"issued"`

	// Retired, if non-empty, marks the key as retired as of that ISO
	// date. The verifier rejects retired keys regardless of date —
	// "retired" is a binary toggle in v1, the date is just metadata.
	Retired string `yaml:"retired,omitempty"`
}

// IsActive reports whether the key is eligible to verify a registry
// signature today. A key is active iff Retired is the empty string.
//
// We deliberately do NOT compare Retired against time.Now: in v1, marking
// a key retired in the YAML is a deliberate admin act and should take
// effect immediately on next verifier invocation, not at midnight UTC of
// some date.
func (rk RegistryKey) IsActive() bool {
	return rk.Retired == ""
}

// AuthorKey is one pinned ed25519 public key for a skill-author identity.
// Consulted ONLY when its TrustRoot sets identity_keys_authorized: pinned.
// Pinning the author key locally lets the verifier check the author signature
// without calling the registry's identity table — the property that makes
// fully offline, third-party verification possible (SPEC-0276 R4.1): a party
// who pins this key out-of-band can reproduce our verdict with no trust in,
// and no call to, our servers.
type AuthorKey struct {
	// ID is the author identity_id exactly as it appears in the bundle's
	// author signature row (e.g. "id:kamir@m3c"). Matched verbatim.
	ID string `yaml:"id"`

	// Pubkey is the raw 32-byte ed25519 public key. Hydrated once by Load
	// from PubkeyB64 so callers don't re-decode per verification.
	Pubkey []byte `yaml:"-"`

	// PubkeyB64 is the base64 form preserved verbatim for lossless round-trip.
	PubkeyB64 string `yaml:"pubkey"`

	// Fingerprint, if set, is the advisory "sha256:<hex>" over the raw pubkey
	// bytes. When present it MUST match the key (a typo'd fingerprint is
	// refused at Load) so a human who cross-checks the fingerprint out-of-band
	// can rely on it. Verification uses the key bytes, never this string.
	Fingerprint string `yaml:"fingerprint,omitempty"`

	// Retired, if non-empty, marks the pin inert — same binary-toggle
	// semantics as RegistryKey.Retired (the date is metadata, not a schedule).
	Retired string `yaml:"retired,omitempty"`
}

// IsActive reports whether the pinned author key is eligible today (not retired).
func (ak AuthorKey) IsActive() bool {
	return ak.Retired == ""
}

// TrustRoot is one pinned registry. It carries 1..N keys (overlap-window
// rotation) plus the policy knobs that bound what the verifier will admit
// from this registry.
type TrustRoot struct {
	// RegistryURL is the canonical aims-core skill-registry root, e.g.
	// https://aims.example.com/api/skills. The verifier matches a
	// bundle's source registry against this URL exactly (no normalization
	// beyond trimming trailing slash).
	RegistryURL string `yaml:"registry_url"`

	// RegistryKeys are the pinned ed25519 public keys that this
	// registry signs its attestations with. May contain retired keys —
	// the loader does NOT silently filter them; callers must check
	// IsActive(). This preserves the file's history when round-tripped.
	RegistryKeys []RegistryKey `yaml:"registry_keys"`

	// IdentityKeysAuthorized governs how the verifier looks up author
	// public keys. "from-registry" (default) trusts the registry's identity
	// table; "pinned" verifies the author signature against the local
	// Authors list below, with no registry call (SPEC-0276 R4.1).
	IdentityKeysAuthorized string `yaml:"identity_keys_authorized"`

	// Authors are pinned author identities, consulted ONLY when
	// IdentityKeysAuthorized == "pinned". Each entry binds one author
	// identity_id to its ed25519 pubkey so the author signature verifies
	// locally and offline. Ignored (and normally absent) in from-registry
	// mode. Additive: an empty list in from-registry mode is fine.
	Authors []AuthorKey `yaml:"authors,omitempty"`

	// GovernanceMinimum is one of "green" or "yellow". A bundle whose
	// current attestation is below this level is rejected with exit
	// code 13 (ErrGovernanceBelowMin).
	GovernanceMinimum string `yaml:"governance_minimum"`

	// Reviewers are pinned reviewer identities (SPEC-0281). When present, the
	// verifier re-verifies the SIGNED governance attestation against the
	// pinned reviewer key instead of trusting the registry's unsigned
	// CurrentGovernance string. Same shape/validation as Authors.
	Reviewers []AuthorKey `yaml:"reviewers,omitempty"`

	// RequireSignedGovernance (SPEC-0281): when true, the governance level
	// MUST be backed by a signed attestation that verifies against a pinned
	// reviewer key, or verification is refused (exit 13). When false (default)
	// governance is advisory in offline mode — the chain summary reports
	// "governance(advisory)" rather than "attested".
	RequireSignedGovernance bool `yaml:"require_signed_governance,omitempty"`

	// MinRevocationEpoch (SPEC-0279 R1): the verifier refuses a signed
	// revocation list whose epoch is below this floor — rollback protection
	// against substituting an older signed list. 0 = no floor.
	MinRevocationEpoch int `yaml:"min_revocation_epoch,omitempty"`

	// RequireIndependentReview (SPEC-0246 §5.2): when true, the binding
	// governance attestation must NOT be self_attested — i.e. the reviewer
	// identity must differ from the author identity. A self-attested bundle is
	// refused with ErrSelfAttested (exit 20). When false (the default and the
	// `self` single-principal tenant per §5.2) self-attestation is allowed —
	// the floor defaults OFF so the personal tenant keeps working.
	//
	// The loader is STRICT (KnownFields(true)) so this MUST be a declared field
	// or a trust-roots file carrying `require_independent_review:` would be
	// rejected as an unknown key.
	RequireIndependentReview bool `yaml:"require_independent_review,omitempty"`

	// RequireAgentApprover (SPEC-0277 §11.5): the agent-instance analogue of
	// RequireIndependentReview. When true, an AgentID (the SPEC-0277 mandate, not
	// a skill bundle) must carry BOTH an owner signature AND an independent
	// approver (sign-off human) signature with approver != owner — the
	// "two-person admit for agents". Both must be PINNED and cryptographically
	// verified; the unsigned claim is never trusted. Enforced by the `agentid`
	// verifier (owners pinned in `authors:`, approvers pinned in `reviewers:`),
	// not by the bundle §7 chain. Default OFF so single-delegation (owner-only)
	// AgentIDs keep working. Declared here so the strict loader accepts the key;
	// validate() requires a non-empty reviewers list when it is set, mirroring
	// require_independent_review (the floor cannot be set fail-OPEN).
	RequireAgentApprover bool `yaml:"require_agent_approver,omitempty"`

	// --- SPEC-0279 R2 — revocation freshness policy ---
	//
	// These four DECLARED fields configure the offline-revocation freshness
	// contract (SPEC-0279 §3). The loader is STRICT (KnownFields(true)) so they
	// MUST be typed fields or a trust-roots file carrying them would be rejected
	// as unknown keys. Durations are Go time.ParseDuration strings ("24h",
	// "12h"); validate() parses them into the resolved Freshness() policy.

	// MaxStaleness is the maximum age of a synced revocation snapshot (now -
	// RevocationList.issued_at) before the fail-policy acts. A Go duration string
	// (e.g. "24h"). Empty = no staleness ceiling (the snapshot is trusted at any
	// age — the pre-SPEC-0279 behaviour, kept so existing files don't change
	// meaning). When set, validate() rejects a non-parseable or negative value.
	MaxStaleness string `yaml:"max_staleness,omitempty"`

	// CacheTTL is the local revocation-cache lifetime (SPEC-0279 §3). A Go
	// duration string; default 12h (the shipped sweep cadence) when empty.
	CacheTTL string `yaml:"cache_ttl,omitempty"`

	// FailPolicy is the disposition for a LOW-RISK / read-only action once a
	// snapshot is older than MaxStaleness: "closed" (deny, the default) or "open"
	// (allow with an audited record). A HIGH-RISK action ALWAYS fails closed past
	// MaxStaleness regardless of this knob (SPEC-0279 R3) — fail_policy only
	// governs the low-risk branch. Empty defaults to "closed"; validate() rejects
	// any value other than "closed"/"open".
	FailPolicy string `yaml:"fail_policy,omitempty"`

	// FailPolicyByRisk is an OPTIONAL per-action-risk override map (SPEC-0279 R2:
	// "an optional per-action-risk override"), e.g. {high: closed, low: open}.
	// Keys are risk classes ("high"/"low"); values are "closed"/"open". An entry
	// overrides FailPolicy for that risk class — but a HIGH-risk override can only
	// be "closed" (you cannot configure a high-risk action to fail OPEN past
	// max_staleness; that would defeat R3). validate() enforces both the closed
	// key/value vocabulary AND the high⇒closed floor.
	FailPolicyByRisk map[string]string `yaml:"fail_policy_by_risk,omitempty"`

	// OfflinePolicy is the SPEC-0317 R-7.3 offline-state-machine policy block.
	// It is the ONE surface (extends this TrustRoot, not a new file) that
	// configures the named online/degraded/offline/locked state machine
	// (pkg/skillctl/statemachine). Absent (nil) = the shipped default: not
	// enterprise, no cache ceilings, unmanaged=allow — a host with no block
	// NEVER enters `locked`. Validated at Load via ResolveOfflinePolicy so a bad
	// duration or an enterprise-only knob set without `enterprise` is refused
	// loudly (a typo cannot lie dormant). The strict loader (KnownFields(true))
	// requires this to be a declared field.
	OfflinePolicy *OfflinePolicyBlock `yaml:"offline_policy,omitempty"`
}

// OfflinePolicyBlock is the YAML surface of the SPEC-0317 R-7.3 `offline_policy`
// block. It carries Go-duration STRINGS (parsed once at Load, like the SPEC-0279
// freshness fields) and the enterprise gate. ResolveOfflinePolicy parses it into
// the stdlib-only statemachine.OfflinePolicy the pure Compute consumes.
//
// The strict loader means every field here must be declared; an unknown key
// under `offline_policy:` is rejected at Load.
type OfflinePolicyBlock struct {
	// AllowCachedTrustedSkills allows a cached, trust-verified skill to run while
	// disconnected (degraded/offline). Advisory to the decision ladder.
	AllowCachedTrustedSkills bool `yaml:"allow_cached_trusted_skills,omitempty"`

	// DenyUnknownSkills denies a skill with no cached trust basis while
	// disconnected. It flips unmanaged=allow for UNKNOWN skills only; it does NOT
	// by itself produce `locked` (that needs `enterprise` + no trust basis).
	DenyUnknownSkills bool `yaml:"deny_unknown_skills,omitempty"`

	// MaxPolicyCacheAge bounds policy- AND trust-cache freshness. Go duration
	// string ("24h"); empty = no ceiling. Rejected at Load if unparseable/negative.
	MaxPolicyCacheAge string `yaml:"max_policy_cache_age,omitempty"`

	// MaxRevocationCacheAge bounds the ORDINARY revocation cache. Go duration
	// string; empty = no ceiling. The emergency deny-list is EXEMPT from this.
	MaxRevocationCacheAge string `yaml:"max_revocation_cache_age,omitempty"`

	// RequireLocalAudit is the SPEC-0317 R-8 inversion of the SPEC-0255
	// decision-invariance contract. ENTERPRISE-ONLY: Load refuses it unless
	// Enterprise is also true (the floor cannot be set on a non-enterprise host).
	RequireLocalAudit bool `yaml:"require_local_audit,omitempty"`

	// Enterprise is the opt-in that enables the `locked` state and permits
	// RequireLocalAudit. Without it the host can NEVER lock (R-7.2 never-brick).
	Enterprise bool `yaml:"enterprise,omitempty"`
}

// ResolveOfflinePolicy parses this trust root's SPEC-0317 R-7.3 offline_policy
// block into the resolved, stdlib-only statemachine.OfflinePolicy the pure
// Compute consumes. A nil block resolves to the zero policy (the shipped default:
// not enterprise, no ceilings). Called by validate() (so a bad value is refused
// at Load) AND by the consumers (so they read the same resolved policy) — the
// same pattern as TrustRoot.Freshness().
//
// Validation (fail-safe, never fail-open):
//   - durations parse as Go durations and are non-negative (empty → 0 = no ceiling);
//   - require_local_audit is refused unless enterprise is set (R-7.3/R-8: the
//     decision-invariance carve-out is enterprise opt-in only).
//
// There is deliberately NO high-risk fail-open knob here: the SPEC-0279
// freshness.go R3 floor remains the authoritative high-risk fail-closed enforcer
// (R-7.4), so the offline policy cannot configure a high-risk action fail-open.
func (t *TrustRoot) ResolveOfflinePolicy() (statemachine.OfflinePolicy, error) {
	if t == nil || t.OfflinePolicy == nil {
		return statemachine.OfflinePolicy{}, nil
	}
	b := t.OfflinePolicy

	maxPolicy, err := parseFreshnessDuration("max_policy_cache_age", b.MaxPolicyCacheAge, 0)
	if err != nil {
		return statemachine.OfflinePolicy{}, err
	}
	maxRevocation, err := parseFreshnessDuration("max_revocation_cache_age", b.MaxRevocationCacheAge, 0)
	if err != nil {
		return statemachine.OfflinePolicy{}, err
	}
	if b.RequireLocalAudit && !b.Enterprise {
		return statemachine.OfflinePolicy{}, fmt.Errorf("offline_policy: require_local_audit is enterprise-only — set enterprise: true (SPEC-0317 R-7.3/R-8; the decision-invariance carve-out cannot be enabled on a non-enterprise host)")
	}

	return statemachine.OfflinePolicy{
		AllowCachedTrustedSkills: b.AllowCachedTrustedSkills,
		DenyUnknownSkills:        b.DenyUnknownSkills,
		MaxPolicyCacheAge:        maxPolicy,
		MaxRevocationCacheAge:    maxRevocation,
		RequireLocalAudit:        b.RequireLocalAudit,
		Enterprise:               b.Enterprise,
	}, nil
}

// ActiveKeys returns the subset of RegistryKeys that are not retired. It
// preserves the original order so error messages stay deterministic.
func (t TrustRoot) ActiveKeys() []RegistryKey {
	out := make([]RegistryKey, 0, len(t.RegistryKeys))
	for _, k := range t.RegistryKeys {
		if k.IsActive() {
			out = append(out, k)
		}
	}
	return out
}

// FindAuthor returns a pointer to the active pinned AuthorKey for identityID,
// or nil if this root has no active pin for it. Retired pins are skipped so a
// rotated-out author key cannot verify. The returned pointer aliases the
// backing array — callers must not mutate it.
func (t *TrustRoot) FindAuthor(identityID string) *AuthorKey {
	if t == nil {
		return nil
	}
	want := normalizeIdentityID(identityID)
	for i := range t.Authors {
		if normalizeIdentityID(t.Authors[i].ID) == want && t.Authors[i].IsActive() {
			return &t.Authors[i]
		}
	}
	return nil
}

// FindReviewer returns the active pinned reviewer key for identityID, or nil
// (SPEC-0281). Retired pins are skipped. Mirrors FindAuthor. ID matching is
// case-normalized (P1c) so it agrees with the reviewer≠author comparison in
// verify.go — no case-twin asymmetry between lookup and equality.
func (t *TrustRoot) FindReviewer(identityID string) *AuthorKey {
	if t == nil {
		return nil
	}
	want := normalizeIdentityID(identityID)
	for i := range t.Reviewers {
		if normalizeIdentityID(t.Reviewers[i].ID) == want && t.Reviewers[i].IsActive() {
			return &t.Reviewers[i]
		}
	}
	return nil
}

// TrustRoots is the in-memory representation of the YAML file plus a
// resolved absolute path so error messages can quote it back to the user.
type TrustRoots struct {
	// Roots is the list of pinned registries. Order matches file order.
	Roots []TrustRoot `yaml:"trust_roots"`

	// TenantScope, if non-empty, pins this consumer machine to a tenant id
	// for the §7 step 5.5 tenant-block check (SPEC-0188 §4.4 G-18 closure,
	// 2026-05-06). The CLI's `--tenant <id>` flag overrides this for the
	// current invocation; an empty value means "untenanted / global" and
	// step 5.5 is skipped.
	//
	// The field is intentionally top-level (not per-TrustRoot): a
	// machine's tenant identity is a property of the consumer, not of the
	// registry it talks to.
	TenantScope string `yaml:"tenant_scope,omitempty"`

	// DefaultRegistry, if non-empty, names the registry URL that
	// commands which take an optional `--registry` flag (e.g.
	// `skillctl awareness sync`) fall back to when neither the flag
	// nor `$M3C_REGISTRY_URL` is set. SPEC-0195 §10 D2 / §12 question 3
	// closure, 2026-05-06: pin the default registry next to the trust
	// keys it's already pinning.
	//
	// Resolution precedence (consumer-side):
	//
	//	1. explicit --registry flag
	//	2. trust-roots `default_registry`
	//	3. $M3C_REGISTRY_URL
	//	4. error
	//
	// An empty value means "no default" — callers must require the flag.
	DefaultRegistry string `yaml:"default_registry,omitempty"`

	// Environment, if non-empty, names the deployment environment of
	// the registry pinned by `default_registry` (or the only registry,
	// in single-pin home-lab setups). SPEC-0195 §6.1 (G-21 closure
	// 2026-05-06) defines the canonical values:
	//
	//	prod  — production registry; refuses dev-seed identities.
	//	dev   — development registry; permissive.
	//	local — loopback / home-lab registry; permissive.
	//	stage — pre-prod; permissive but distinct from `dev`.
	//
	// The client uses this for the §6.1 short-circuit: if Environment
	// is "prod" and the envelope's client_identity is the SKILLCTL_DEV_SEED
	// synthetic identity, the request is refused before any HTTP call.
	// The registry remains the authoritative gate (server-side check is
	// still enforced); this is just a fast-fail for the obvious case.
	//
	// Spelled with a leading underscore in the YAML to mark it as a
	// metadata / tooling field rather than a trust-policy knob.
	Environment string `yaml:"_environment,omitempty"`

	// Logs pins the transparency log(s) this machine trusts for the
	// SPEC-0278 L1 inclusion-proof check. Each entry pins a log's public
	// key plus a recent (witnessed) STH set. Empty means "no log pinned"
	// and the inclusion check is skipped entirely (unless a per-log policy
	// demands it — which it cannot, since there is no log to demand it).
	//
	// L1 makes equivocation/withholding DETECTABLE, not impossible; pinning
	// a recent STH here is what lets the offline verifier confirm an event
	// is committed under a head it already trusts, and lets cross-witnessed
	// heads surface a split view.
	Logs []LogTrust `yaml:"logs,omitempty"`

	// RequireLogInclusion, when true, makes the ABSENCE of a valid
	// inclusion proof under a pinned STH a HARD refusal (fail-closed). When
	// false (the default) the inclusion check is ADVISORY: a missing/invalid
	// proof is surfaced as a warning but does not block. SPEC-0278 §3 makes
	// this opt-in hard, advisory by default — a transparency log that is
	// still being rolled out should not brick every install.
	RequireLogInclusion bool `yaml:"require_log_inclusion,omitempty"`

	// Path is the resolved absolute file path used by Load (and by
	// Save() on round-trip). Not serialized to YAML.
	Path string `yaml:"-"`
}

// LogTrust pins one transparency log: its identity, its signing public key,
// and a set of STHs the machine has witnessed/accepted. The verifier checks
// inclusion proofs against the pinned STH whose tree_size covers the proof,
// entirely offline.
type LogTrust struct {
	// LogID identifies the log. Must be unique within the file and match
	// the log_id carried in the STHs and in the log's own records.
	LogID string `yaml:"log_id"`

	// LogKeyB64 is the base64 of the raw 32-byte ed25519 LOG public key.
	// Distinct from any registry/author/attestation key — the STH domain
	// separator guarantees a signature over an STH can't be reused as any
	// other envelope, but pinning a dedicated key is still the right
	// hygiene. The loader hydrates LogKey (raw bytes) from this.
	LogKeyB64 string `yaml:"log_key"`

	// LogKey is the decoded raw 32-byte ed25519 public key. Populated by
	// the loader; not serialized (the b64 form round-trips instead).
	LogKey []byte `yaml:"-"`

	// PinnedSTHs is the set of accepted STHs for this log (the witnessed
	// heads). A verifier checks an inclusion proof against the pinned STH
	// whose tree_size >= the proof size (and whose signature verifies under
	// LogKey). Multiple heads support cross-witness split-view detection.
	PinnedSTHs []PinnedSTH `yaml:"pinned_sths,omitempty"`
}

// PinnedSTH is one accepted Signed Tree Head, stored in the trust-roots
// file. The fields mirror translog.STH but live here so the verify package
// declares its own typed loader surface (strict YAML) without importing the
// translog types into the YAML schema.
type PinnedSTH struct {
	TreeSize  int    `yaml:"tree_size"`
	RootHash  string `yaml:"root_hash"`
	Timestamp string `yaml:"timestamp"`
	LogID     string `yaml:"log_id"`
	Signature string `yaml:"signature"`
}

// DefaultPath returns the absolute path to the user's trust-roots file
// (typically ~/.claude/skill-trust-roots.yaml). Returns an error if the
// home directory can't be determined.
func DefaultPath() (string, error) {
	home, err := userHome()
	if err != nil {
		return "", fmt.Errorf("trust-roots: resolve home dir: %w", err)
	}
	return filepath.Join(home, DefaultTrustRootsPath), nil
}

// Load reads and validates the trust-roots YAML at path.
//
// On the first run (file doesn't exist) Load returns a *TrustRoots with
// Path set and Roots empty, plus a wrapped os.ErrNotExist so callers can
// `errors.Is(err, os.ErrNotExist)` to distinguish "file missing" from
// "file malformed". This is what `skillctl trust list` and `skillctl
// trust add` need to bootstrap a config without an extra "exists?" check.
//
// Strict mode: unknown YAML fields are rejected. A typo in `governance_minimum`
// or `registry_keys` would otherwise silently disable a key — the verifier
// would then trust nothing on that registry, refusing every install with a
// confusing "registry not in trust roots" — and the user would never know
// their YAML had a typo. We refuse loudly instead.
func Load(path string) (*TrustRoots, error) {
	if path == "" {
		return nil, errors.New("trust-roots: path is required")
	}
	abs, err := resolveAndValidatePath(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Bootstrap path: empty config, but the error is wrapped
			// so the caller can detect "file missing" deliberately.
			return &TrustRoots{Path: abs}, fmt.Errorf("trust-roots: %w", err)
		}
		return nil, fmt.Errorf("trust-roots: read %s: %w", abs, err)
	}

	var tr TrustRoots
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // strict: unknown fields → error
	if err := dec.Decode(&tr); err != nil {
		return nil, fmt.Errorf("trust-roots: parse %s: %w", abs, err)
	}
	tr.Path = abs

	if err := tr.validate(); err != nil {
		return nil, fmt.Errorf("trust-roots: validate %s: %w", abs, err)
	}
	return &tr, nil
}

// Save writes the TrustRoots back to t.Path with mode 0600. The file is
// written atomically (write to <path>.tmp, fsync, rename) so a crashed
// editor never leaves a half-written config — a corrupted trust-roots file
// would brick `skillctl install` until the user noticed and fixed it.
//
// Mode 0600: the pubkeys themselves aren't secrets, but the file IS the
// machine's policy decision about what to trust, and another local user
// shouldn't be able to silently add a registry to it.
func (t *TrustRoots) Save() error {
	if t == nil {
		return errors.New("trust-roots: Save called on nil")
	}
	if t.Path == "" {
		return errors.New("trust-roots: Path is empty (Load before Save, or set Path explicitly)")
	}
	if err := t.validate(); err != nil {
		return fmt.Errorf("trust-roots: refuse to save invalid config: %w", err)
	}

	// Make sure the parent dir exists (~/.claude/ may not on a fresh
	// machine). 0700 because it lives under the user's home and may
	// hold other Claude state.
	if dir := filepath.Dir(t.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("trust-roots: create parent dir %s: %w", dir, err)
		}
	}

	// Marshal with a 2-space indent for human-friendly diffs.
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(t); err != nil {
		return fmt.Errorf("trust-roots: encode YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("trust-roots: close encoder: %w", err)
	}

	// Atomic write: tmp file in same dir → fsync → rename.
	tmp := t.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("trust-roots: open tmp %s: %w", tmp, err)
	}
	if _, err := f.WriteString(buf.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: write tmp %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: fsync tmp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: close tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, t.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("trust-roots: rename %s → %s: %w", tmp, t.Path, err)
	}
	return nil
}

// AddRegistry registers a new public key under registryURL. It loads the
// pubkey from a PEM SPKI file (the format produced by `skillctl keygen`
// per stream S1's contract), decodes it to 32 raw bytes, and stores it
// base64-encoded in the YAML.
//
// Behavior:
//   - If registryURL has no entry yet, a new TrustRoot is appended with
//     sane defaults (`identity_keys_authorized: from-registry`,
//     `governance_minimum: green`).
//   - If registryURL already has an entry, the new key is appended to
//     its registry_keys list. This is the rotation overlap path: caller
//     is expected to mark the OLD key retired manually (via a future
//     `skillctl trust retire` or by editing the YAML).
//   - keyID is optional. If empty, a default ID derived from the key
//     fingerprint is generated so the user has SOMETHING to refer to.
//
// The pubkey file format uses S1's existing LoadPublicKey (PEM SPKI).
// Storing as base64-of-raw-bytes (per SPEC §4.4) keeps the YAML compact
// and matches the field type the verifier expects at runtime.
func (t *TrustRoots) AddRegistry(registryURL, pubkeyPath, keyID string) error {
	if t == nil {
		return errors.New("trust-roots: AddRegistry called on nil")
	}
	registryURL = strings.TrimRight(strings.TrimSpace(registryURL), "/")
	if registryURL == "" {
		return errors.New("trust-roots: --registry is required")
	}
	if pubkeyPath == "" {
		return errors.New("trust-roots: --pubkey is required")
	}
	if err := validateRegistryURL(registryURL); err != nil {
		return fmt.Errorf("trust-roots: %w", err)
	}

	pub, err := signing.LoadPublicKey(pubkeyPath)
	if err != nil {
		return fmt.Errorf("trust-roots: load pubkey %s: %w", pubkeyPath, err)
	}
	if len(pub) != pubkeyRawSize {
		// Belt-and-braces; signing.LoadPublicKey already enforces this.
		return fmt.Errorf("trust-roots: pubkey %s is %d bytes, want %d", pubkeyPath, len(pub), pubkeyRawSize)
	}
	rawCopy := make([]byte, len(pub))
	copy(rawCopy, pub)
	b64 := base64.StdEncoding.EncodeToString(rawCopy)

	if keyID == "" {
		keyID = deriveKeyID(rawCopy)
	}

	rk := RegistryKey{
		ID:        keyID,
		Pubkey:    rawCopy,
		PubkeyB64: b64,
		Issued:    todayISO(),
	}

	// Find or create the matching TrustRoot.
	if existing := t.findRegistry(registryURL); existing != nil {
		// Reject duplicate ID so the user can find their own entries.
		for _, k := range existing.RegistryKeys {
			if k.ID == rk.ID {
				return fmt.Errorf("trust-roots: registry %s already has a key with id %q", registryURL, rk.ID)
			}
			if k.PubkeyB64 == rk.PubkeyB64 {
				return fmt.Errorf("trust-roots: registry %s already pins this exact pubkey under id %q", registryURL, k.ID)
			}
		}
		existing.RegistryKeys = append(existing.RegistryKeys, rk)
		return nil
	}

	t.Roots = append(t.Roots, TrustRoot{
		RegistryURL:            registryURL,
		RegistryKeys:           []RegistryKey{rk},
		IdentityKeysAuthorized: "from-registry",
		GovernanceMinimum:      "green",
	})
	return nil
}

// FindRegistry returns the TrustRoot for registryURL or nil if there is no
// matching entry. The match is exact after a trailing-slash trim; SPEC §4.4
// does not specify URL canonicalization beyond that.
func (t *TrustRoots) FindRegistry(url string) *TrustRoot {
	if t == nil {
		return nil
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	return t.findRegistry(url)
}

// findRegistry is the unexported lookup; callers via FindRegistry get nil
// safety + URL normalization.
func (t *TrustRoots) findRegistry(url string) *TrustRoot {
	for i := range t.Roots {
		if t.Roots[i].RegistryURL == url {
			return &t.Roots[i]
		}
	}
	return nil
}

// RemoveRegistry deletes the TrustRoot for registryURL. Returns an error
// if no matching entry exists so the CLI can show a clear message.
func (t *TrustRoots) RemoveRegistry(url string) error {
	if t == nil {
		return errors.New("trust-roots: RemoveRegistry called on nil")
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	for i := range t.Roots {
		if t.Roots[i].RegistryURL == url {
			t.Roots = append(t.Roots[:i], t.Roots[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("trust-roots: no registry entry for %s", url)
}

// validate runs the full sanity check on the in-memory model. Called by
// Load (before returning) AND by Save (before writing) so the file on disk
// can never be in a state that Load would reject.
func (t *TrustRoots) validate() error {
	seenURLs := make(map[string]struct{}, len(t.Roots))
	for i, root := range t.Roots {
		if root.RegistryURL == "" {
			return fmt.Errorf("trust_roots[%d]: registry_url is required", i)
		}
		if err := validateRegistryURL(root.RegistryURL); err != nil {
			return fmt.Errorf("trust_roots[%d]: %w", i, err)
		}
		if _, dup := seenURLs[root.RegistryURL]; dup {
			return fmt.Errorf("trust_roots[%d]: duplicate registry_url %q", i, root.RegistryURL)
		}
		seenURLs[root.RegistryURL] = struct{}{}

		if len(root.RegistryKeys) == 0 {
			return fmt.Errorf("trust_roots[%d] %s: registry_keys is empty (a registry with no keys is useless)", i, root.RegistryURL)
		}
		seenIDs := make(map[string]struct{}, len(root.RegistryKeys))
		for j, k := range root.RegistryKeys {
			if k.ID == "" {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d]: id is required", i, j)
			}
			if _, dup := seenIDs[k.ID]; dup {
				return fmt.Errorf("trust_roots[%d] %s: duplicate key id %q", i, root.RegistryURL, k.ID)
			}
			seenIDs[k.ID] = struct{}{}

			if k.PubkeyB64 == "" {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d] (%s): pubkey is required", i, j, k.ID)
			}
			raw, err := base64.StdEncoding.DecodeString(k.PubkeyB64)
			if err != nil {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d] (%s): pubkey is not valid base64: %w", i, j, k.ID, err)
			}
			if len(raw) != pubkeyRawSize {
				return fmt.Errorf("trust_roots[%d].registry_keys[%d] (%s): pubkey decodes to %d bytes, want %d", i, j, k.ID, len(raw), pubkeyRawSize)
			}
			// Hydrate Pubkey from PubkeyB64 so callers downstream
			// don't redo the decode.
			t.Roots[i].RegistryKeys[j].Pubkey = raw
		}
		if root.IdentityKeysAuthorized == "" {
			return fmt.Errorf("trust_roots[%d] %s: identity_keys_authorized is required", i, root.RegistryURL)
		}
		if _, ok := validIdentityModes[root.IdentityKeysAuthorized]; !ok {
			return fmt.Errorf("trust_roots[%d] %s: identity_keys_authorized %q is not one of [from-registry, pinned]", i, root.RegistryURL, root.IdentityKeysAuthorized)
		}

		// Pinned-author mode (SPEC-0276 R4.1): the authors list is the local
		// authority for author pubkeys, so it must be non-empty and every
		// entry must decode to a valid ed25519 key. In from-registry mode the
		// list is ignored, but we still validate any entries present so a typo
		// can't lie dormant until the operator flips the mode.
		if root.IdentityKeysAuthorized == "pinned" && len(root.Authors) == 0 {
			return fmt.Errorf("trust_roots[%d] %s: identity_keys_authorized: pinned requires a non-empty authors list", i, root.RegistryURL)
		}
		seenAuthorIDs := make(map[string]struct{}, len(root.Authors))
		for j, a := range root.Authors {
			if a.ID == "" {
				return fmt.Errorf("trust_roots[%d].authors[%d]: id is required", i, j)
			}
			if _, dup := seenAuthorIDs[a.ID]; dup {
				return fmt.Errorf("trust_roots[%d] %s: duplicate author id %q", i, root.RegistryURL, a.ID)
			}
			seenAuthorIDs[a.ID] = struct{}{}
			if a.PubkeyB64 == "" {
				return fmt.Errorf("trust_roots[%d].authors[%d] (%s): pubkey is required", i, j, a.ID)
			}
			raw, err := base64.StdEncoding.DecodeString(a.PubkeyB64)
			if err != nil {
				return fmt.Errorf("trust_roots[%d].authors[%d] (%s): pubkey is not valid base64: %w", i, j, a.ID, err)
			}
			if len(raw) != pubkeyRawSize {
				return fmt.Errorf("trust_roots[%d].authors[%d] (%s): pubkey decodes to %d bytes, want %d", i, j, a.ID, len(raw), pubkeyRawSize)
			}
			if a.Fingerprint != "" {
				want := authorFingerprint(raw)
				if !strings.EqualFold(strings.TrimSpace(a.Fingerprint), want) {
					return fmt.Errorf("trust_roots[%d].authors[%d] (%s): fingerprint %q does not match pubkey (derived %s)", i, j, a.ID, a.Fingerprint, want)
				}
			}
			// Hydrate raw bytes so the verifier doesn't redo the decode.
			t.Roots[i].Authors[j].Pubkey = raw
		}

		// Pinned reviewers (SPEC-0281): same validation as authors. If
		// require_signed_governance is set there must be at least one reviewer
		// to verify against. Entries present without the flag are still
		// validated (so a typo can't lie dormant).
		if root.RequireSignedGovernance && len(root.Reviewers) == 0 {
			return fmt.Errorf("trust_roots[%d] %s: require_signed_governance needs a non-empty reviewers list", i, root.RegistryURL)
		}
		// SPEC-0246 §5.2 (P1b): the reviewer≠author floor can only be ENFORCED if
		// the verifier has pinned reviewer keys to PROVE independence (the floor
		// requires a signature-verified independent attestation, not the unsigned
		// sidecar reviewer_id). Refuse to load a floor that lacks the keys to
		// enforce it — mirrors how require_signed_governance requires reviewers,
		// so the floor cannot be set fail-OPEN.
		if root.RequireIndependentReview && len(root.Reviewers) == 0 {
			return fmt.Errorf("trust_roots[%d] %s: require_independent_review needs a non-empty reviewers list (the floor is proven by a signature-verified independent attestation)", i, root.RegistryURL)
		}
		// SPEC-0277 §11.5: the agent approver floor is enforced by a
		// signature-verified approver pinned in the reviewers list (approvers reuse
		// the same pinned-reviewer slot, owners reuse authors). Refuse a floor with
		// no pinned approver keys — same fail-OPEN guard as require_independent_review.
		if root.RequireAgentApprover && len(root.Reviewers) == 0 {
			return fmt.Errorf("trust_roots[%d] %s: require_agent_approver needs a non-empty reviewers list (the approver/sign-off human is a pinned reviewer key)", i, root.RegistryURL)
		}
		seenReviewerIDs := make(map[string]struct{}, len(root.Reviewers))
		for j, r := range root.Reviewers {
			if r.ID == "" {
				return fmt.Errorf("trust_roots[%d].reviewers[%d]: id is required", i, j)
			}
			if _, dup := seenReviewerIDs[r.ID]; dup {
				return fmt.Errorf("trust_roots[%d] %s: duplicate reviewer id %q", i, root.RegistryURL, r.ID)
			}
			seenReviewerIDs[r.ID] = struct{}{}
			if r.PubkeyB64 == "" {
				return fmt.Errorf("trust_roots[%d].reviewers[%d] (%s): pubkey is required", i, j, r.ID)
			}
			raw, err := base64.StdEncoding.DecodeString(r.PubkeyB64)
			if err != nil {
				return fmt.Errorf("trust_roots[%d].reviewers[%d] (%s): pubkey is not valid base64: %w", i, j, r.ID, err)
			}
			if len(raw) != pubkeyRawSize {
				return fmt.Errorf("trust_roots[%d].reviewers[%d] (%s): pubkey decodes to %d bytes, want %d", i, j, r.ID, len(raw), pubkeyRawSize)
			}
			if r.Fingerprint != "" {
				want := authorFingerprint(raw)
				if !strings.EqualFold(strings.TrimSpace(r.Fingerprint), want) {
					return fmt.Errorf("trust_roots[%d].reviewers[%d] (%s): fingerprint %q does not match pubkey (derived %s)", i, j, r.ID, r.Fingerprint, want)
				}
			}
			t.Roots[i].Reviewers[j].Pubkey = raw
		}

		// P1c key-confusion guard: the SAME key must not be pinned as BOTH an
		// author and a reviewer in one root. Otherwise the author could sign an
		// "independent" governance attestation under a reviewer id and launder
		// reviewer≠author (the floor compares ids, not key bytes). Compare raw
		// pubkey bytes — ids may differ while the key is the same.
		for ai := range t.Roots[i].Authors {
			for ri := range t.Roots[i].Reviewers {
				if string(t.Roots[i].Authors[ai].Pubkey) == string(t.Roots[i].Reviewers[ri].Pubkey) {
					return fmt.Errorf("trust_roots[%d] %s: key pinned as both author %q and reviewer %q — a key cannot be both (key-confusion)", i, root.RegistryURL, t.Roots[i].Authors[ai].ID, t.Roots[i].Reviewers[ri].ID)
				}
			}
		}

		if root.MinRevocationEpoch < 0 {
			return fmt.Errorf("trust_roots[%d] %s: min_revocation_epoch must be >= 0", i, root.RegistryURL)
		}

		// SPEC-0279 R2 — the revocation-freshness policy fields. Validate the
		// duration strings, the fail_policy vocabulary, and the per-risk override
		// map (including the high⇒closed floor) by constructing the resolved
		// FreshnessPolicy; a bad value is refused at Load so a typo cannot lie
		// dormant and silently disable the staleness ceiling.
		if _, ferr := root.Freshness(); ferr != nil {
			return fmt.Errorf("trust_roots[%d] %s: %w", i, root.RegistryURL, ferr)
		}

		// SPEC-0317 R-7.3 — the offline_policy block. Resolve it at Load so a
		// bad duration or an enterprise-only knob set without `enterprise` is
		// refused loudly (a typo cannot lie dormant and silently mis-state the
		// offline posture). Mirrors the Freshness() call above.
		if _, oerr := root.ResolveOfflinePolicy(); oerr != nil {
			return fmt.Errorf("trust_roots[%d] %s: %w", i, root.RegistryURL, oerr)
		}

		if root.GovernanceMinimum == "" {
			return fmt.Errorf("trust_roots[%d] %s: governance_minimum is required", i, root.RegistryURL)
		}
		// One shared floor guard (SPEC-0252 §6) — same {green,yellow}, red-and-
		// unknown-rejected check the self loader uses. Store the normalized form
		// back into the loaded root so the governance comparison can't depend on
		// re-normalising mixed case (matches registry.LoadSelfTrustRoots).
		norm, ok := govlevel.ValidFloor(root.GovernanceMinimum)
		if !ok {
			return fmt.Errorf("trust_roots[%d] %s: governance_minimum %q is not one of [green, yellow]", i, root.RegistryURL, root.GovernanceMinimum)
		}
		t.Roots[i].GovernanceMinimum = norm
	}

	// SPEC-0278 L1: validate + hydrate the pinned transparency logs.
	if err := t.validateLogs(); err != nil {
		return err
	}
	return nil
}

// validateLogs runs strict validation over the SPEC-0278 `logs` block and
// hydrates LogKey (raw bytes) from LogKeyB64 so callers don't re-decode.
// Each log id must be unique; each log key must decode to a 32-byte ed25519
// public key; each pinned STH must carry the SAME log_id, a 64-hex root, a
// 128-hex signature, and tree_size >= 1.
func (t *TrustRoots) validateLogs() error {
	seenLogs := make(map[string]struct{}, len(t.Logs))
	for i := range t.Logs {
		lt := &t.Logs[i]
		if lt.LogID == "" {
			return fmt.Errorf("logs[%d]: log_id is required", i)
		}
		if _, dup := seenLogs[lt.LogID]; dup {
			return fmt.Errorf("logs[%d]: duplicate log_id %q", i, lt.LogID)
		}
		seenLogs[lt.LogID] = struct{}{}

		if lt.LogKeyB64 == "" {
			return fmt.Errorf("logs[%d] %s: log_key is required", i, lt.LogID)
		}
		raw, err := base64.StdEncoding.DecodeString(lt.LogKeyB64)
		if err != nil {
			return fmt.Errorf("logs[%d] %s: log_key is not valid base64: %w", i, lt.LogID, err)
		}
		if len(raw) != pubkeyRawSize {
			return fmt.Errorf("logs[%d] %s: log_key decodes to %d bytes, want %d", i, lt.LogID, len(raw), pubkeyRawSize)
		}
		lt.LogKey = raw

		for j, s := range lt.PinnedSTHs {
			if s.LogID != lt.LogID {
				return fmt.Errorf("logs[%d].pinned_sths[%d]: log_id %q must match parent log %q", i, j, s.LogID, lt.LogID)
			}
			if s.TreeSize < 1 {
				return fmt.Errorf("logs[%d].pinned_sths[%d]: tree_size must be >= 1", i, j)
			}
			if len(s.RootHash) != 64 {
				return fmt.Errorf("logs[%d].pinned_sths[%d]: root_hash must be 64 hex chars", i, j)
			}
			if len(s.Signature) != 128 {
				return fmt.Errorf("logs[%d].pinned_sths[%d]: signature must be 128 hex chars", i, j)
			}
		}
	}
	return nil
}

// FindLog returns the pinned LogTrust for logID, or nil if none is pinned.
func (t *TrustRoots) FindLog(logID string) *LogTrust {
	if t == nil {
		return nil
	}
	for i := range t.Logs {
		if t.Logs[i].LogID == logID {
			return &t.Logs[i]
		}
	}
	return nil
}

// validateRegistryURL enforces an allowlist of URL schemes. HTTPS is
// always permitted; HTTP is permitted ONLY when the host is loopback or
// in an RFC1918 private range (so the home-lab MinIO at
// http://192.168.0.131:9100 works without `--allow-insecure`). Anything
// else is refused — a plain-HTTP public-Internet registry is exactly the
// scenario the trust-chain is meant to prevent.
//
// We keep this loose enough to be useful (no DNS lookup; no TLS probe)
// and strict enough that a public-Internet HTTP URL cannot land in the
// pinned config by accident.
func validateRegistryURL(url string) error {
	if strings.HasPrefix(url, "https://") {
		return nil
	}
	if strings.HasPrefix(url, "http://") {
		host := url[len("http://"):]
		// Strip path: take everything up to '/' or end.
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		// Strip port: take everything before ':'.
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		if isLoopbackOrPrivate(host) {
			return nil
		}
		return fmt.Errorf("registry_url %q uses http:// on a non-private host (only loopback and RFC1918 are allowed for plain HTTP)", url)
	}
	return fmt.Errorf("registry_url %q must use https:// (or http:// for loopback / RFC1918 only)", url)
}

// isLoopbackOrPrivate reports whether host is a loopback address or in an
// RFC1918 / IPv6-loopback range. This is intentionally lexical (no net
// lookups): "localhost" is loopback; "127.x.y.z" is loopback; "10.x.y.z",
// "192.168.x.y", "172.16.x.y" through "172.31.x.y" are private; "::1" is
// loopback.
func isLoopbackOrPrivate(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if strings.HasPrefix(host, "127.") {
		return true
	}
	if strings.HasPrefix(host, "10.") {
		return true
	}
	if strings.HasPrefix(host, "192.168.") {
		return true
	}
	if strings.HasPrefix(host, "172.") {
		// 172.16.0.0 – 172.31.255.255
		// Parse the second octet.
		rest := host[len("172."):]
		end := strings.IndexByte(rest, '.')
		if end < 0 {
			return false
		}
		oct := rest[:end]
		if len(oct) == 0 || len(oct) > 3 {
			return false
		}
		var n int
		for _, c := range oct {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		return n >= 16 && n <= 31
	}
	return false
}

// resolveAndValidatePath expands `~` in path, makes it absolute, and
// confirms it lies inside the user's home directory. The home-dir check
// is a defense against a misconfigured environment (HOME pointing somewhere
// surprising) silently picking up a config from an unexpected location.
//
// Test environments can override the home dir by setting HOME, since we
// route through userHome() which honors HOME on ALL platforms (os.UserHomeDir
// alone would read %USERPROFILE% on Windows and ignore HOME).
func resolveAndValidatePath(path string) (string, error) {
	expanded := path
	if strings.HasPrefix(path, "~/") {
		home, err := userHome()
		if err != nil {
			return "", fmt.Errorf("trust-roots: resolve ~: %w", err)
		}
		expanded = filepath.Join(home, path[2:])
	} else if path == "~" {
		home, err := userHome()
		if err != nil {
			return "", fmt.Errorf("trust-roots: resolve ~: %w", err)
		}
		expanded = home
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return "", fmt.Errorf("trust-roots: abs %s: %w", path, err)
	}
	// We do NOT enforce the home-dir constraint when an explicit
	// absolute path is provided by the caller (test code, alternate
	// config locations). The constraint only applies when the
	// CLI defaulted to ~/.claude/...; that guard lives at the CLI
	// boundary, not in Load.
	return abs, nil
}

// authorFingerprint returns the canonical "sha256:<hex>" fingerprint over the
// raw ed25519 pubkey bytes. This MUST match the derivation used everywhere
// else in the trust stack (registry.selfFingerprint, cmd pubkeyFingerprint) so
// a fingerprint an operator reads from one tool can be pinned in another and
// cross-checked out-of-band. hexLower lives in verify.go (same package).
func authorFingerprint(rawPub []byte) string {
	sum := sha256.Sum256(rawPub)
	return "sha256:" + hexLower(sum[:])
}

// deriveKeyID returns a short, deterministic id of the form "key-<hex8>"
// derived from the first 4 bytes of the raw pubkey. Used as a fallback
// when the user doesn't pass --id.
func deriveKeyID(rawPub []byte) string {
	if len(rawPub) < 4 {
		return "key-unknown"
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len("key-")+8)
	out = append(out, "key-"...)
	for _, b := range rawPub[:4] {
		out = append(out, hex[b>>4], hex[b&0x0f])
	}
	return string(out)
}

// todayISO returns today's date in YYYY-MM-DD format. Pulled out as a var
// so tests can stub time without dragging the time package into the
// data-model file's hot path.
var todayISO = func() string {
	return nowISO()
}
