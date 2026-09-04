package registry

// ER1 pull + registry-view path for the `self` tenant (SPEC-0225 P2).
//
// Three exported entry points:
//
//   ListRegistry: query ER1, build a per-skill registry view (admit history
//                   + attestations + installs + revocations), dedupe by digest.
//                   Implements `skillctl registry ls [--latest]`.
//
//   ShowSkill: return the full timeline for one skill (all events,
//                   sorted by occurred_at). Implements `registry show <name>`.
//
//   PullBundles: for each `admitted` event matching the query, run the
//                   five-gate verification gauntlet (envelope sig vs
//                   trust-roots → digest → bundle author+registry sigs →
//                   governance floor → not-revoked) and stage the .skb to
//                   ~/.cache/m3c/skill-bundles/<digest>/. Implements
//                   `skillctl pull` (and the verification half of
//                   `pull --install`).
//
// The publisher's body shape (renderAdmittedBody) writes a ```json fenced block
// with the SPEC-0190 event + an optional ```skb-base64 block. Pull parses both
// out of the item's stored body text.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustcore"
)

// ─── Errors ────────────────────────────────────────────────────────────────

// Gate-failure sentinels: `pull` reports the specific gate that rejected
// each bundle so the operator sees what to fix.
var (
	ErrGateEnvelope    = errors.New("gate 1: envelope_signature does not verify against trust-roots")
	ErrGateDigest      = errors.New("gate 2: SHA-256 of the fetched .skb does not match the skill-digest tag / bundle_digest")
	ErrGateBundleSigs  = errors.New("gate 3: bundle author/registry signature(s) do not verify against trust-roots")
	ErrGateGovernance  = errors.New("gate 4: no attestation at or above the trust-roots governance_minimum")
	ErrGateRevoked     = errors.New("gate 5: bundle digest has a BundleRevokedEvent in the registry")
	ErrBundleBytesMiss = errors.New("admitted item has no inline ```skb-base64 block and no blob_uri (claim-check not implemented yet)")
)

// ─── Listing / show types ──────────────────────────────────────────────────

// EventRow is one row of the per-skill timeline.
type EventRow struct {
	Kind       string         // "admitted" | "attested" | "revoked" | "installed"
	DocID      string         // ER1 doc_id
	OccurredAt string         // RFC3339 from the event's occurred_at
	Governance string         // attested events: the level; admitted: the author_intent; else ""
	Host       string         // admit packed-on host; installed-on host; else ""
	Transport  string         // admit only
	Rationale  string         // attest / revoke
	Event      map[string]any // parsed event JSON
	RawBody    string         // the markdown body (for ShowSkill rendering)
}

// SkillView is the registry-view entry for one skill.
type SkillView struct {
	Name             string
	LatestVersion    string
	LatestDigest     string
	LatestGovernance string // newest non-revoked attestation
	IsRevoked        bool   // latest digest carries a revoked event
	Events           []EventRow
}

// RegistryListing is the registry-ls result.
type RegistryListing struct {
	Skills []SkillView
}

// ListOpts bounds the query.
type ListOpts struct {
	OnlySkill  string // empty → all skills
	OnlyLatest bool   // collapse to newest non-revoked digest per skill
	Since      string // RFC3339 lower bound (matched against occurred_at): optional
}

// ListRegistry queries ER1 for m3c-skill-bundle items, groups by skill, dedupes
// by digest, and returns the registry view.
func ListRegistry(cfg *er1.Config, ctxID string, opts ListOpts) (*RegistryListing, error) {
	rawItems, err := searchByTagsRaw(cfg, ctxID, []string{"m3c-skill-bundle", "skill-registry:self"})
	if err != nil {
		return nil, err
	}
	rowsByDigest := map[string][]EventRow{}
	skillOf := map[string]string{} // digest → skill name
	verOf := map[string]string{}   // digest → version
	for _, item := range rawItems {
		row, digest, skillName, version, _ := parseRowFromItem(item)
		if digest == "" {
			continue
		}
		if opts.OnlySkill != "" && skillName != opts.OnlySkill {
			continue
		}
		rowsByDigest[digest] = append(rowsByDigest[digest], row)
		if skillName != "" {
			skillOf[digest] = skillName
		}
		if version != "" {
			verOf[digest] = version
		}
	}
	// Group digests by skill name.
	digestsBySkill := map[string][]string{}
	for digest, name := range skillOf {
		digestsBySkill[name] = append(digestsBySkill[name], digest)
	}
	var skills []SkillView
	for name, digests := range digestsBySkill {
		// Sort digests by the latest occurred_at of their admit row (newest first).
		sort.Slice(digests, func(i, j int) bool {
			return latestAdmitTS(rowsByDigest[digests[i]]) > latestAdmitTS(rowsByDigest[digests[j]])
		})
		var view SkillView
		view.Name = name
		for _, d := range digests {
			rows := rowsByDigest[d]
			isRevoked := false
			gov := ""
			for _, r := range rows {
				if r.Kind == EventKindRevoked {
					isRevoked = true
				}
				if r.Kind == EventKindAttested && r.Governance != "" {
					gov = r.Governance
				}
			}
			if opts.OnlyLatest {
				if isRevoked {
					continue
				}
				view.LatestDigest = d
				view.LatestVersion = verOf[d]
				view.LatestGovernance = gov
				view.IsRevoked = isRevoked
				view.Events = rows
				break
			}
			// not --latest: collect all digests
			if view.LatestDigest == "" {
				view.LatestDigest = d
				view.LatestVersion = verOf[d]
				view.LatestGovernance = gov
				view.IsRevoked = isRevoked
			}
			view.Events = append(view.Events, rows...)
		}
		if opts.OnlyLatest && view.LatestDigest == "" {
			// Skill is fully revoked → skip in --latest mode.
			continue
		}
		skills = append(skills, view)
	}
	sort.Slice(skills, func(i, j int) bool { return skills[i].Name < skills[j].Name })
	return &RegistryListing{Skills: skills}, nil
}

// ShowSkill returns full detail for one skill, addressed by name or a
// `sha256:<hex>` digest.
func ShowSkill(cfg *er1.Config, ctxID, nameOrDigest string) (*SkillView, error) {
	opts := ListOpts{}
	if strings.HasPrefix(nameOrDigest, "sha256:") {
		// Address by digest: list all and filter.
		listing, err := ListRegistry(cfg, ctxID, ListOpts{})
		if err != nil {
			return nil, err
		}
		for _, s := range listing.Skills {
			for _, e := range s.Events {
				if d, _ := e.Event["bundle_digest"].(string); d == nameOrDigest {
					return &s, nil
				}
			}
		}
		return nil, fmt.Errorf("show: digest %q not found in registry", nameOrDigest)
	}
	opts.OnlySkill = nameOrDigest
	listing, err := ListRegistry(cfg, ctxID, opts)
	if err != nil {
		return nil, err
	}
	for _, s := range listing.Skills {
		if s.Name == nameOrDigest {
			// Sort events newest-first for display.
			sort.Slice(s.Events, func(i, j int) bool { return s.Events[i].OccurredAt > s.Events[j].OccurredAt })
			return &s, nil
		}
	}
	return nil, fmt.Errorf("show: skill %q not found in registry", nameOrDigest)
}

// ─── Pull + 5-gate gauntlet ────────────────────────────────────────────────

// StagedBundle is one verified bundle, with the .skb bytes (decoded inline or
// fetched from MinIO) cached on disk under ~/.cache/m3c/skill-bundles/<digest>/.
type StagedBundle struct {
	Name           string
	Version        string
	Digest         string // sha256:<hex>
	Governance     string // attested level (≥ governance_minimum)
	PackedOnHost   string
	AdmittedAt     string
	StagedSkbPath  string // <cache>/<digest>/bundle.skb
	ProvenancePath string // <cache>/<digest>/.m3c-provenance.json  (P3 will copy these into ~/.claude/skills/...)
	SourceDocID    string // ER1 doc_id of the admit item
	AuthorIdentity string
	// Attestation is the SIGNED context (admit event + governance attestation)
	// that just passed the pull gates. installOne stashes it so the runtime
	// gate can re-verify against the pinned key with no network (SPEC-0266 F2/F19).
	Attestation *AttestationContext
}

// PullOpts bounds the pull.
type PullOpts struct {
	OnlySkill  string    // empty → all skills
	OnlyDigest string    // empty → all admit items in scope
	Since      string    // RFC3339; pass to the search query (best-effort filter)
	Now        time.Time // injectable clock for attestation freshness (D5); zero → time.Now()

	// FR-0090 IS-RS-01: signed revoke-HEAD consultation. Gate 5's revoked set is
	// built only from tag DISCOVERY (searchByTagsRaw, limit=500, range=year), which
	// a hostile/compromised tenant can truncate so a revoke never enters the
	// accumulator (strip a tag, age it past a year, or flood past 500). The signed
	// revocation HEAD (revoked_set_root + emergency[], verified against the pinned
	// trust root) is the authority that catches such an omission. These carry it in.
	RevocationHeadURL string // registry base for FetchRevocationHead; "" → HEAD not consulted (best-effort)
	// RevocationHeadTenant is the optional tenant_scope for the HEAD fetch.
	RevocationHeadTenant string
	// RequireRevocationHead is the freshness policy (mirror IS-T5). When true, an
	// UNCONFIGURED / UNREACHABLE / UNVERIFIABLE HEAD FAILS the pull closed (a managed
	// enterprise root demands a fresh revoke authority); when false, HEAD consultation
	// is best-effort (a fetch failure falls back to discovery + the cap-hit trigger).
	RequireRevocationHead bool
	// RevocationHeadFloorEpoch is the client's epoch floor for SPEC-0279 R1 rollback
	// protection: consultRevokeHead rejects a fetched HEAD whose epoch is below this,
	// defeating a replay of an older validly-signed HEAD. Resolve it as
	// max(readRevokedCacheHead(home).epoch, root.MinRevocationEpoch).
	RevocationHeadFloorEpoch int
	// RevocationHeadMaxStaleness, when > 0, rejects a validly-signed monotonic HEAD
	// whose issued_at is older than this (freshness). 0 → epoch-floor only.
	RevocationHeadMaxStaleness time.Duration
}

// now resolves the freshness clock (zero → wall clock).
func (o PullOpts) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// PullResult reports the outcome of a pull.
type PullResult struct {
	Staged   []*StagedBundle
	Skipped  []*PullSkip // bundles rejected by one of the 5 gates
	Warnings []string    // non-fatal advisories (e.g. a best-effort revoke-discovery cap-hit)
}

// PullSkip is a per-bundle rejection.
type PullSkip struct {
	Name    string
	Version string
	Digest  string
	DocID   string
	Gate    error // one of ErrGateEnvelope/Digest/BundleSigs/Governance/Revoked
	Detail  string
}

// pullRevocationHeadTimeout bounds the HEAD fetch during a pull. Short by design:
// the HEAD is a best-effort authority unless a freshness policy demands it, so a
// slow/unreachable registry must not stall the gauntlet.
const pullRevocationHeadTimeout = 3 * time.Second

// pullRevocationHeadFetch is the injectable seam PullBundles uses to fetch the
// signed revocation HEAD (FR-0090 IS-RS-01). Production = FetchRevocationHead
// (the SAME mechanism the SessionStart quarantine sweep reuses); tests replace it
// to serve a signed HEAD offline.
var pullRevocationHeadFetch = FetchRevocationHead

// revokeHeadDecision is the outcome of consulting the signed revoke HEAD for a
// pull. denySet lists digests to refuse OUTRIGHT (the HEAD's emergency[] burn
// list, enumerable inline). discoveryIncomplete is true when the pull must fail
// CLOSED for every candidate because it cannot prove its DISCOVERED revoked set
// is complete: the HEAD verified but its revoked_set_root did NOT match the
// discovered set (a revoke was omitted from discovery), OR discovery hit the page
// cap without a verified HEAD to independently prove completeness, OR a freshness
// policy demanded a HEAD that was unconfigured/unreachable/unverifiable.
type revokeHeadDecision struct {
	denySet             map[string]struct{}
	discoveryIncomplete bool
	reason              string
	capWarning          string // non-fatal: a best-effort cap-hit that does NOT brick the pull
}

func (d revokeHeadDecision) denies(digest string) bool {
	_, ok := d.denySet[digest]
	return ok
}

// consultRevokeHead binds the DISCOVERED revoked set to the signed revocation
// HEAD. discoveredRevoked is acc.RevokedDigests(); discoveryCapHit is whether the
// discovery page was truncated. Fail-closed everywhere a completeness claim
// cannot be proven; best-effort (no HEAD) only when RequireRevocationHead is off.
func consultRevokeHead(tr *SelfTrustRoots, opts PullOpts, discoveredRevoked []string, discoveryCapHit bool) revokeHeadDecision {
	dec := revokeHeadDecision{denySet: map[string]struct{}{}}

	// capFallback handles a discovery page-cap hit when there is no trustworthy
	// HEAD to prove completeness. When a HEAD is REQUIRED it is a hard fail-closed;
	// on a best-effort (self) host it is only a WARNING (IS-RS-01c): searchTagsLimit
	// is counted on RAW context items (not the tag-filtered skill set), so it is
	// not a reliable completeness signal on its own, and bricking every pull once a
	// self context grows past the cap is a worse failure than the residual it guards.
	capFallback := func() {
		if opts.RequireRevocationHead {
			dec.discoveryIncomplete = true
			dec.reason = fmt.Sprintf("revocation HEAD required but unavailable/unverifiable and discovery hit the %d-item cap. Completeness cannot be proven", searchTagsLimit)
			return
		}
		if discoveryCapHit {
			dec.capWarning = fmt.Sprintf("revocation discovery page hit the %d-item cap and no trustworthy signed HEAD proves completeness (best-effort self host)", searchTagsLimit)
		}
	}

	if opts.RevocationHeadURL == "" {
		capFallback()
		return dec
	}

	head, ferr := pullRevocationHeadFetch(opts.RevocationHeadURL, opts.RevocationHeadTenant, pullRevocationHeadTimeout)
	if ferr != nil {
		capFallback()
		return dec
	}

	// (1) Signature. An untrustworthy HEAD is not a completeness proof: a REQUIRED
	// HEAD fails closed; a best-effort host falls back to the cap rule (a flaky/bad
	// response must not brick a self host).
	if VerifyEnvelopeSignature(tr.PubKey(), head) != nil {
		if opts.RequireRevocationHead {
			dec.discoveryIncomplete = true
			dec.reason = "revocation HEAD required by policy but unverifiable (bad signature)"
			return dec
		}
		capFallback()
		return dec
	}

	// (2) Epoch monotonicity: the IS-RS-01 replay/rollback fix, enforced at EVERY
	// policy level. A signature-only check accepted a replayed OLD-but-validly-signed
	// HEAD (e.g. the genesis head: epoch 0, empty set) whose stale revoked_set_root
	// matched a hostile-truncated discovery, silently un-revoking everything. A HEAD
	// whose epoch is below the persisted/pinned floor is an unambiguous active-attack
	// signal → fail closed. (Residual, documented honestly: a brand-new self host
	// that has never synced AND pins no min_revocation_epoch has floor 0, so a
	// first-contact genesis replay still passes here: inherent TOFU; the sweep
	// advances the floor after the first legitimate sync, and on `self` the tenant is
	// the author/trust-root owner anyway. A managed root closes it via
	// min_revocation_epoch.) A same-epoch-but-stale HEAD cannot omit a revoke the
	// current epoch commits to (its revoked_set_root is unchanged, so step (5) still
	// binds); the issued_at freshness in step (3) is the defense-in-depth against it
	// and fires only under a max_staleness policy (managed roots default 48h; a self
	// host with no policy relies on the epoch floor + set-root binding). We do NOT
	// persist the epoch here. The pull is read-only.
	if err := CheckEpochMonotonic(head, opts.RevocationHeadFloorEpoch); err != nil {
		dec.discoveryIncomplete = true
		dec.reason = "revocation HEAD epoch rolled back below the accepted floor (replay/rollback): " + err.Error()
		return dec
	}

	// (3) Freshness: a validly-signed, monotonic, but stale HEAD must not prove
	// completeness when a max_staleness policy is set.
	if opts.RevocationHeadMaxStaleness > 0 {
		if ia, e := HeadIssuedAt(head); e != nil || opts.now().Sub(ia) > opts.RevocationHeadMaxStaleness {
			dec.discoveryIncomplete = true
			dec.reason = "revocation HEAD is older than the max_staleness freshness policy (or has no valid issued_at)"
			return dec
		}
	}

	// (4) tenant_scope (defense-in-depth): a HEAD committing to a different tenant's
	// scope must not bind ours.
	if opts.RevocationHeadTenant != "" {
		if ts, _ := headString(head, "tenant_scope"); ts != "" && ts != opts.RevocationHeadTenant {
			dec.discoveryIncomplete = true
			dec.reason = "revocation HEAD tenant_scope does not match the expected tenant"
			return dec
		}
	}

	// (5) Bind the discovered revoked set to the HEAD's committed root. A MATCH
	// proves discovery is complete; a MISMATCH means discovery omitted a revoke the
	// (now signature-verified, monotonic, fresh) HEAD commits to → fail closed.
	if VerifyRevocationHeadSet(head, discoveredRevoked) != nil {
		dec.discoveryIncomplete = true
		dec.reason = "revocation HEAD revoked_set_root does not match the discovered revoked set (a revoke was omitted from discovery)"
		return dec
	}

	// HEAD accepted (verified, monotonic, fresh, tenant-correct, set-root bound →
	// discovery complete). Deny each enumerable emergency (burned) digest outright.
	if em, e := HeadEmergency(head); e == nil {
		for _, d := range em {
			dec.denySet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}
	}
	return dec
}

// PullBundles runs the 5-gate gauntlet over every admit item in scope and
// stages the bytes for those that pass. Returns ErrTrustRootsMissing (wrapped)
// if the trust-roots file is absent. Other errors are transport-level.
func PullBundles(cfg *er1.Config, ctxID string, tr *SelfTrustRoots, opts PullOpts) (*PullResult, error) {
	if tr == nil {
		return nil, ErrTrustRootsMissing
	}
	tags := []string{"m3c-skill-bundle", "skill-registry:self", "skill-event:" + EventKindAdmitted}
	if opts.OnlySkill != "" {
		tags = append(tags, "skill:"+opts.OnlySkill)
	}
	if opts.OnlyDigest != "" {
		tags = append(tags, "skill-digest:"+opts.OnlyDigest)
	}
	admits, err := searchByTagsRaw(cfg, ctxID, tags)
	if err != nil {
		return nil, err
	}
	// Pre-build a map of digest → highest attestation level + revocation flag
	// from a single secondary query. SEC-H1: the trust-roots public key is
	// passed in so loadAttestRevoke verifies the envelope_signature of EVERY
	// attest/revoke event before trusting its governance_level / revoked status
	//. Mirroring Gate 1's admit-envelope verification (~:297). An unsigned or
	// forged governance verdict is otherwise free to forge.
	acc, discoveryCapHit, err := loadAttestAccumulator(cfg, ctxID, tr, opts.now())
	if err != nil {
		return nil, err
	}

	// FR-0090 IS-RS-01: consult the SIGNED revoke HEAD to catch a revoke that tag
	// discovery MISSED, and to fail closed when we cannot prove the discovered
	// revoked set is complete. Reuses FetchRevocationHead (the same mechanism the
	// SessionStart quarantine sweep uses) and verifies it against the pinned key.
	headDec := consultRevokeHead(tr, opts, acc.RevokedDigests(), discoveryCapHit)

	cacheRoot := defaultCacheRoot()
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		return nil, fmt.Errorf("pull: mkdir cache: %w", err)
	}

	sinceCutoff, serr := parsePullSince(opts.Since)
	if serr != nil {
		return nil, serr
	}

	res := &PullResult{}
	if headDec.capWarning != "" {
		res.Warnings = append(res.Warnings, headDec.capWarning)
	}
	for _, item := range admits {
		docID, _ := item["doc_id"].(string)
		if docID == "" {
			docID, _ = item["id"].(string) // maindrec list responses
		}
		body := itemBody(item)
		event, err := extractEvent(body)
		if err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{DocID: docID, Gate: ErrGateEnvelope, Detail: "could not parse event JSON: " + err.Error()})
			continue
		}
		name, _ := event["name"].(string)
		ver, _ := event["version"].(string)
		digest, _ := event["bundle_digest"].(string)

		// Gate 1: envelope_signature.
		if err := VerifyEnvelopeSignature(tr.PubKey(), event); err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateEnvelope, Detail: err.Error()})
			continue
		}
		// --since: best-effort scope narrowing on the now-AUTHENTICATED occurred_at.
		if eventOlderThan(event, sinceCutoff) {
			continue
		}
		// Gate 5: revoked? (cheapest non-cryptographic gate; check before fetching bytes)
		// FR-0090 IS-RS-01: also deny a digest the DISCOVERED accumulator missed but
		// the signed HEAD names (emergency burn list), and fail closed for EVERY
		// candidate when discovery could not be proven complete.
		if acc.IsRevoked(digest) || headDec.denies(strings.ToLower(strings.TrimSpace(digest))) || headDec.discoveryIncomplete {
			detail := "BundleRevokedEvent present for this digest"
			switch {
			case acc.IsRevoked(digest):
				// keep the default detail
			case headDec.denies(strings.ToLower(strings.TrimSpace(digest))):
				detail = "digest is on the signed revocation HEAD emergency burn list but was ABSENT from tag discovery (IS-RS-01)"
			default:
				detail = "revocation discovery could not be proven complete: failing closed (IS-RS-01): " + headDec.reason
			}
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateRevoked, Detail: detail})
			continue
		}
		// Gate 4: governance floor: N-of-M signed, fresh attestations ≥ floor from
		// DISTINCT pinned signers (default quorum 1 == a single attestation).
		qual := acc.Qualifying(digest)
		if len(qual) < tr.quorum() {
			detail := "no attestation found for this digest"
			if len(qual) == 0 && acc.HasBelowFloor(digest) {
				detail = fmt.Sprintf("attestation(s) below governance_minimum %q", tr.GovernanceMinimum)
			} else if tr.quorum() > 1 {
				detail = fmt.Sprintf("quorum not met: %d of %d distinct signers ≥ %q", len(qual), tr.quorum(), tr.GovernanceMinimum)
			}
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateGovernance, Detail: detail})
			continue
		}
		level := acc.RepresentativeLevel(digest)
		// Fetch bytes (inline base64 or claim-check). v1 only inline.
		skbBytes, err := extractSkbBytes(body)
		if err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateDigest, Detail: err.Error()})
			continue
		}
		// Gate 2: digest match.
		gotDigest := "sha256:" + hex.EncodeToString(sha256Sum(skbBytes))
		if gotDigest != digest {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateDigest, Detail: fmt.Sprintf("computed %s, item declared %s", gotDigest, digest)})
			continue
		}
		// Gate 3: bundle author + registry signatures from the event verify against trust-roots.
		if err := verifyBundleSignatures(event, tr.PubKey(), gotDigest); err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateBundleSigs, Detail: err.Error()})
			continue
		}
		// All gates passed: stage.
		dir := filepath.Join(cacheRoot, strings.TrimPrefix(digest, "sha256:"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("pull: mkdir %s: %w", dir, err)
		}
		skbPath := filepath.Join(dir, "bundle.skb")
		if err := os.WriteFile(skbPath, skbBytes, 0o644); err != nil {
			return nil, fmt.Errorf("pull: write %s: %w", skbPath, err)
		}
		authorIdentity, _ := event["admitted_by_identity"].(string)
		packedHost, _ := event["packed_on_host"].(string)
		if packedHost == "" {
			// Try the host: tag from the admit item.
			packedHost = tagValueFromItem(item, "host:")
		}
		admittedAt, _ := event["admitted_at"].(string)
		res.Staged = append(res.Staged, &StagedBundle{
			Name:           name,
			Version:        ver,
			Digest:         digest,
			Governance:     level,
			PackedOnHost:   packedHost,
			AdmittedAt:     admittedAt,
			StagedSkbPath:  skbPath,
			SourceDocID:    docID,
			AuthorIdentity: authorIdentity,
			// SPEC-0266 F2/F19: carry the SIGNED context (this admit event +
			// the signed governance attestation(s) for the same digest) so the
			// installer can stash it and the runtime gate can re-verify it.
			Attestation: attestationContextFor(event, acc, digest),
		})
	}
	return res, nil
}

// verifyBundleSignatures verifies each entry in event["signatures"] against
// the trust-roots public key. The author and registry refs both signed over
// the raw 32-byte digest (per SPEC-0188 §4.1).
func verifyBundleSignatures(event map[string]any, pub ed25519.PublicKey, recomputedDigest string) error {
	digestStr, _ := event["bundle_digest"].(string)
	if !strings.HasPrefix(digestStr, "sha256:") {
		return errors.New("bundle_digest not in sha256:<hex> form")
	}
	// SEC F4/F9: bind the signatures to the RECOMPUTED digest, not just the
	// declared one. The author/registry refs signed over the bundle's true
	// 32-byte digest; verifying over the caller's recomputed digest (and
	// asserting the event's declared digest equals it) makes this check
	// intrinsically sound rather than safe only because a separate digest-match
	// gate happened to run first, so a future reorder / new caller can't
	// silently regress to verifying over an attacker-declared digest.
	if recomputedDigest != "" && digestStr != recomputedDigest {
		return fmt.Errorf("bundle_digest %s does not match recomputed %s", digestStr, recomputedDigest)
	}
	verifyOver := digestStr
	if recomputedDigest != "" {
		verifyOver = recomputedDigest
	}
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(verifyOver, "sha256:"))
	if err != nil {
		return fmt.Errorf("bundle_digest not valid hex: %w", err)
	}
	sigsRaw, _ := event["signatures"].([]any)
	if len(sigsRaw) < 2 {
		return fmt.Errorf("expected ≥ 2 signatures, got %d", len(sigsRaw))
	}
	for i, s := range sigsRaw {
		m, ok := s.(map[string]any)
		if !ok {
			return fmt.Errorf("signatures[%d] is not an object", i)
		}
		role, _ := m["role"].(string)
		sigB64, _ := m["signature_b64"].(string)
		if sigB64 == "" {
			// Personal-tenant constructors emit empty signature_b64 in tests/
			// dry-runs; for a real verifier this is a failure.
			return fmt.Errorf("signatures[%d] (%s): empty signature_b64", i, role)
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return fmt.Errorf("signatures[%d] (%s): not valid base64: %w", i, role, err)
		}
		if !ed25519.Verify(pub, digestBytes, sig) {
			return fmt.Errorf("signatures[%d] (%s): does not verify against trust-roots key", i, role)
		}
	}
	return nil
}

// loadAttestRevoke fetches the attest + revoke items for the WHOLE registry (never
// narrowed by skill: see the discovery note below) and returns:
//   - the latest governance_level per digest (newest occurred_at wins)
//   - the set of digests that carry any (verified) BundleRevokedEvent
//
// SEC-H1: a governance verdict (attestation green/yellow/red, or a revocation)
// is only trusted if its event ENVELOPE signature verifies against the
// trust-roots public key `pub`: exactly like Gate 1 verifies the admit
// envelope. Unsigned/invalid events are skipped (fail-closed): a forged green
// attestation over a yellow bundle never reaches the governance floor, and a
// forged revocation can't suppress a legitimately-attested bundle. (Skipping
// an invalid revoke is also fail-closed: a bundle still must clear the
// governance floor on a *valid* attestation to be staged.)
// FetchRevokedDigests returns the set of bundle digests carrying a verified
// BundleRevokedEvent for the registry (SPEC-0266 F1). It is the online
// "revocation authority" the per-invocation offline gate cannot be: the
// SessionStart sweep calls this to quarantine installed skills whose bundle was
// revoked AFTER install. Each revoke event's envelope signature MUST verify
// against `pub` (a forged revoke can't be used to suppress, and, more to the
// point here, a forged revoke can't be used to quarantine a good bundle).
func FetchRevokedDigests(cfg *er1.Config, ctxID string, pub ed25519.PublicKey) (map[string]struct{}, error) {
	_, revoked, _, err := loadAttestRevoke(cfg, ctxID, pub)
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

func loadAttestRevoke(cfg *er1.Config, ctxID string, pub ed25519.PublicKey) (map[string]string, map[string]struct{}, map[string]map[string]any, error) {
	attestByDigest := map[string]string{}
	attestTS := map[string]string{}
	attestEventByDigest := map[string]map[string]any{} // SPEC-0266 F19: raw signed attestation event (latest) per digest
	revokedDigests := map[string]struct{}{}

	// FR-0090 IS-T4b: DISCOVERY must NOT be prefiltered on the attacker-controlled
	// skill-event:<kind> tag. The old per-kind loop searched
	// skill-event:{attested,revoked} only, so a signed revoke re-tagged
	// skill-event:installed (or tag-stripped) was dropped at DISCOVERY, BEFORE the
	// signed-shape classifier ever saw it: a hostile ER1 tenant could suppress a
	// revoke by retagging it. We now search only the STABLE bundle tags every
	// skill-event item carries regardless of kind (the registry/context tags) and
	// classify each item by the SIGNED envelope shape after its signature verifies.
	//
	// IS-T4b (scoped-pull residual, challenge-gate LOW): this AUTHORITATIVE revocation
	// sweep also does NOT narrow on skill:<name>. A skill: tag is equally
	// writer-controlled, so a revoke with that one tag stripped must not be able to
	// hide from a scoped pull. Correctness is preserved because every verdict is keyed
	// on the SIGNED bundle_digest (unique per bundle), so seeing OTHER skills' events
	// only ever adds their own digests; it never mis-attributes a verdict to the
	// bundle a caller is checking. The personal registry is tens-to-hundreds of events
	// (see searchByTagsRaw), so the comprehensive sweep is cheap. One search now
	// replaces the two per-kind searches.
	tags := []string{"m3c-skill-bundle", "skill-registry:self"}
	items, err := searchByTagsRaw(cfg, ctxID, tags)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, item := range items {
		body := itemBody(item)
		ev, err := extractEvent(body)
		if err != nil {
			continue
		}
		digest, _ := ev["bundle_digest"].(string)
		if digest == "" {
			continue
		}
		// SEC-H1: verify the event envelope signature before trusting its
		// governance_level / revoked status. Skip (and effectively log via
		// the dropped event) unsigned or forged verdicts.
		if err := VerifyEnvelopeSignature(pub, ev); err != nil {
			continue
		}
		// FR-0090 IS-T4/IS-T4b: classify by the SIGNED envelope SHAPE, never a
		// carrier tag. An ER1 item's tags are metadata a writer controls, so a signed
		// revoke re-tagged skill-event:attested/installed (to SUPPRESS the revoke) or
		// an attestation re-tagged skill-event:revoked (to forge a revocation) is
		// judged by what the SIGNED bytes actually are.
		switch trustcore.KindFromSignedEnvelope(ev) {
		case artifact.KindRevoke:
			revokedDigests[digest] = struct{}{}
		case artifact.KindAttest:
			level, _ := ev["governance_level"].(string)
			ts, _ := ev["occurred_at"].(string)
			if prev, ok := attestTS[digest]; !ok || ts > prev {
				attestByDigest[digest] = level
				attestTS[digest] = ts
				attestEventByDigest[digest] = ev // keep the SIGNED event for the install-time stash
			}
		default:
			// admit/install/unclassifiable → never a governance verdict here.
		}
	}
	return attestByDigest, revokedDigests, attestEventByDigest, nil
}

// loadAttestAccumulator fetches the attest + revoke events for the registry and
// feeds them into an AttestAccumulator (SPEC-0359 D3/D5): the shared N-of-M +
// freshness path used by both carriers. Mirrors loadAttestRevoke's fetch; the
// accumulator performs the SEC-H1 envelope verification against each pinned signer.
func loadAttestAccumulator(cfg *er1.Config, ctxID string, tr *SelfTrustRoots, now time.Time) (*AttestAccumulator, bool, error) {
	acc := NewAttestAccumulator(tr, now)
	// FR-0090 IS-T4b: search the STABLE bundle tags every skill-event item carries
	// (registry/context), NOT skill-event:<kind> and NOT skill:<name>, so a signed
	// revoke/attest re-tagged to another kind, tag-stripped, OR with its skill tag
	// stripped is still DISCOVERED, even on a scoped pull (challenge-gate LOW: the
	// authoritative sweep must not be narrowable by an attacker-strippable skill tag).
	// The accumulator's OfferRevoke/OfferAttest re-check the signed discriminator
	// fields (IS-T3) and key every verdict on the SIGNED bundle_digest, so seeing
	// other skills' events only adds their own digests, never mis-attributing a
	// verdict to the digest a caller is pulling. Admit/install fall through to the
	// default (never a governance verdict). One comprehensive search.
	tags := []string{"m3c-skill-bundle", "skill-registry:self"}
	items, hitCap, err := searchByTagsRawCapped(cfg, ctxID, tags)
	if err != nil {
		return nil, false, err
	}
	for _, item := range items {
		ev, err := extractEvent(itemBody(item))
		if err != nil {
			continue
		}
		switch trustcore.KindFromSignedEnvelope(ev) {
		case artifact.KindRevoke:
			acc.OfferRevoke(ev)
		case artifact.KindAttest:
			acc.OfferAttest(ev)
		default:
			// admit/install/unclassifiable → not a governance verdict.
		}
	}
	return acc, hitCap, nil
}

// ─── ER1 item body parsing ─────────────────────────────────────────────────

var (
	jsonBlockRe = regexp.MustCompile("(?s)```json\\s*\\n(.*?)\\n```")
	skbBlockRe  = regexp.MustCompile("(?s)```skb-base64\\s*\\n(.*?)\\n```")
)

// extractEvent parses the ```json fenced block out of the item body and
// returns the decoded event.
func extractEvent(body string) (map[string]any, error) {
	m := jsonBlockRe.FindStringSubmatch(body)
	if m == nil {
		return nil, errors.New("no ```json block found")
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(m[1]), &ev); err != nil {
		return nil, fmt.Errorf("decode event JSON: %w", err)
	}
	return ev, nil
}

// extractSkbBytes parses the ```skb-base64 fenced block; returns the decoded
// .skb bytes. If the block is absent, returns ErrBundleBytesMiss (claim-check
// path is P2.x future work).
func extractSkbBytes(body string) ([]byte, error) {
	m := skbBlockRe.FindStringSubmatch(body)
	if m == nil {
		return nil, ErrBundleBytesMiss
	}
	clean := strings.ReplaceAll(m[1], "\n", "")
	clean = strings.TrimSpace(clean)
	return base64.StdEncoding.DecodeString(clean)
}

// itemBody returns the markdown body of an ER1 item. ER1 stores the
// transcript_data we POSTed under a field whose exact name has varied
// over time; try the common shapes.
func itemBody(item map[string]any) string {
	for _, key := range []string{"transcript", "transcript_text", "body", "content", "text"} {
		if v, ok := item[key].(string); ok && v != "" {
			return v
		}
	}
	// Some viewers nest the body under "data" or "fields".
	if data, ok := item["data"].(map[string]any); ok {
		for _, key := range []string{"transcript", "body", "content"} {
			if v, ok := data[key].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// tagValueFromItem extracts the value of a `prefix<v>` tag from an item's
// `tags` field. Tags can be a comma-separated string or a list: try both.
func tagValueFromItem(item map[string]any, prefix string) string {
	switch tags := item["tags"].(type) {
	case string:
		for _, t := range strings.Split(tags, ",") {
			t = strings.TrimSpace(t)
			if strings.HasPrefix(t, prefix) {
				return strings.TrimPrefix(t, prefix)
			}
		}
	case []any:
		for _, x := range tags {
			if s, ok := x.(string); ok && strings.HasPrefix(s, prefix) {
				return strings.TrimPrefix(s, prefix)
			}
		}
	}
	return ""
}

// parseRowFromItem extracts an EventRow + the digest/name/version from one
// ER1 item. Returns digest=="" if the item is not a parseable bundle event.
func parseRowFromItem(item map[string]any) (EventRow, string, string, string, error) {
	body := itemBody(item)
	ev, err := extractEvent(body)
	if err != nil {
		return EventRow{}, "", "", "", err
	}
	docID, _ := item["doc_id"].(string)
	if docID == "" {
		// maindrec list responses carry the doc id under `id`, not `doc_id`.
		docID, _ = item["id"].(string)
	}
	digest, _ := ev["bundle_digest"].(string)
	name, _ := ev["name"].(string)
	version, _ := ev["version"].(string)
	// Attestation/revocation events carry only the digest in the event body:
	// recover the skill name/version from the `skill:` / `skill-version:` tags.
	if name == "" {
		name = tagValueFromItem(item, "skill:")
	}
	if version == "" {
		if sv := tagValueFromItem(item, "skill-version:"); sv != "" {
			if i := strings.Index(sv, "@"); i > 0 {
				version = sv[i+1:]
			}
		}
	}
	kind := tagValueFromItem(item, "skill-event:")
	row := EventRow{
		Kind:       kind,
		DocID:      docID,
		OccurredAt: stringOr(ev["occurred_at"], ""),
		Event:      ev,
		RawBody:    body,
	}
	switch kind {
	case EventKindAdmitted:
		row.Governance = stringOr(ev["author_intent"], "")
		row.Host = stringOr(ev["packed_on_host"], tagValueFromItem(item, "host:"))
		row.Transport = tagValueFromItem(item, "transport:")
	case EventKindAttested:
		row.Governance = stringOr(ev["governance_level"], "")
		row.Rationale = stringOr(ev["rationale"], "")
	case EventKindRevoked:
		row.Rationale = stringOr(ev["rationale"], "")
	case EventKindInstalled:
		row.Host = stringOr(ev["installed_on_host"], tagValueFromItem(item, "host:"))
	}
	return row, digest, name, version, nil
}

// latestAdmitTS returns the newest occurred_at among admit rows in `rows`.
// Used to order digests within a skill (newest admit first).
func latestAdmitTS(rows []EventRow) string {
	best := ""
	for _, r := range rows {
		if r.Kind == EventKindAdmitted && r.OccurredAt > best {
			best = r.OccurredAt
		}
	}
	return best
}

func stringOr(v any, fb string) string {
	s, _ := v.(string)
	if s == "" {
		return fb
	}
	return s
}

func sha256Sum(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

// ─── searchByTagsRaw: GET /memory/<ctx>/search?tags=… ──────────────────────

// searchByTagsRaw is the shared "give me all items with this set of tags"
// query path. Returns a list of raw item maps (whatever shape the server
// gives), callers do the field extraction.
//
// SPEC-0225 P5: prod ER1 doesn't expose a tag-filtered list endpoint that
// accepts X-API-KEY (the SPEC-0222 `/api/memory/<ctx>/search` is session-
// cookie-only). We use maindrec's dual-auth `GET /memory/<ctx>?limit=…
// &range=year` and filter client-side. The `limit` is large by design (500)
// since the personal registry is tens-to-hundreds of events, not thousands.
// Tag matching is "all of `tags` are in the item's `tags` field": same
// semantics the (non-existent) /search route would have had.
func searchByTagsRaw(cfg *er1.Config, ctxID string, tags []string) ([]map[string]any, error) {
	out, _, err := searchByTagsRawCapped(cfg, ctxID, tags)
	return out, err
}

// searchTagsLimit is the server-side page cap searchByTagsRaw requests. The
// personal registry is tens-to-hundreds of events by design, so a page that
// RETURNS exactly this many raw items is itself the anomaly signal: the list may
// be truncated (naturally, or by a flood attack that pushes a revoke off the
// page). FR-0090 IS-RS-01 uses the cap-hit as a fail-closed trigger for the
// revocation gate unless the signed HEAD independently proves the revoked set is
// complete.
const searchTagsLimit = 500

// searchByTagsRawCapped is searchByTagsRaw plus a hitCap flag: hitCap is true
// when the server returned at least searchTagsLimit RAW items (before tag
// filtering), i.e. the page may have been truncated and the caller cannot prove
// it saw every matching item.
func searchByTagsRawCapped(cfg *er1.Config, ctxID string, tags []string) (items []map[string]any, hitCap bool, err error) {
	base := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", searchTagsLimit))
	q.Set("range", "year")
	path := "/memory/" + url.PathEscape(ctxID) + "?" + q.Encode()
	v, gerr := er1Get(base, cfg, path)
	if gerr != nil {
		return nil, false, gerr
	}
	all := coerceItems(v)
	hitCap = len(all) >= searchTagsLimit
	var out []map[string]any
	for _, item := range all {
		if itemMatchesAllTags(item, tags) {
			out = append(out, item)
		}
	}
	return out, hitCap, nil
}

// itemMatchesAllTags returns true iff every tag in `want` appears in the
// item's `tags` field. The tags field can be a comma-separated string OR a
// list, both are handled. Matching is exact string equality on the tag
// token (no prefix-match, no substring-match).
func itemMatchesAllTags(item map[string]any, want []string) bool {
	have := make(map[string]struct{}, 32)
	switch tags := item["tags"].(type) {
	case string:
		for _, t := range strings.Split(tags, ",") {
			have[strings.TrimSpace(t)] = struct{}{}
		}
	case []any:
		for _, x := range tags {
			if s, ok := x.(string); ok {
				have[s] = struct{}{}
			}
		}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			return false
		}
	}
	return true
}

func defaultCacheRoot() string {
	if v := os.Getenv("M3C_SKILL_CACHE_DIR"); v != "" {
		return v
	}
	return filepath.Join(userHome(), ".cache", "m3c", "skill-bundles")
}

// unused-import dead-stores (keeps the linter quiet across partial builds).
var _ = bytes.NewBuffer
