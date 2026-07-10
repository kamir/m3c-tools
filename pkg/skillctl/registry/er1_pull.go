package registry

// ER1 pull + registry-view path for the `self` tenant (SPEC-0225 P2).
//
// Three exported entry points:
//
//   ListRegistry  — query ER1, build a per-skill registry view (admit history
//                   + attestations + installs + revocations), dedupe by digest.
//                   Implements `skillctl registry ls [--latest]`.
//
//   ShowSkill     — return the full timeline for one skill (all events,
//                   sorted by occurred_at). Implements `registry show <name>`.
//
//   PullBundles   — for each `admitted` event matching the query, run the
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

	"github.com/kamir/m3c-tools/pkg/er1"
)

// ─── Errors ────────────────────────────────────────────────────────────────

// Gate-failure sentinels — `pull` reports the specific gate that rejected
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
	Since      string // RFC3339 lower bound (matched against occurred_at) — optional
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
	OnlySkill  string // empty → all skills
	OnlyDigest string // empty → all admit items in scope
	Since      string // RFC3339; pass to the search query (best-effort filter)
}

// PullResult reports the outcome of a pull.
type PullResult struct {
	Staged  []*StagedBundle
	Skipped []*PullSkip // bundles rejected by one of the 5 gates
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
	// — mirroring Gate 1's admit-envelope verification (~:297). An unsigned or
	// forged governance verdict is otherwise free to forge.
	attestByDigest, revokedDigests, attestEventByDigest, err := loadAttestRevoke(cfg, ctxID, opts.OnlySkill, tr.PubKey())
	if err != nil {
		return nil, err
	}

	cacheRoot := defaultCacheRoot()
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		return nil, fmt.Errorf("pull: mkdir cache: %w", err)
	}

	res := &PullResult{}
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
		// Gate 5: revoked? (cheapest non-cryptographic gate; check before fetching bytes)
		if _, isRevoked := revokedDigests[digest]; isRevoked {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateRevoked, Detail: "BundleRevokedEvent present for this digest"})
			continue
		}
		// Gate 4: governance floor.
		level, hasAttest := attestByDigest[digest]
		if !hasAttest || !tr.MeetsFloor(level) {
			detail := "no attestation found for this digest"
			if hasAttest {
				detail = fmt.Sprintf("latest attestation %q < governance_minimum %q", level, tr.GovernanceMinimum)
			}
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, DocID: docID, Gate: ErrGateGovernance, Detail: detail})
			continue
		}
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
		// All gates passed — stage.
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
			// the signed governance attestation for the same digest) so the
			// installer can stash it and the runtime gate can re-verify it.
			Attestation: &AttestationContext{
				AdmitEvent:            event,
				GovernanceAttestation: attestEventByDigest[digest],
			},
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
	// gate happened to run first — so a future reorder / new caller can't
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

// loadAttestRevoke fetches the attest + revoke items for the registry (optionally
// scoped to one skill) and returns:
//   - the latest governance_level per digest (newest occurred_at wins)
//   - the set of digests that carry any (verified) BundleRevokedEvent
//
// SEC-H1: a governance verdict (attestation green/yellow/red, or a revocation)
// is only trusted if its event ENVELOPE signature verifies against the
// trust-roots public key `pub` — exactly like Gate 1 verifies the admit
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
// against `pub` (a forged revoke can't be used to suppress, and — more to the
// point here — a forged revoke can't be used to quarantine a good bundle).
func FetchRevokedDigests(cfg *er1.Config, ctxID string, pub ed25519.PublicKey) (map[string]struct{}, error) {
	_, revoked, _, err := loadAttestRevoke(cfg, ctxID, "", pub)
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

func loadAttestRevoke(cfg *er1.Config, ctxID, onlySkill string, pub ed25519.PublicKey) (map[string]string, map[string]struct{}, map[string]map[string]any, error) {
	attestByDigest := map[string]string{}
	attestTS := map[string]string{}
	attestEventByDigest := map[string]map[string]any{} // SPEC-0266 F19: raw signed attestation event (latest) per digest
	revokedDigests := map[string]struct{}{}

	for _, kind := range []string{EventKindAttested, EventKindRevoked} {
		tags := []string{"m3c-skill-bundle", "skill-registry:self", "skill-event:" + kind}
		if onlySkill != "" {
			tags = append(tags, "skill:"+onlySkill)
		}
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
			if kind == EventKindRevoked {
				revokedDigests[digest] = struct{}{}
				continue
			}
			level, _ := ev["governance_level"].(string)
			ts, _ := ev["occurred_at"].(string)
			if prev, ok := attestTS[digest]; !ok || ts > prev {
				attestByDigest[digest] = level
				attestTS[digest] = ts
				attestEventByDigest[digest] = ev // keep the SIGNED event for the install-time stash
			}
		}
	}
	return attestByDigest, revokedDigests, attestEventByDigest, nil
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
// `tags` field. Tags can be a comma-separated string or a list — try both.
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
	// Attestation/revocation events carry only the digest in the event body —
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
// gives) — callers do the field extraction.
//
// SPEC-0225 P5: prod ER1 doesn't expose a tag-filtered list endpoint that
// accepts X-API-KEY (the SPEC-0222 `/api/memory/<ctx>/search` is session-
// cookie-only). We use maindrec's dual-auth `GET /memory/<ctx>?limit=…
// &range=year` and filter client-side. The `limit` is large by design (500)
// since the personal registry is tens-to-hundreds of events, not thousands.
// Tag matching is "all of `tags` are in the item's `tags` field" — same
// semantics the (non-existent) /search route would have had.
func searchByTagsRaw(cfg *er1.Config, ctxID string, tags []string) ([]map[string]any, error) {
	base := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	q := url.Values{}
	q.Set("limit", "500")
	q.Set("range", "year")
	path := "/memory/" + url.PathEscape(ctxID) + "?" + q.Encode()
	v, err := er1Get(base, cfg, path)
	if err != nil {
		return nil, err
	}
	all := coerceItems(v)
	var out []map[string]any
	for _, item := range all {
		if itemMatchesAllTags(item, tags) {
			out = append(out, item)
		}
	}
	return out, nil
}

// itemMatchesAllTags returns true iff every tag in `want` appears in the
// item's `tags` field. The tags field can be a comma-separated string OR a
// list — both are handled. Matching is exact string equality on the tag
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
