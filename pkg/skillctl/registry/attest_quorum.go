package registry

// SPEC-0359 D3(ii) N-of-M co-attestation + D5(a) attestation freshness.
//
// AttestAccumulator is the SINGLE place both gauntlets (er1_pull.go via
// loadAttestRevoke, backend_pull.go inline) collect attestations, so the two
// carriers cannot drift. It:
//   - verifies each attest envelope against each PINNED signer key (SEC-H1);
//   - dedups per DISTINCT verifying key (newest occurred_at wins within a signer)
//     — distinctness is anchored to the KEY, never the reviewer_id string, so one
//     key cannot mint a quorum;
//   - binds reviewer_id to the signer it is pinned to (mismatch dropped, fail-closed);
//   - drops an EXPIRED attestation (D5) before it can occupy a signer slot;
//   - answers the N-of-M governance floor (`Qualifying`).
//
// k=1 IDENTITY: with GovernanceQuorum defaulting to 1 and an empty Signers set
// (one implicit signer {"", tr.pub} matching any reviewer_id) and no expires_at,
// OfferAttest admits exactly the attestations that verify against tr.pub, dedups
// to ONE via newest-occurred_at-wins (== the old attestTS), and Qualifying returns
// 0 or 1 — reproducing `hasAttest && MeetsFloor(level)` byte-for-byte. ed25519
// verification (VerifyEnvelopeSignature) is untouched.

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"
)

// Signer is one pinned governance reviewer key (D3). The key is what counts
// toward a quorum; ReviewerID binds the attestation's reviewer_id to this key.
type Signer struct {
	ReviewerID string `yaml:"reviewer_id"`
	PubKeyB64  string `yaml:"pubkey_b64"`
	pub        ed25519.PublicKey
}

// attRec is one accepted attestation for a digest from a distinct signer.
type attRec struct {
	level      string
	occurredAt string
	event      map[string]any
}

// AttestAccumulator collects verified, fresh attestations per digest keyed by the
// distinct verifying signer key, plus the revoked-digest set.
type AttestAccumulator struct {
	tr       *SelfTrustRoots
	now      time.Time
	signers  []Signer
	byDigest map[string]map[string]attRec // digest -> signerKeyID -> the signer's NEWEST attestation
	revoked  map[string]struct{}
}

// NewAttestAccumulator binds the accumulator to the trust roots + a fixed clock
// (injected so freshness is deterministic in tests).
func NewAttestAccumulator(tr *SelfTrustRoots, now time.Time) *AttestAccumulator {
	if now.IsZero() {
		now = time.Now()
	}
	return &AttestAccumulator{
		tr: tr, now: now, signers: tr.signerSet(),
		byDigest: map[string]map[string]attRec{},
		revoked:  map[string]struct{}{},
	}
}

func signerKeyID(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }

// attestationExpired reports whether a signed attestation's expires_at has
// lapsed. Absent expires_at → never (opt-in; legacy attestations unchanged).
// Unparseable or now >= expiry → expired (fail-safe), mirroring the freshness
// discipline in verify/freshness.go.
func attestationExpired(ev map[string]any, now time.Time) bool {
	raw, _ := ev["expires_at"].(string)
	if raw == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return true
	}
	return !now.Before(exp)
}

// OfferAttest ingests one KindAttest envelope. It is verified against each pinned
// signer key; on the first key it verifies against (with reviewer_id binding), it
// is recorded under that signer (newest occurred_at wins). Expired attestations
// are dropped before they can occupy a slot.
func (a *AttestAccumulator) OfferAttest(ev map[string]any) {
	digest, _ := ev["bundle_digest"].(string)
	if digest == "" {
		return
	}
	for _, s := range a.signers {
		if VerifyEnvelopeSignature(s.pub, ev) != nil {
			continue // not this signer's key
		}
		if s.ReviewerID != "" {
			if rid, _ := ev["reviewer_id"].(string); rid != s.ReviewerID {
				continue // key/id binding mismatch → fail closed, do not count
			}
		}
		level, _ := ev["governance_level"].(string)
		ts, _ := ev["occurred_at"].(string)
		key := signerKeyID(s.pub)
		if a.byDigest[digest] == nil {
			a.byDigest[digest] = map[string]attRec{}
		}
		// Record the signer's NEWEST-occurred_at attestation REGARDLESS of expiry —
		// the reviewer's LATEST word governs. Qualifying then denies a slot whose
		// newest is expired, so an expiry cannot be shadowed by an older
		// non-expiring sibling (challenge-gate fix; invariant "never fall back").
		if prev, ok := a.byDigest[digest][key]; !ok || ts > prev.occurredAt {
			a.byDigest[digest][key] = attRec{level: level, occurredAt: ts, event: ev}
		}
		return // an attestation is signed by exactly one key → one signer slot
	}
}

// OfferRevoke ingests one KindRevoke envelope; a revoke that verifies against any
// pinned signer key marks the digest revoked (SEC-H1). For the single-key default
// this verifies against tr.pub exactly as today.
func (a *AttestAccumulator) OfferRevoke(ev map[string]any) {
	digest, _ := ev["bundle_digest"].(string)
	if digest == "" {
		return
	}
	for _, s := range a.signers {
		if VerifyEnvelopeSignature(s.pub, ev) == nil {
			a.revoked[digest] = struct{}{}
			return
		}
	}
}

// Qualifying returns the accepted attestations from DISTINCT signers whose NEWEST
// attestation is BOTH unexpired AND meets the floor. A signer whose newest word
// has expired is denied even if an older non-expiring sibling exists (invariant:
// never fall back to an older green). len >= tr.quorum() ⇒ the governance gate passes.
func (a *AttestAccumulator) Qualifying(digest string) []attRec {
	var out []attRec
	for _, rec := range a.byDigest[digest] {
		if attestationExpired(rec.event, a.now) {
			continue // the signer's latest word has lapsed → slot denied
		}
		if a.tr.MeetsFloor(rec.level) {
			out = append(out, rec)
		}
	}
	return out
}

// IsRevoked reports whether a verified revoke exists for the digest.
func (a *AttestAccumulator) IsRevoked(digest string) bool {
	_, ok := a.revoked[digest]
	return ok
}

// HasBelowFloor reports whether a signer's newest (unexpired) attestation was seen
// that did not meet the floor (for a precise gate-4 message).
func (a *AttestAccumulator) HasBelowFloor(digest string) bool {
	for _, rec := range a.byDigest[digest] {
		if !attestationExpired(rec.event, a.now) && !a.tr.MeetsFloor(rec.level) {
			return true
		}
	}
	return false
}

// RepresentativeLevel returns the newest qualifying level for the digest (for
// StagedBundle.Governance). Empty when nothing qualifies.
func (a *AttestAccumulator) RepresentativeLevel(digest string) string {
	best := ""
	bestTS := ""
	for _, rec := range a.Qualifying(digest) {
		if rec.occurredAt >= bestTS {
			bestTS, best = rec.occurredAt, rec.level
		}
	}
	return best
}

// EventsFor returns the qualifying signed attestation events for the digest (for
// the plural runtime stash). The newest-per-signer envelope, floor-passing only.
func (a *AttestAccumulator) EventsFor(digest string) []map[string]any {
	var out []map[string]any
	for _, rec := range a.Qualifying(digest) {
		out = append(out, rec.event)
	}
	return out
}

// RepresentativeEvent returns one qualifying attestation event (the newest), for
// the legacy singular stash field. nil when nothing qualifies.
func (a *AttestAccumulator) RepresentativeEvent(digest string) map[string]any {
	var best map[string]any
	bestTS := ""
	for _, rec := range a.Qualifying(digest) {
		if rec.occurredAt >= bestTS {
			bestTS, best = rec.occurredAt, rec.event
		}
	}
	return best
}

// attestationContextFor builds the stashed AttestationContext for a staged bundle:
// the admit event + the representative qualifying attestation (singular, legacy /
// k=1 path) plus the full qualifying set ONLY when a quorum of >1 qualified — so a
// single-attestation stash stays byte-identical (the plural field is omitempty).
func attestationContextFor(admit map[string]any, acc *AttestAccumulator, digest string) *AttestationContext {
	ctx := &AttestationContext{
		AdmitEvent:            admit,
		GovernanceAttestation: acc.RepresentativeEvent(digest),
	}
	if evs := acc.EventsFor(digest); len(evs) > 1 {
		ctx.GovernanceAttestations = evs
	}
	return ctx
}
