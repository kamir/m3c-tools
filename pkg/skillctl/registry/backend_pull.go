package registry

// SPEC-0356: the verifying pull over an artifact.Backend (git / gitlab / github).
//
// This is PullBundles with two sources swapped: the signed SPEC-0190 event
// envelopes come from the backend's GovernanceLog (the committed events/ tree)
// instead of ER1 tag queries, and the .skb bytes come from Backend.Fetch instead
// of the inline base64 body. EVERY §7 gate and the staging are identical to
// PullBundles and use the SAME primitives (VerifyEnvelopeSignature,
// verifyBundleSignatures, MeetsFloor, the revoked set, SEC-H1 verify-before-trust)
// — this file lives in package registry precisely so it can call the unexported
// verifyBundleSignatures. Verified bundles land in the same cache layout, so
// PlanInstall / ConfirmInstall are reused unchanged.

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// parsePullSince turns the --since flag into a lower bound on occurred_at.
// Accepts RFC3339, a date (YYYY-MM-DD), or a Go duration ("168h" => now-168h).
// Empty => zero time (no bound). Shared by PullBundles (ER1) and
// PullBundlesFromBackend (git) so --since behaves identically on both carriers.
func parsePullSince(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			// A negative duration would invert --since into a FUTURE lower bound
			// (now-(-d)), silently excluding everything. Reject it instead.
			return time.Time{}, fmt.Errorf("bad --since %q (duration must be non-negative, e.g. 168h)", s)
		}
		return time.Now().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("bad --since %q (want RFC3339, YYYY-MM-DD, or a duration like 168h)", s)
}

// eventOlderThan reports whether a signed event's occurred_at is strictly before
// cutoff. An absent/unparseable timestamp is treated as NOT older (kept): --since
// is a best-effort scope narrowing, never a security gate. Callers apply it only
// AFTER the envelope signature verifies, so the timestamp is authenticated.
func eventOlderThan(ev map[string]any, cutoff time.Time) bool {
	if cutoff.IsZero() {
		return false
	}
	ts, _ := ev["occurred_at"].(string)
	if ts == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	return t.Before(cutoff)
}

// PullBundlesFromBackend runs the SPEC-0188 §7 gauntlet over be and stages the
// bundles that pass. The governance floor requires a SIGNED AttestationPublished
// event at/above tr.GovernanceMinimum for each digest — the admit event's
// author_intent is never sufficient (identical to PullBundles / the ER1 self
// tenant). A backend with no GovernanceLog cannot be verified and is rejected.
func PullBundlesFromBackend(ctx context.Context, be artifact.Backend, tr *SelfTrustRoots, opts PullOpts) (*PullResult, error) {
	if tr == nil {
		return nil, ErrTrustRootsMissing
	}
	gl, ok := be.(artifact.GovernanceLog)
	if !ok {
		return nil, fmt.Errorf("pull: backend %q exposes no signed events (no GovernanceLog) — cannot verify", be.Describe().Scheme)
	}

	// Read every signed event envelope for the target skill(s).
	page, err := gl.Events(ctx, artifact.ListFilter{Name: opts.OnlySkill}, artifact.Page{})
	if err != nil {
		return nil, fmt.Errorf("pull: read events: %w", err)
	}

	pub := tr.PubKey()

	// Governance/revocation side-index + admit set — mirrors loadAttestRevoke,
	// including SEC-H1: verify the envelope of EVERY attest/revoke event before
	// trusting its governance_level / revoked status.
	attestByDigest := map[string]string{}
	attestTS := map[string]string{}
	attestEventByDigest := map[string]map[string]any{}
	revokedDigests := map[string]struct{}{}
	var admits []map[string]any

	for _, rec := range page.Events {
		ev := rec.Envelope
		if ev == nil {
			continue
		}
		switch rec.Kind {
		case artifact.KindAdmit:
			admits = append(admits, ev)
		case artifact.KindRevoke:
			if err := VerifyEnvelopeSignature(pub, ev); err != nil {
				continue // SEC-H1: unsigned/forged revoke does not count
			}
			if d, _ := ev["bundle_digest"].(string); d != "" {
				revokedDigests[d] = struct{}{}
			}
		case artifact.KindAttest:
			if err := VerifyEnvelopeSignature(pub, ev); err != nil {
				continue // SEC-H1: unsigned/forged verdict does not count
			}
			d, _ := ev["bundle_digest"].(string)
			if d == "" {
				continue
			}
			level, _ := ev["governance_level"].(string)
			ts, _ := ev["occurred_at"].(string)
			if prev, ok := attestTS[d]; !ok || ts > prev { // keep the latest attestation
				attestByDigest[d] = level
				attestTS[d] = ts
				attestEventByDigest[d] = ev
			}
		}
	}

	cacheRoot := defaultCacheRoot()
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		return nil, fmt.Errorf("pull: mkdir cache: %w", err)
	}

	sinceCutoff, serr := parsePullSince(opts.Since)
	if serr != nil {
		return nil, serr
	}

	res := &PullResult{}
	for _, event := range admits {
		name, _ := event["name"].(string)
		ver, _ := event["version"].(string)
		digest, _ := event["bundle_digest"].(string)
		if opts.OnlyDigest != "" && digest != opts.OnlyDigest {
			continue
		}

		// Gate 1: envelope_signature (admit).
		if err := VerifyEnvelopeSignature(pub, event); err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateEnvelope, Detail: err.Error()})
			continue
		}
		// --since: best-effort scope narrowing on the now-AUTHENTICATED occurred_at.
		if eventOlderThan(event, sinceCutoff) {
			continue
		}
		// Gate 5: revoked?
		if _, isRevoked := revokedDigests[digest]; isRevoked {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateRevoked, Detail: "BundleRevokedEvent present for this digest"})
			continue
		}
		// Gate 4: governance floor — a signed attestation ≥ floor is mandatory.
		level, hasAttest := attestByDigest[digest]
		if !hasAttest || !tr.MeetsFloor(level) {
			detail := "no signed attestation found for this digest"
			if hasAttest {
				detail = fmt.Sprintf("latest attestation %q < governance_minimum %q", level, tr.GovernanceMinimum)
			}
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateGovernance, Detail: detail})
			continue
		}
		// Fetch the bytes from the backend (untrusted-but-available).
		skbBytes, err := be.Fetch(ctx, artifact.ArtifactRef{Name: name, Version: ver, Digest: digest})
		if err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateDigest, Detail: err.Error()})
			continue
		}
		// Gate 2: digest match (recompute — never trust the backend).
		gotDigest := "sha256:" + hex.EncodeToString(sha256Sum(skbBytes))
		if gotDigest != digest {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateDigest, Detail: fmt.Sprintf("computed %s, event declared %s", gotDigest, digest)})
			continue
		}
		// Gate 3: bundle author + registry signatures over the recomputed digest.
		if err := verifyBundleSignatures(event, pub, gotDigest); err != nil {
			res.Skipped = append(res.Skipped, &PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateBundleSigs, Detail: err.Error()})
			continue
		}

		// All gates passed — stage to the SAME cache layout PullBundles uses.
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
		admittedAt, _ := event["admitted_at"].(string)
		res.Staged = append(res.Staged, &StagedBundle{
			Name:           name,
			Version:        ver,
			Digest:         digest,
			Governance:     level,
			PackedOnHost:   packedHost,
			AdmittedAt:     admittedAt,
			StagedSkbPath:  skbPath,
			SourceDocID:    be.Describe().Scheme + ":" + name + "/v" + ver, // git ref-ish provenance
			AuthorIdentity: authorIdentity,
			// Carry the SIGNED context so the installer can stash it and the
			// runtime gate (SPEC-0247) can re-verify offline.
			Attestation: &AttestationContext{
				AdmitEvent:            event,
				GovernanceAttestation: attestEventByDigest[digest],
			},
		})
	}
	return res, nil
}
