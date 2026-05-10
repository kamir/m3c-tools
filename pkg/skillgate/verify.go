package skillgate

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"time"
)

// MaxChainDepth mirrors the Python MAX_CHAIN_DEPTH (SPEC-0202 §6 / §17 AC-6).
// Operationally locked at 5; tests can override via Verify's chain check by
// constructing tokens with longer chains and asserting the "chain_too_deep"
// reason.
const MaxChainDepth = 5

// VerifyResult is the outcome of a Verify() call. Reason strings match the
// Python verifier's stable surface so cross-language operators can correlate.
type VerifyResult struct {
	OK     bool
	Reason string // "ok" | "expired" | "bad_signature" | "malformed" | "unknown_issuer" | "envelope_grew" | "expires_extended" | "denylist_shrunk" | "destructive_added" | "chain_too_deep" | "missing_parent_link"
	Token  *Token
}

// TrustRoots maps registry_key_id → ed25519 public key (raw 32 bytes).
type TrustRoots struct {
	RegistryKeys map[string][]byte
}

// Verify checks signature, expiry, and attenuation-chain monotonicity.
//
// Steps (mirrors `verify_token` + `verify_attenuation_chain` in Python):
//  1. Parse expires_at; if now >= expires_at → expired.
//  2. Lookup roots.RegistryKeys[token.RegistryKeyID]; missing → unknown_issuer.
//  3. Re-canonicalize the token; verify ed25519 signature; bad → bad_signature.
//  4. If len(token.Attenuations) > 0, verify chain monotonicity.
func Verify(tok *Token, roots *TrustRoots) VerifyResult {
	return verifyAt(tok, roots, time.Now().UTC())
}

// verifyAt is the Verify implementation with a pluggable clock for tests.
func verifyAt(tok *Token, roots *TrustRoots, now time.Time) VerifyResult {
	if tok == nil {
		return VerifyResult{OK: false, Reason: "malformed"}
	}
	// Required-field gate matches the Python check.
	if tok.Schema == "" || tok.TokenID == "" || tok.IssuedAt == "" || tok.ExpiresAt == "" ||
		tok.BundleDigest == "" || tok.SkillName == "" || tok.SkillVersion == "" ||
		tok.CallerIdentity == "" || tok.CallerSession == "" || tok.RegistryKeyID == "" ||
		tok.SignatureB64 == "" {
		return VerifyResult{OK: false, Reason: "malformed"}
	}

	// Step 1: expiry.
	exp, err := time.Parse("2006-01-02T15:04:05Z", tok.ExpiresAt)
	if err != nil {
		return VerifyResult{OK: false, Reason: "malformed"}
	}
	if !now.Before(exp) {
		return VerifyResult{OK: false, Reason: "expired"}
	}

	// Step 2: trust-root lookup.
	if roots == nil {
		return VerifyResult{OK: false, Reason: "unknown_issuer"}
	}
	pub, ok := roots.RegistryKeys[tok.RegistryKeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return VerifyResult{OK: false, Reason: "unknown_issuer"}
	}

	// Step 3: signature.
	sig, err := base64.StdEncoding.DecodeString(tok.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return VerifyResult{OK: false, Reason: "malformed"}
	}
	msg, err := CanonicalizeToken(tok)
	if err != nil {
		return VerifyResult{OK: false, Reason: "malformed"}
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return VerifyResult{OK: false, Reason: "bad_signature"}
	}

	// Step 4: chain monotonicity.
	if len(tok.Attenuations) > 0 {
		ok, reason := verifyAttenuationChain(tok)
		if !ok {
			return VerifyResult{OK: false, Reason: reason}
		}
	}

	return VerifyResult{OK: true, Reason: "ok", Token: tok}
}

// verifyAttenuationChain mirrors the Python `verify_attenuation_chain`.
// Chain steps must be monotonically restrictive; returns a stable refusal
// reason on any growth.
func verifyAttenuationChain(t *Token) (bool, string) {
	if len(t.Attenuations) > MaxChainDepth {
		return false, "chain_too_deep"
	}
	if len(t.Attenuations) > 0 && t.ParentTokenID == "" {
		return false, "missing_parent_link"
	}

	cur := t.Envelope
	for _, a := range t.Attenuations {
		switch a.Rule {
		case "shrink_egress_allowlist":
			val, ok := stringSliceFromValue(a.Value)
			if !ok {
				return false, "envelope_grew"
			}
			if !subsetStrings(cur.EgressAllowlist, val) {
				return false, "envelope_grew"
			}

		case "shrink_subprocess_allowlist":
			val, ok := stringSliceFromValue(a.Value)
			if !ok {
				return false, "envelope_grew"
			}
			if !subsetStrings(cur.SubprocessAllowlist, val) {
				return false, "envelope_grew"
			}

		case "extend_subprocess_denylist":
			val, ok := stringSliceFromValueLoose(a.Value)
			if !ok {
				return false, "denylist_shrunk"
			}
			if !subsetStrings(val, cur.SubprocessDenylist) {
				return false, "denylist_shrunk"
			}

		case "shrink_max_runtime_seconds":
			n, ok := intFromValue(a.Value)
			if !ok {
				return false, "envelope_grew"
			}
			if cur.MaxRuntimeSeconds > n {
				return false, "envelope_grew"
			}

		case "shrink_max_egress_bytes":
			n, ok := int64FromValue(a.Value)
			if !ok {
				return false, "envelope_grew"
			}
			if cur.MaxEgressBytes > n {
				return false, "envelope_grew"
			}

		case "shrink_max_invocations":
			n, ok := intFromValue(a.Value)
			if !ok {
				return false, "envelope_grew"
			}
			if cur.MaxInvocations > n {
				return false, "envelope_grew"
			}

		case "shrink_expires_at":
			s, ok := stringFromValue(a.Value)
			if !ok {
				return false, "expires_extended"
			}
			ruleExp, err1 := time.Parse("2006-01-02T15:04:05Z", s)
			curExp, err2 := time.Parse("2006-01-02T15:04:05Z", t.ExpiresAt)
			if err1 != nil || err2 != nil {
				return false, "expires_extended"
			}
			if curExp.After(ruleExp) {
				return false, "expires_extended"
			}

		case "force_destructive_false":
			if cur.Destructive {
				return false, "destructive_added"
			}

		case "drop_capability":
			dropped, _ := stringSliceFromValueLoose(a.Value)
			for _, d := range dropped {
				for _, c := range cur.Capabilities {
					if c == d {
						return false, "envelope_grew"
					}
				}
			}

		default:
			// Forward-compat: unknown rules don't fail the chain.
		}
	}
	return true, "ok"
}

// ---------------------------------------------------------------------------
// helpers — extract typed values out of a generic Attenuation.Value map.
// The wire shape uses the "_value" sentinel key for non-dict rule values
// (see canonical.go); we mirror that here for verification.
// ---------------------------------------------------------------------------

func stringSliceFromValue(v map[string]any) ([]string, bool) {
	raw, ok := v["_value"]
	if !ok {
		return nil, false
	}
	sl, ok := raw.([]any)
	if !ok {
		// Allow []string directly too.
		if ss, isSS := raw.([]string); isSS {
			return ss, true
		}
		return nil, false
	}
	out := make([]string, 0, len(sl))
	for _, item := range sl {
		s, isStr := item.(string)
		if !isStr {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// stringSliceFromValueLoose accepts a single string OR a []any/[]string.
func stringSliceFromValueLoose(v map[string]any) ([]string, bool) {
	raw, ok := v["_value"]
	if !ok {
		return nil, false
	}
	if s, isStr := raw.(string); isStr {
		return []string{s}, true
	}
	if sl, isSlice := raw.([]any); isSlice {
		out := make([]string, 0, len(sl))
		for _, item := range sl {
			s, isStr := item.(string)
			if !isStr {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	if ss, isSS := raw.([]string); isSS {
		return ss, true
	}
	return nil, false
}

func intFromValue(v map[string]any) (int, bool) {
	raw, ok := v["_value"]
	if !ok {
		return 0, false
	}
	switch n := raw.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i, true
		}
	}
	return 0, false
}

func int64FromValue(v map[string]any) (int64, bool) {
	raw, ok := v["_value"]
	if !ok {
		return 0, false
	}
	switch n := raw.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case string:
		if i, err := strconv.ParseInt(n, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

func stringFromValue(v map[string]any) (string, bool) {
	raw, ok := v["_value"]
	if !ok {
		return "", false
	}
	s, isStr := raw.(string)
	return s, isStr
}

// subsetStrings returns true iff every element of `sub` is in `super`.
func subsetStrings(sub, super []string) bool {
	set := make(map[string]struct{}, len(super))
	for _, s := range super {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
