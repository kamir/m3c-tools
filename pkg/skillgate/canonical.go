package skillgate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CanonicalDomainSeparator is the first line of the canonical message —
// distinct from the SPEC-0188 attestation domain so a captured attestation
// signature can never replay as a capability-token signature.
const CanonicalDomainSeparator = "capability_v1"

// canonicalCSV sorts the input by Unicode code point and joins with ',' .
// Empty / nil → empty string. This mirrors the Python `_csv_sorted` helper
// (Python's `sorted()` default is also Unicode code-point order on str).
func canonicalCSV(items []string) string {
	if len(items) == 0 {
		return ""
	}
	cp := make([]string, len(items))
	copy(cp, items)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// canonicalAttenuationValue returns the JSON encoding of an attenuation
// `value` map matching Python's
//
//	json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
//
// Go's encoding/json marshals map[string]any with keys sorted lexicographically
// (json.Marshal alphabetizes map keys since Go 1.12). The default separators
// are exactly ',' and ':' with no spaces. The default escapes some HTML chars
// (<, >, &) which Python does NOT escape with ensure_ascii=False, so we use
// an Encoder with SetEscapeHTML(false).
//
// Set-semantics rules ("shrink_egress_allowlist", "shrink_subprocess_allowlist")
// require sorting the slice value before marshaling — mirrors the Python
// behavior at canonicalize time.
func canonicalAttenuationValue(rule string, value map[string]any) (string, error) {
	// Python stores `value` as the raw rule value (str/list/int/bool/dict/null),
	// not a wrapper map. The Go type holds map[string]any; callers using
	// flat values should put them under a sentinel key OR pass the value
	// directly. To keep byte-parity we accept either: if `value` has a single
	// key "_" we emit the inner; otherwise we emit the map.
	//
	// In practice the Python issuer puts the rule value in directly (e.g.
	// `value=["a", "b"]` for shrink_egress_allowlist). The Go-side caller
	// constructs Attenuation.Value as a map with a "_value" key for non-dict
	// rule values; the map case (full envelope deltas) is emitted as-is.
	if v, ok := value["_value"]; ok {
		// Set-semantics rules sort the slice value at canonical time.
		if (rule == "shrink_egress_allowlist" || rule == "shrink_subprocess_allowlist") && v != nil {
			if sl, ok := v.([]any); ok {
				strs := make([]string, 0, len(sl))
				ok := true
				for _, item := range sl {
					if s, isStr := item.(string); isStr {
						strs = append(strs, s)
					} else {
						ok = false
						break
					}
				}
				if ok {
					sort.Strings(strs)
					return marshalCanonical(strs)
				}
			}
		}
		return marshalCanonical(v)
	}
	// Full envelope-shape map.
	return marshalCanonical(value)
}

// marshalCanonical wraps json.Encoder with HTML escaping disabled so the
// output exactly matches Python's `json.dumps(..., ensure_ascii=False)`
// for the same input value (modulo the always-sorted-keys rule, which Go
// already enforces for map[string]any).
func marshalCanonical(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	// json.Encoder.Encode appends a trailing '\n' which is NOT in
	// Python's json.dumps output. Strip it.
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return string(out), nil
}

// CanonicalizeToken produces the byte-identical signature payload as the
// Python `_canonicalize_token_message`. SPEC-0202 §4.1, §6 (attenuation chain
// suffix). Every line is terminated with LF, including the last.
//
// Field order — line by line — MUST match Python verbatim:
//
//	capability_v1
//	schema=...
//	token_id=...
//	issued_at=...
//	expires_at=...
//	bundle_digest=...
//	skill_name=...
//	skill_version=...
//	tenant_scope=<id-or-empty>
//	caller_identity=...
//	caller_session=...
//	envelope_capabilities=<sorted csv>
//	envelope_egress_allowlist=<sorted csv>
//	envelope_subprocess_allowlist=<sorted csv>
//	envelope_subprocess_denylist=<sorted csv>
//	envelope_destructive=true|false
//	envelope_max_invocations=<int>
//	envelope_max_runtime_seconds=<int>
//	envelope_max_egress_bytes=<int>
//	registry_key_id=...
//	parent_token_id=<ct:...-or-empty>
//	attenuation_count=<int>
//	# for each attenuation in chain order (i in [0, count)):
//	attenuation[i].applied_at=...
//	attenuation[i].applied_by=...
//	attenuation[i].rule=...
//	attenuation[i].value=<json with sort_keys, no spaces, ensure_ascii=False>
//	attenuation[i].rationale=<utf8-or-empty>
func CanonicalizeToken(t *Token) ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("skillgate: nil token")
	}
	var b strings.Builder
	// Top-level fields in fixed order.
	w := func(line string) { b.WriteString(line); b.WriteByte('\n') }

	w(CanonicalDomainSeparator)
	w("schema=" + t.Schema)
	w("token_id=" + t.TokenID)
	w("issued_at=" + t.IssuedAt)
	w("expires_at=" + t.ExpiresAt)
	w("bundle_digest=" + t.BundleDigest)
	w("skill_name=" + t.SkillName)
	w("skill_version=" + t.SkillVersion)
	w("tenant_scope=" + t.TenantScope) // empty string when absent — matches Python's None→""
	w("caller_identity=" + t.CallerIdentity)
	w("caller_session=" + t.CallerSession)
	w("envelope_capabilities=" + canonicalCSV(t.Envelope.Capabilities))
	w("envelope_egress_allowlist=" + canonicalCSV(t.Envelope.EgressAllowlist))
	w("envelope_subprocess_allowlist=" + canonicalCSV(t.Envelope.SubprocessAllowlist))
	w("envelope_subprocess_denylist=" + canonicalCSV(t.Envelope.SubprocessDenylist))
	if t.Envelope.Destructive {
		w("envelope_destructive=true")
	} else {
		w("envelope_destructive=false")
	}
	w(fmt.Sprintf("envelope_max_invocations=%d", t.Envelope.MaxInvocations))
	w(fmt.Sprintf("envelope_max_runtime_seconds=%d", t.Envelope.MaxRuntimeSeconds))
	w(fmt.Sprintf("envelope_max_egress_bytes=%d", t.Envelope.MaxEgressBytes))
	w("registry_key_id=" + t.RegistryKeyID)
	w("parent_token_id=" + t.ParentTokenID)

	// Attenuation chain suffix.
	w(fmt.Sprintf("attenuation_count=%d", len(t.Attenuations)))
	for i, a := range t.Attenuations {
		valStr, err := canonicalAttenuationValue(a.Rule, a.Value)
		if err != nil {
			return nil, fmt.Errorf("attenuation[%d].value: %w", i, err)
		}
		w(fmt.Sprintf("attenuation[%d].applied_at=%s", i, a.AppliedAt))
		w(fmt.Sprintf("attenuation[%d].applied_by=%s", i, a.AppliedBy))
		w(fmt.Sprintf("attenuation[%d].rule=%s", i, a.Rule))
		w(fmt.Sprintf("attenuation[%d].value=%s", i, valStr))
		w(fmt.Sprintf("attenuation[%d].rationale=%s", i, a.Rationale))
	}

	return []byte(b.String()), nil
}
