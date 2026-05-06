// Envelope construction for SPEC-0195 §5.1.
//
// Inputs: a model.Inventory + signing identity material.
// Outputs: a SyncEnvelope ready to JSON-encode + a list of locally-skipped
// skills (for the --require-intent gate).
//
// All wire-level field naming lives in awareness.go (struct tags). This
// file is the I/O-free transformation that turns a scanner record into
// a SkillEntry; tests pin the exact shape so a SPEC-0195 wire change
// must edit both the struct tags AND the corresponding test fixture.

package awareness

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// IntentSentinelUNKNOWN is the SPEC-0196 §7 marker used by the legacy
// awareness backfill: a bundle whose intent was filled in by tooling
// (rather than declared by the author) carries `side_effects: ["UNKNOWN"]`.
//
// The --require-intent gate refuses to send envelopes carrying this
// sentinel; the --default-intent flag stamps a real governance level over
// it. Both behaviours live in BuildEnvelope.
const IntentSentinelUNKNOWN = "UNKNOWN"

// BuildEnvelope is the pure transformation: model.Inventory in,
// SyncEnvelope + locally-skipped rows out. No I/O.
//
// The function is exported so the SPEC-0189 §13 `--push-to-registry`
// shorthand can build the same envelope from the same inputs without
// going through Sync(). Acceptance criterion #6 checks that
// `awareness sync --source claude --dry-run` and
// `scan --push-to-registry --dry-run-push` produce the byte-identical
// envelope.
func BuildEnvelope(opts Opts) (SyncEnvelope, []SkippedRow, error) {
	if opts.Inventory == nil {
		return SyncEnvelope{}, nil, fmt.Errorf("awareness: Inventory is required")
	}
	if opts.AuthorSigner == nil {
		return SyncEnvelope{}, nil, fmt.Errorf("awareness: AuthorSigner is required")
	}

	env := SyncEnvelope{
		SessionTag:              opts.SessionTag,
		ClientIdentity:          opts.AuthorIdentity,
		ClientPubkeyFingerprint: opts.AuthorPubkeyFingerprint,
		EnvelopeVersion:         EnvelopeVersion,
		Skills:                  make([]SkillEntry, 0, len(opts.Inventory.Skills)),
	}

	var localSkipped []SkippedRow

	for _, sk := range opts.Inventory.Skills {
		// SkillEntry only ships when we have a content hash — the
		// server's `local_digest` derivation depends on it, and a
		// bundle with no hash is malformed enough to refuse on the
		// client side. Mirror the Python reference's "if not
		// content_hash: continue" behaviour.
		if sk.ContentHash == "" {
			localSkipped = append(localSkipped, SkippedRow{
				Name:   sk.Name,
				Reason: "missing_content_hash",
			})
			continue
		}

		entry := buildSkillEntry(sk)

		// Apply --default-intent gap-fill BEFORE --require-intent so the
		// gap-fill counts as "satisfying intent" for the gate's purposes.
		if opts.DefaultIntentLevel != "" {
			entry = stampDefaultIntent(entry, opts.DefaultIntentLevel)
		}

		// --require-intent: refuse to send entries that lack a
		// declared, non-sentinel intent. Mirrors the SPEC-0196 §7
		// "UNKNOWN sentinel" semantics. Acceptance test #5 in
		// the cmd-level test suite asserts this fires.
		if opts.RequireIntent {
			if reason, ok := failsRequireIntent(entry); ok {
				localSkipped = append(localSkipped, SkippedRow{
					Name:       sk.Name,
					Reason:     "intent_required_local_gate",
					FailedRule: reason,
				})
				continue
			}
		}

		// Sign the local_digest message: ASCII bytes of "sha256:<hex>".
		// The server validates this signature against the
		// client_pubkey_fingerprint we send in the envelope header.
		localDigest := "sha256:" + sk.ContentHash
		sig, err := opts.AuthorSigner([]byte(localDigest))
		if err != nil {
			return SyncEnvelope{}, nil, fmt.Errorf(
				"awareness: sign digest for skill %q: %w", sk.Name, err)
		}
		entry.ClientSignatureB64 = sig

		env.Skills = append(env.Skills, entry)
	}

	return env, localSkipped, nil
}

// buildSkillEntry is the core inventory-row → SkillEntry mapping. Pulled
// out so tests can pin the shape without re-running the full BuildEnvelope.
func buildSkillEntry(sk model.SkillDescriptor) SkillEntry {
	entry := SkillEntry{
		Name:          sk.Name,
		SkillMDSHA256: sk.ContentHash,
		Tier:          sk.Tier,
		SourcePath:    sk.SourcePath,
	}

	if sk.Frontmatter != nil {
		entry.Version = sk.Frontmatter.Version
		entry.Frontmatter = frontmatterToMap(sk.Frontmatter)

		// SPEC-0196 §3 mirroring: lift `intent` and `data_dependencies`
		// out of the frontmatter Metadata bag (where the YAML parser
		// stashed them) into their own envelope fields. The registry
		// validates them server-side; surfacing them at the top level
		// keeps the wire shape close to the SPEC-0196 §3.1 example.
		if intent, ok := metadataMap(sk.Frontmatter, "intent"); ok {
			entry.Intent = intent
		}
		if deps, ok := metadataList(sk.Frontmatter, "data_dependencies"); ok {
			entry.DataDependencies = deps
		}
	}

	return entry
}

// frontmatterToMap converts a typed Frontmatter into a map suitable for
// the SkillEntry.Frontmatter field. We lose the typed shape on the wire
// but keep the Metadata bag intact, which matches what the registry
// server expects to see (see SPEC-0195 §5.1 example).
func frontmatterToMap(fm *model.Frontmatter) map[string]interface{} {
	m := map[string]interface{}{}
	if fm.Name != "" {
		m["name"] = fm.Name
	}
	if fm.Version != "" {
		m["version"] = fm.Version
	}
	if fm.Description != "" {
		m["description"] = fm.Description
	}
	if fm.GovernanceLevel != "" {
		m["governance_level"] = fm.GovernanceLevel
	}
	if fm.Category != "" {
		m["category"] = fm.Category
	}
	if len(fm.Tags) > 0 {
		m["tags"] = fm.Tags
	}
	if len(fm.AllowedTools) > 0 {
		m["allowed_tools"] = fm.AllowedTools
	}
	if fm.Intent != "" {
		// Free-text intent (SPEC-0115 era). Distinct from the
		// SPEC-0196 structured `intent` block under Metadata; we send
		// both verbatim so consumers who care about either don't lose
		// signal.
		m["intent_text"] = fm.Intent
	}
	if fm.Metadata != nil {
		// Carry through any extra Metadata keys (the SPEC-0196
		// `intent` and `data_dependencies` live here verbatim).
		for k, v := range fm.Metadata {
			m[k] = v
		}
	}
	return m
}

// metadataMap returns the sub-map at fm.Metadata[key] if present, or
// (nil, false) otherwise. Used to lift the SPEC-0196 `intent` block
// out of the parsed frontmatter into its own envelope field.
func metadataMap(fm *model.Frontmatter, key string) (map[string]interface{}, bool) {
	if fm == nil || fm.Metadata == nil {
		return nil, false
	}
	v, ok := fm.Metadata[key]
	if !ok {
		return nil, false
	}
	if m, ok := v.(map[string]interface{}); ok {
		// Defensive copy so the envelope owns its own map. The
		// scanner caches Frontmatter and a downstream consumer
		// mutating the envelope shouldn't bleed back into it.
		out := make(map[string]interface{}, len(m))
		for k, vv := range m {
			out[k] = vv
		}
		return out, true
	}
	return nil, false
}

// metadataList returns a list-of-maps shape from fm.Metadata[key]. The
// SPEC-0196 `data_dependencies` field is a list of objects.
func metadataList(fm *model.Frontmatter, key string) ([]map[string]interface{}, bool) {
	if fm == nil || fm.Metadata == nil {
		return nil, false
	}
	v, ok := fm.Metadata[key]
	if !ok {
		return nil, false
	}
	switch xs := v.(type) {
	case []map[string]interface{}:
		out := make([]map[string]interface{}, 0, len(xs))
		for _, x := range xs {
			cp := make(map[string]interface{}, len(x))
			for k, vv := range x {
				cp[k] = vv
			}
			out = append(out, cp)
		}
		return out, true
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(xs))
		for _, x := range xs {
			if m, ok := x.(map[string]interface{}); ok {
				cp := make(map[string]interface{}, len(m))
				for k, vv := range m {
					cp[k] = vv
				}
				out = append(out, cp)
			}
		}
		return out, true
	}
	return nil, false
}

// failsRequireIntent reports whether an entry should be locally refused
// because --require-intent is on AND the entry's intent is missing or is
// the SPEC-0196 §7 UNKNOWN sentinel.
//
// Returns (failed_rule_name, true) on failure for structured logging in
// the SkippedRow.
func failsRequireIntent(entry SkillEntry) (string, bool) {
	if len(entry.Intent) == 0 {
		return "missing_intent_block", true
	}
	side := entry.Intent["side_effects"]
	if side == nil {
		return "missing_side_effects", true
	}
	xs, ok := side.([]interface{})
	if !ok {
		// Try string-list form too.
		if ss, ok := side.([]string); ok {
			if len(ss) == 1 && ss[0] == IntentSentinelUNKNOWN {
				return "side_effects_unknown_sentinel", true
			}
			return "", false
		}
		return "side_effects_malformed", true
	}
	if len(xs) == 1 {
		if s, ok := xs[0].(string); ok && s == IntentSentinelUNKNOWN {
			return "side_effects_unknown_sentinel", true
		}
	}
	return "", false
}

// stampDefaultIntent fills in a real governance_level on entries whose
// intent is missing or is the UNKNOWN sentinel. Does NOT touch entries
// with explicit non-sentinel intent. Acceptance test:
// `TestAwarenessSync_DefaultIntentYellow_StampsAll`.
func stampDefaultIntent(entry SkillEntry, level string) SkillEntry {
	// Only stamp where there's a gap. An entry with a real
	// non-sentinel intent stays as-is (we don't downgrade declared
	// `green` to `yellow` just because the operator passed
	// --default-intent yellow).
	reason, isGap := failsRequireIntent(entry)
	if !isGap {
		return entry
	}

	if entry.Intent == nil {
		entry.Intent = map[string]interface{}{}
	}
	// Replace the side_effects field if it was the UNKNOWN sentinel
	// (or missing); the level is encoded as the governance_level on
	// the entry's frontmatter so the server's SPEC-0196 §3.3 cross-rule
	// check has something to validate against.
	entry.Intent["side_effects"] = []interface{}{}
	entry.Intent["governance_level"] = level
	entry.Intent["_default_intent_reason"] = reason
	entry.Intent["_default_intent_source"] = "awareness_cli_default_intent_flag"

	if entry.Frontmatter == nil {
		entry.Frontmatter = map[string]interface{}{}
	}
	if _, exists := entry.Frontmatter["governance_level"]; !exists {
		entry.Frontmatter["governance_level"] = level
	}

	return entry
}

// writeJSONLine encodes v as a single JSON line + newline. Stable struct
// field order is preserved by encoding/json's declaration-order walk;
// tests rely on that.
func writeJSONLine(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// sortedTierKeys returns the keys of m sorted lexicographically. Used
// by Verify() so its output order is stable across runs.
func sortedTierKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CanonicalEnvelopeJSON returns the deterministic JSON encoding of env,
// for cross-implementation acceptance tests (SPEC-0189 §13 acceptance #6).
// Uses encoding/json; struct field order is the declaration order in
// awareness.go, which is the contract.
func CanonicalEnvelopeJSON(env SyncEnvelope) (string, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return "", err
	}
	// Encoder appends '\n'; trim it for direct equality comparisons.
	return strings.TrimSuffix(b.String(), "\n"), nil
}
