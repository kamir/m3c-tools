package datascope

import (
	"encoding/json"
	"fmt"
)

// FromMap decodes one raw `data_dependencies[]` entry (the `map[string]any`
// shape the `intent declare` CLI and the bundle.json both carry) into a typed
// DataScope. It does NOT validate — the caller runs Validate()/Validate(...)
// after decoding so the structural decode error and the semantic validation
// error stay distinguishable.
//
// Unknown keys are tolerated (forward-compat): a future field on the wire must
// not break decoding on an older binary. Only the typed fields are pulled out.
func FromMap(m map[string]any) (DataScope, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return DataScope{}, fmt.Errorf("datascope: re-marshal raw dep: %w", err)
	}
	var d DataScope
	if err := json.Unmarshal(b, &d); err != nil {
		return DataScope{}, fmt.Errorf("datascope: decode dep: %w", err)
	}
	return d, nil
}

// FromMaps decodes a slice of raw deps. The first decode error short-circuits.
func FromMaps(ms []map[string]any) ([]DataScope, error) {
	out := make([]DataScope, 0, len(ms))
	for i, m := range ms {
		d, err := FromMap(m)
		if err != nil {
			return nil, fmt.Errorf("data_dependencies[%d]: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// IntentFromMap pulls the typed cross-rule fields out of the free-form `intent`
// map. It is lenient: a missing/absent key leaves the corresponding pointer
// nil (so the cross-rules can tell "absent" from "false"). Non-bool values for
// destructive/network are treated as absent rather than an error — the field
// validators in the CLI already reject malformed flag input upstream; here we
// only extract what is cleanly typed.
func IntentFromMap(m map[string]any) Intent {
	var in Intent
	if se, ok := m["side_effects"]; ok {
		in.SideEffects = toStringSlice(se)
	}
	if d, ok := m["destructive"]; ok {
		if b, isBool := d.(bool); isBool {
			in.Destructive = &b
		}
	}
	if n, ok := m["network"]; ok {
		if b, isBool := n.(bool); isBool {
			in.Network = &b
		}
	}
	return in
}

// toStringSlice coerces an `any` (typically []any from JSON or []string from
// in-code construction) into []string, dropping non-string members.
func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
