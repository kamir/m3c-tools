// Package govlevel holds the ONE canonical governance-level vocabulary and its
// normalisation + floor-validation primitives (SPEC-0252 §6, SPEC-0188 §4.4).
//
// Before this, the two trust-root loaders — verify.Load (SPEC-0188 signing
// roots) and registry.LoadSelfTrustRoots (SPEC-0225 governance floor) — each
// spelled the valid-floor set AND the case/whitespace normalisation separately,
// and they had drifted:
//
//   - registry normalised the floor with ToLower+TrimSpace and STORED the
//     result (the SEC-L1 residual fix), so its rank lookup couldn't collapse;
//   - verify lowercased-WITHOUT-trim at load, stored the mixed-case value, and
//     relied on a SECOND normalisation at comparison time. As a side effect it
//     rejected a whitespace-padded but valid floor (" green ") that registry
//     accepted.
//
// Two copies of a security-relevant normaliser is exactly how the case-collapse
// class (a mixed-case floor ranking as "unknown" → the governance gate silently
// admitting everything) gets reintroduced by a future edit to one and not the
// other. Centralising it here makes that drift impossible: both loaders, and
// every comparison, call the same Normalize / ValidFloor.
package govlevel

import "strings"

// Canonical governance levels, strictest first. "red" is the most-permissive
// rung — a valid *attestation level* but never a valid *floor* (see ValidFloor).
const (
	Green  = "green"
	Yellow = "yellow"
	Red    = "red"
)

// Normalize lower-cases and trims a governance level so storage and comparison
// are case- and whitespace-insensitive. This is the ONE normaliser; call it at
// every load, store, and comparison so a floor can never collapse via case.
func Normalize(level string) string {
	return strings.ToLower(strings.TrimSpace(level))
}

// ValidFloor reports whether s is a meaningful governance FLOOR and returns its
// normalised form. Only "green" and "yellow" are valid floors: "red" is the
// most-permissive rung, so pinning the floor to red would silently admit every
// attestation (defeating the gate), and unknown/typo'd values are rejected so a
// config error fails loudly rather than silently disabling governance. The
// returned normalised string is meaningful only when ok is true; callers store
// it verbatim. (SPEC-0188 §4.4.)
func ValidFloor(s string) (normalized string, ok bool) {
	n := Normalize(s)
	switch n {
	case Green, Yellow:
		return n, true
	default:
		return n, false
	}
}
