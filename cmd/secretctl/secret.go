package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Secret is a value that must never reach an output stream (SPEC-0438 §6,
// AC-6).
//
// It is a TYPE and not a convention on purpose. A convention holds until
// someone adds a debug line at three in the morning; a type that renders as
// "<redacted>" holds through fmt, %v, %s, log, and json.Marshal without anyone
// having to remember. The occasion for this is in the same session as the spec:
// a value that was piped and here-documented into the same stdin ended up as
// text in a session transcript.
//
// The value is reachable only through Reveal(), which is greppable. If a code
// review sees Reveal() near an output call, that is the whole review.
type Secret string

// String is what fmt, %v and %s reach for. It never yields the value.
func (s Secret) String() string { return "<redacted>" }

// GoString covers %#v, which bypasses String().
func (s Secret) GoString() string { return "<redacted>" }

// MarshalJSON covers the path a struct takes when it is logged as JSON.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal("<redacted>") }

// MarshalYAML covers the same for the registry format.
func (s Secret) MarshalYAML() (any, error) { return "<redacted>", nil }

// Reveal returns the value. The only way, and deliberately conspicuous.
func (s Secret) Reveal() string { return string(s) }

// Empty reports whether nothing is held. Useful without revealing.
func (s Secret) Empty() bool { return len(s) == 0 }

// Fingerprint is how two values are compared and reported: the first 12
// characters of sha256. Enough to tell two values apart in a table, far too
// little to reconstruct one.
//
// Every comparison in this tool runs over fingerprints, never over the values,
// so that a diff, a log line or a failing assertion cannot carry the secret.
func (s Secret) Fingerprint() string {
	if s.Empty() {
		return "<leer>"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// SameAs compares two secrets in a way that reads as an intent, not as an
// accident. Not constant time: both sides are values this operator already
// holds, so there is no attacker to time here. The reason to have it at all is
// that `a == b` on two Secrets would be easy to later "fix" into a print.
func (s Secret) SameAs(other Secret) bool {
	return !s.Empty() && !other.Empty() && s == other
}
