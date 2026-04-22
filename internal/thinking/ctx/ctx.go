// Package ctx provides a compile-time-safe wrapper around the
// SHA-256-derived user-context hash used by the Thinking Engine.
//
// SPEC-0167 §Isolation Model requires that:
//
//   - The raw user-context-id is NEVER used in a topic name, HTTP
//     log line, or operational metric.
//   - Only the first 16 hex chars of SHA-256(user_context_id) appear
//     in any runtime identifier.
//
// To prevent accidental use of the raw id where a hash is required,
// this package exports two distinct types — Raw and Hash — and
// forces a hash computation step between them. Using a Raw where a
// Hash is expected (e.g. as a topic prefix) is a COMPILE ERROR.
package ctx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// HashLen is the number of hex characters used in a Hash. Matches
// SPEC-0167 topic-naming rule.
const HashLen = 16

// Raw wraps the user-provided context identifier. It should never
// cross a logging, topic-naming, or network boundary. The only
// supported transform is Raw.Hash().
type Raw struct {
	value string
}

// NewRaw constructs a Raw from a non-empty, trimmed string. An empty
// string is rejected: the engine refuses to run without a concrete
// user context.
func NewRaw(s string) (Raw, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Raw{}, errors.New("ctx: user_context_id must not be empty")
	}
	return Raw{value: s}, nil
}

// Value returns the raw context string. Intentionally unexported in
// formatting to discourage accidental logging — callers must opt in.
func (r Raw) Value() string { return r.value }

// String intentionally redacts. Any stringification of Raw yields
// a placeholder; if you want the real value, call Value() explicitly.
func (r Raw) String() string { return "<ctx:redacted>" }

// Hash is the 16-hex-char SHA-256 prefix of a Raw. It is the only
// type safe to use in topic prefixes, URLs, or log lines.
type Hash struct {
	hex string
}

// Hash derives the canonical Hash from a Raw value.
func (r Raw) Hash() Hash {
	sum := sha256.Sum256([]byte(r.value))
	return Hash{hex: hex.EncodeToString(sum[:])[:HashLen]}
}

// Hex returns the hex string form of the hash.
func (h Hash) Hex() string { return h.hex }

// String returns the hex form.
func (h Hash) String() string { return h.hex }

// TopicPrefix is the mandatory prefix for all Kafka topics owned by
// an engine with this hash: "m3c.<hex>.".
func (h Hash) TopicPrefix() string { return fmt.Sprintf("m3c.%s.", h.hex) }

// Equal reports hash equality.
func (h Hash) Equal(other Hash) bool { return h.hex == other.hex }

// ParseHash validates a raw 16-hex-char string and wraps it in a
// Hash. Used when receiving a ctx hash from a trusted source (e.g.
// token claims) that has already been hashed elsewhere.
func ParseHash(s string) (Hash, error) {
	if len(s) != HashLen {
		return Hash{}, fmt.Errorf("ctx: hash must be %d chars, got %d", HashLen, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return Hash{}, fmt.Errorf("ctx: hash not valid hex: %w", err)
	}
	return Hash{hex: s}, nil
}
