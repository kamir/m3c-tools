// Package redact holds the Trust Freeze redaction seam (SPEC-0467 R5).
//
// This file defines only the Redacted byte type. It is a leaf: it imports
// nothing from the trustfreeze core, because the core bundle writer accepts
// raw evidence only as a Redacted value. That makes "persist output that never
// passed the redactor" a compile error instead of a review finding.
package redact

// Redacted is evidence that has passed through the redactor of this package.
//
// Only this package can construct a non-empty value: the field is unexported
// and so is the constructor. Code outside the package can spell the zero value
// (Redacted{}), which carries no bytes and therefore cannot smuggle raw output
// into a bundle.
type Redacted struct {
	b []byte
}

// newRedacted wraps bytes that the redactor has already processed. It copies
// its input, so a caller that keeps the original slice cannot change the
// evidence afterwards.
func newRedacted(b []byte) Redacted {
	if len(b) == 0 {
		return Redacted{}
	}
	c := make([]byte, len(b))
	copy(c, b)
	return Redacted{b: c}
}

// Bytes returns a copy of the redacted evidence. Mutating the result does not
// change the value.
func (r Redacted) Bytes() []byte {
	if len(r.b) == 0 {
		return []byte{}
	}
	c := make([]byte, len(r.b))
	copy(c, r.b)
	return c
}
