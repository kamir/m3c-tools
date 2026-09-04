package auditevent

// eventid.go: a dependency-free, ULID-like event_id generator (REQ-3.1 /
// AUD-04). event_id is the stable identity used for dedup downstream (REQ-6.2):
// a 48-bit millisecond timestamp prefix makes ids time-ordered and lexically
// sortable, an 80-bit crypto/rand suffix makes them unique. Within a single
// millisecond the suffix is incremented so ids stay strictly monotonic even
// under a tight loop. No ULID library is pulled in; the encoding is ~40 lines
// of stdlib.

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U). 128 bits encode to
// 26 characters, matching the canonical ULID string form (e.g. 01K...).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// idState carries the monotonic generator state behind a mutex.
var idState struct {
	mu      sync.Mutex
	lastMS  uint64
	lastEnt [10]byte
}

// Test seams (production defaults). idNow pins the clock; idRandRead pins the
// entropy source. Both are package-level so a test can make NewEventID
// deterministic without a build tag.
var (
	idNow      = func() time.Time { return time.Now().UTC() }
	idRandRead = rand.Read
)

// NewEventID returns a fresh ULID-like 26-character event id. It is safe for
// concurrent use and strictly monotonic within a process.
func NewEventID() string {
	idState.mu.Lock()
	defer idState.mu.Unlock()

	ms := uint64(idNow().UnixMilli())
	var ent [10]byte

	if ms <= idState.lastMS {
		// Same or backwards clock: hold the timestamp and increment the previous
		// 80-bit entropy as a big-endian counter so the id still advances.
		ms = idState.lastMS
		ent = idState.lastEnt
		incr80(&ent)
	} else if _, err := idRandRead(ent[:]); err != nil {
		// crypto/rand should not fail; if it does, derive a non-repeating suffix
		// from the previous one so ids stay unique rather than aborting.
		ent = idState.lastEnt
		incr80(&ent)
	}

	idState.lastMS = ms
	idState.lastEnt = ent

	// Assemble 16 bytes: a 48-bit big-endian millisecond timestamp then 80 bits
	// of entropy. binary.BigEndian keeps the byte extraction inside the stdlib
	// (no hand-rolled uint64->byte truncation).
	var b [16]byte
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(b[0:6], ts[2:]) // low 48 bits = the millisecond timestamp.
	copy(b[6:], ent[:])
	return encodeULID(b)
}

// incr80 increments a 10-byte (80-bit) big-endian counter, wrapping on overflow.
func incr80(e *[10]byte) {
	for i := len(e) - 1; i >= 0; i-- {
		e[i]++
		if e[i] != 0 {
			return
		}
	}
}

// encodeULID renders 128 bits (16 bytes) as 26 Crockford base32 characters,
// most-significant bits first. The 130-bit output space is left-padded with two
// zero bits, so the first character is limited to 0–7; exactly the canonical
// ULID layout.
func encodeULID(b [16]byte) string {
	var out [26]byte
	for i := 0; i < 26; i++ {
		var v uint
		for j := 0; j < 5; j++ {
			pos := i*5 + j  // position in the 130-bit padded stream.
			real := pos - 2 // position in the 128-bit value (first 2 bits are pad).
			v <<= 1
			if real >= 0 {
				v |= bitAt(b, real)
			}
		}
		out[i] = crockford[v]
	}
	return string(out[:])
}

// bitAt returns bit k of b, counting k=0 as the most-significant bit of b[0].
func bitAt(b [16]byte, k int) uint {
	return uint(b[k/8]>>(7-uint(k%8))) & 1
}
