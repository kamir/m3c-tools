package ctx

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewRawRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		if _, err := NewRaw(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestHashIsDeterministicAnd16Hex(t *testing.T) {
	raw, err := NewRaw("demo-user")
	if err != nil {
		t.Fatal(err)
	}
	h := raw.Hash()
	if len(h.Hex()) != HashLen {
		t.Fatalf("hash length = %d, want %d", len(h.Hex()), HashLen)
	}
	sum := sha256.Sum256([]byte("demo-user"))
	want := hex.EncodeToString(sum[:])[:HashLen]
	if h.Hex() != want {
		t.Errorf("hash = %q, want %q", h.Hex(), want)
	}

	// determinism
	raw2, _ := NewRaw("demo-user")
	if !h.Equal(raw2.Hash()) {
		t.Errorf("hash not deterministic")
	}
}

func TestTopicPrefix(t *testing.T) {
	raw, _ := NewRaw("abc")
	h := raw.Hash()
	prefix := h.TopicPrefix()
	if !strings.HasPrefix(prefix, "m3c.") || !strings.HasSuffix(prefix, ".") {
		t.Errorf("bad prefix shape: %q", prefix)
	}
	if !strings.Contains(prefix, h.Hex()) {
		t.Errorf("prefix %q missing hex %q", prefix, h.Hex())
	}
}

func TestRawRedactsInString(t *testing.T) {
	raw, _ := NewRaw("super-secret-user-id")
	if strings.Contains(raw.String(), "super-secret") {
		t.Errorf("raw.String() must redact, got %q", raw.String())
	}
}

func TestParseHashRoundtrip(t *testing.T) {
	raw, _ := NewRaw("demo-user")
	h := raw.Hash()
	back, err := ParseHash(h.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(h) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestParseHashRejectsBad(t *testing.T) {
	for _, in := range []string{"", "xyz", "zzzzzzzzzzzzzzzz", "012345678"} {
		if _, err := ParseHash(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}
