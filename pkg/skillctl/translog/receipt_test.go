package translog

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func buildReceipt(t *testing.T) (Receipt, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, _ := OpenLog(tmpLogPath(t), "log-1")
	var entries []LogEntry
	for i := 0; i < 6; i++ {
		e := mkEntry(EventAttest, i)
		entries = append(entries, e)
		if _, err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	sth, err := l.SignHead(priv, time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	proof, size, _, err := l.ProveInclusion(3)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReceipt(entries[3], 3, size, proof, sth)
	return r, pub, priv
}

func TestReceipt_VerifyOfflineRoundTrip(t *testing.T) {
	r, pub, _ := buildReceipt(t)
	if err := r.VerifyOffline(pub); err != nil {
		t.Fatalf("receipt should verify offline: %v", err)
	}
}

func TestReceipt_JSONRoundTrip(t *testing.T) {
	r, pub, _ := buildReceipt(t)
	data, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.VerifyOffline(pub); err != nil {
		t.Fatalf("parsed receipt should verify: %v", err)
	}
}

func TestReceipt_UnpinnedKeyRefused(t *testing.T) {
	r, _, _ := buildReceipt(t)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := r.VerifyOffline(otherPub); !errors.Is(err, ErrSTHSignatureInvalid) {
		t.Fatalf("wrong log key: want ErrSTHSignatureInvalid, got %v", err)
	}
}

func TestReceipt_TamperedEntryRefused(t *testing.T) {
	r, pub, _ := buildReceipt(t)
	// Tamper the event subject after the proof was made → leaf changes →
	// inclusion fails.
	r.Entry.Subject = "tampered"
	if err := r.VerifyOffline(pub); err == nil {
		t.Fatal("tampered entry should fail inclusion")
	}
}

func TestReceipt_BadProofHexRefused(t *testing.T) {
	r, pub, _ := buildReceipt(t)
	if len(r.ProofHex) == 0 {
		t.Fatal("expected a non-empty proof")
	}
	r.ProofHex[0] = "zz" + r.ProofHex[0][2:] // invalid hex
	if err := r.VerifyOffline(pub); !errors.Is(err, ErrReceiptInvalid) {
		t.Fatalf("bad proof hex: want ErrReceiptInvalid, got %v", err)
	}
}

func TestReceipt_SizeMismatchRefused(t *testing.T) {
	r, _, _ := buildReceipt(t)
	r.TreeSize = 99 // STH still says 6
	if _, err := ParseReceiptRoundtrip(t, r); !errors.Is(err, ErrReceiptInvalid) {
		t.Fatalf("size mismatch: want ErrReceiptInvalid, got %v", err)
	}
}

// ParseReceiptRoundtrip marshals then parses, surfacing validation errors.
func ParseReceiptRoundtrip(t *testing.T, r Receipt) (Receipt, error) {
	t.Helper()
	data, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	// Defeat the JSON marshal hiding the mismatch: the marshal preserves
	// fields, so ParseReceipt's validate() catches the STH/tree_size skew.
	if strings.Count(string(data), "tree_size") < 2 {
		t.Fatal("expected both receipt and STH tree_size in JSON")
	}
	return ParseReceipt(data)
}
