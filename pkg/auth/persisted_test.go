package auth

import (
	"testing"
	"time"
)

// FR-0043: PersistedBearer reads a stored token back so skillctl can authenticate
// after a login alone, without an exported ER1_DEVICE_TOKEN.

func TestPersistedBearer_FileBackend(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("M3C_TOKEN_STORE", "file")

	tok := &DeviceToken{
		Token:    "tok-abc-123",
		UserID:   "testsub",
		DeviceID: DeviceID(),
		SavedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := (fileStore{}).Save(tok); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, expired := PersistedBearer("testsub")
	if expired {
		t.Fatalf("unexpected expired=true")
	}
	if got != "tok-abc-123" {
		t.Fatalf("PersistedBearer = %q, want tok-abc-123", got)
	}
}

func TestPersistedBearer_Expired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("M3C_TOKEN_STORE", "file")

	tok := &DeviceToken{
		Token:     "tok-old",
		UserID:    "testsub",
		DeviceID:  DeviceID(),
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	if err := (fileStore{}).Save(tok); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, expired := PersistedBearer("testsub")
	if got != "" || !expired {
		t.Fatalf("PersistedBearer = (%q, %v), want (\"\", true)", got, expired)
	}
}

func TestPersistedBearer_None(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("M3C_TOKEN_STORE", "file")

	got, expired := PersistedBearer("nobody")
	if got != "" || expired {
		t.Fatalf("PersistedBearer = (%q, %v), want (\"\", false)", got, expired)
	}
}
