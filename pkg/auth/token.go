// Package auth handles device token storage and retrieval for m3c-tools.
//
// At rest the token is kept in the operating-system keychain (macOS Keychain,
// Linux Secret Service, Windows Credential Manager) via a TokenStore backend.
// When no keychain is available (headless Linux, CI, a locked keyring) it falls
// back to a host-bound encrypted file under ~/.m3c-tools/. See store.go for the
// backend selection and migration logic.
package auth

import (
	"os"
	"time"
)

// DeviceToken holds the token and metadata received from aims-core after login.
type DeviceToken struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	ContextID string `json:"context_id"`
	UserName  string `json:"user_name,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	DeviceID  string `json:"device_id"`
	ExpiresAt string `json:"expires_at,omitempty"`
	SavedAt   string `json:"saved_at"`
}

// IsExpired returns true if the token has passed its expiration time.
func (t *DeviceToken) IsExpired() bool {
	if t.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return true // treat unparseable as expired
	}
	return time.Now().After(exp)
}

// DeviceID returns a stable identifier for this machine.
func DeviceID() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
