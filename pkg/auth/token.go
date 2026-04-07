// Package auth handles device token storage and retrieval for m3c-tools.
// Tokens are stored encrypted on disk using AES-256-GCM with a key derived
// from device-specific material (hostname + user ID).
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// tokenDir returns the directory for token storage.
func tokenDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config directory: %w", err)
	}
	return dir, nil
}

// tokenPath returns the path to the encrypted token file.
func tokenPath() (string, error) {
	dir, err := tokenDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "device-token.enc"), nil
}

// deriveKey creates a 256-bit encryption key from the device ID and user ID.
// This ensures the encrypted file is tied to this specific device+user combination.
func deriveKey(deviceID, userID string) []byte {
	h := sha256.Sum256([]byte("m3c-device-token:" + deviceID + ":" + userID))
	return h[:]
}

// Save encrypts and writes the device token to disk.
func Save(token *DeviceToken) error {
	path, err := tokenPath()
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	key := deriveKey(token.DeviceID, token.UserID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}

// Load reads and decrypts the device token from disk.
// Returns nil, nil if no token file exists.
func Load(deviceID, userID string) (*DeviceToken, error) {
	path, err := tokenPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no token saved
		}
		return nil, fmt.Errorf("read token file: %w", err)
	}

	key := deriveKey(deviceID, userID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("token file too short")
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt token (wrong device or corrupted): %w", err)
	}

	var token DeviceToken
	if err := json.Unmarshal(plaintext, &token); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}
	return &token, nil
}

// Clear removes the stored device token.
func Clear() error {
	path, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove token: %w", err)
	}
	return nil
}

// DeviceID returns a stable identifier for this machine.
func DeviceID() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
