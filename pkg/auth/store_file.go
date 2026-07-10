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
)

// fileStore persists the token as a host-bound AES-256-GCM blob under
// ~/.m3c-tools/device-token.enc. It is the fallback for hosts without a usable
// OS keychain. The encryption key is derived from device + user material, so
// the file cannot be decrypted on a different machine — but note this is
// host-binding, not true secrecy against a same-user process (which can
// re-derive the key). The keychain backend is preferred for that reason.
type fileStore struct{}

func newFileStore() TokenStore { return fileStore{} }

func (fileStore) Name() string { return "file" }

// tokenDir returns the directory for token storage, creating it if needed.
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
// This ties the encrypted file to this specific device+user combination.
func deriveKey(deviceID, userID string) []byte {
	h := sha256.Sum256([]byte("m3c-device-token:" + deviceID + ":" + userID))
	return h[:]
}

// Save encrypts and writes the device token to disk.
func (fileStore) Save(token *DeviceToken) error {
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
func (fileStore) Load(deviceID, userID string) (*DeviceToken, error) {
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

// Clear removes the stored device token file.
func (fileStore) Clear() error {
	path, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove token: %w", err)
	}
	return nil
}

// Has reports whether the encrypted token file exists, without creating the
// config directory as a side effect.
func (fileStore) Has() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, statErr := os.Stat(filepath.Join(home, ".m3c-tools", "device-token.enc"))
	return statErr == nil
}
