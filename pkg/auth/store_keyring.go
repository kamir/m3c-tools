package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	keyring "github.com/zalando/go-keyring"
)

// keyring item coordinates. There is exactly one device token per machine+home
// (mirroring the single-file model), so a fixed service+account is used; the
// secret is the DeviceToken JSON, encrypted at rest by the OS keychain.
const (
	keyringService = "m3c-tools"
	keyringAccount = "device-token"
)

// keyringStore persists the token in the OS keychain via go-keyring:
// macOS Keychain (security), Linux Secret Service (D-Bus), Windows Credential
// Manager. Unlike the file backend, the encryption key is OS-managed and not
// derivable by a reader of the store.
type keyringStore struct{}

// newKeyringStore returns the keychain backend, unless the operator has opted
// out via M3C_TOKEN_STORE=file (force the encrypted-file backend — useful on a
// macOS box where keychain prompts are unwanted, in CI, or to keep tests off
// the real OS keychain). Any other value ("", "keychain", "auto") keeps the
// keychain-first behaviour.
func newKeyringStore() TokenStore {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("M3C_TOKEN_STORE")), "file") {
		return disabledStore{}
	}
	return keyringStore{}
}

// disabledStore is a keychain backend that reports itself unavailable, so the
// orchestration in store.go transparently uses the file backend.
type disabledStore struct{}

func (disabledStore) Name() string                           { return "keychain(disabled)" }
func (disabledStore) Save(*DeviceToken) error                { return ErrUnavailable }
func (disabledStore) Load(_, _ string) (*DeviceToken, error) { return nil, ErrUnavailable }
func (disabledStore) Clear() error                           { return nil }
func (disabledStore) Has() bool                              { return false }

func (keyringStore) Name() string { return "keychain" }

func (keyringStore) Save(t *DeviceToken) error {
	blob, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	if err := keyring.Set(keyringService, keyringAccount, string(blob)); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (keyringStore) Load(_, _ string) (*DeviceToken, error) {
	val, err := keyring.Get(keyringService, keyringAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil // keychain reachable but empty
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var t DeviceToken
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}
	return &t, nil
}

func (keyringStore) Clear() error {
	if err := keyring.Delete(keyringService, keyringAccount); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (keyringStore) Has() bool {
	_, err := keyring.Get(keyringService, keyringAccount)
	return err == nil
}
