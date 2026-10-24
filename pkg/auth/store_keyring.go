package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	keyring "github.com/zalando/go-keyring"
)

const (
	keyringService = "m3c-tools"
	keyringAccount = "device-token"
)

// keyringStore uses the native macOS Keychain, Linux Secret Service or Windows
// Credential Manager. An unavailable provider never selects weaker persistence.
type keyringStore struct{}

// The historical auto spelling now means native-only. Explicit file and unknown
// selectors fail before any provider call, including management and diagnostics.
func newKeyringStore() TokenStore {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("M3C_TOKEN_STORE"))) {
	case "", "keychain", "auto":
		return keyringStore{}
	default:
		return unsupportedStore{}
	}
}

type unsupportedStore struct{}

func (unsupportedStore) Name() string                           { return "none" }
func (unsupportedStore) Save(*DeviceToken) error                { return ErrStorePolicy }
func (unsupportedStore) Load(_, _ string) (*DeviceToken, error) { return nil, ErrStorePolicy }
func (unsupportedStore) Clear() error                           { return ErrStorePolicy }
func (unsupportedStore) Has() bool                              { return false }

func (keyringStore) Name() string { return "keychain" }

// Native error text may contain credentials or provider-controlled diagnostics.
// Retain only known stable classifications, never the original error chain.
func nativeStoreError(err error) error {
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		return fmt.Errorf("%w: %w", ErrUnavailable, keyring.ErrSetDataTooBig)
	}
	return ErrUnavailable
}

func (keyringStore) Save(t *DeviceToken) error { return saveKeyringToken(t, keyring.Set) }

func saveKeyringToken(t *DeviceToken, set func(string, string, string) error) error {
	if t == nil {
		return ErrInvalidToken
	}
	blob, err := json.Marshal(t)
	if err != nil {
		return ErrInvalidToken
	}
	if err := set(keyringService, keyringAccount, string(blob)); err != nil {
		return nativeStoreError(err)
	}
	return nil
}

func (keyringStore) Load(_, _ string) (*DeviceToken, error) { return loadKeyringToken(keyring.Get) }

func loadKeyringToken(get func(string, string) (string, error)) (*DeviceToken, error) {
	val, err := get(keyringService, keyringAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil
		}
		return nil, nativeStoreError(err)
	}
	var t DeviceToken
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return nil, ErrInvalidToken
	}
	return &t, nil
}

func (keyringStore) Clear() error { return clearKeyringToken(keyring.Delete) }

func clearKeyringToken(remove func(string, string) error) error {
	if err := remove(keyringService, keyringAccount); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil
		}
		return nativeStoreError(err)
	}
	return nil
}

func (keyringStore) Has() bool {
	t, err := loadKeyringToken(keyring.Get)
	return err == nil && t != nil
}
