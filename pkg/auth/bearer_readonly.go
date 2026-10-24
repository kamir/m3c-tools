package auth

import (
	"errors"
	"strings"
)

// PersistedBearerReadOnly reads the existing token without migration, deletion
// or any other store writes. Missing or expired tokens are errors. Callers must
// validate their independent destination binding before invoking this function.
func PersistedBearerReadOnly(userIDHint string) (string, error) {
	store := newKeyringStore()
	return persistedBearerReadOnly(store, DeviceID(), userIDHint)
}

// persistedBearerReadOnly performs exactly one Load, without writes or fallback.
func persistedBearerReadOnly(store TokenStore, deviceID, userID string) (string, error) {
	token, err := store.Load(deviceID, userID)
	if err != nil {
		return "", err
	}
	if token == nil {
		return "", errors.New("auth: saved bearer unavailable")
	}
	if token.IsExpired() {
		return "", errors.New("auth: saved bearer expired")
	}
	value := strings.TrimSpace(token.Token)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("auth: saved bearer invalid")
	}
	return value, nil
}
