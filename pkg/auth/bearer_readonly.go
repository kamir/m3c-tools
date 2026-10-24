package auth

import (
	"errors"
	"strings"
)

// PersistedBearerReadOnly reads the existing token without migration, deletion
// or any other store writes. Missing or expired tokens are errors. Callers must
// validate their independent destination binding before invoking this function.
func PersistedBearerReadOnly(userIDHint string) (string, error) {
	primary, fallback := stores()
	return persistedBearerReadOnly(primary, fallback, DeviceID(), userIDHint)
}

// persistedBearerReadOnly retains the existing backend preference, but performs
// only Load operations. Store errors remain available to errors.Is/As callers.
func persistedBearerReadOnly(primary, fallback TokenStore, deviceID, userID string) (string, error) {
	token, err := primary.Load(deviceID, userID)
	if err != nil && !errors.Is(err, ErrUnavailable) {
		return "", err
	}
	if token == nil || err != nil {
		token, err = fallback.Load(deviceID, userID)
		if err != nil {
			return "", err
		}
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
