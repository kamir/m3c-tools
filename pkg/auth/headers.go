package auth

import (
	"net/http"
	"os"
)

// ApplyAuth sets the correct authentication header on an HTTP request.
// Device token (Bearer) takes priority over API key (X-API-KEY).
// The apiKey parameter is the caller's local API key for backward compat;
// the device token is read from the ER1_DEVICE_TOKEN env var (set at startup).
func ApplyAuth(req *http.Request, apiKey string) {
	if token := os.Getenv("ER1_DEVICE_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if apiKey != "" {
		req.Header.Set("X-API-KEY", apiKey)
	}
}

// HasAuth returns true if any authentication method is available.
func HasAuth(apiKey string) bool {
	return os.Getenv("ER1_DEVICE_TOKEN") != "" || apiKey != ""
}

// AuthMethod returns the name of the active authentication method.
func AuthMethod() string {
	if os.Getenv("ER1_DEVICE_TOKEN") != "" {
		return "device token"
	}
	if os.Getenv("ER1_API_KEY") != "" {
		return "API key"
	}
	return "none"
}

// PersistedBearer resolves a device token from the at-rest store (OS keychain or
// the encrypted-file fallback) for use as an Authorization: Bearer credential,
// WITHOUT requiring the caller to export ER1_DEVICE_TOKEN. It is the read-back
// half of FR-0043: `m3c-tools login` / `skillctl login` persist the token; this
// reads it so skillctl can authenticate after a login alone.
//
// userIDHint is only consulted by the encrypted-file backend's key derivation
// (the keychain backend ignores it). Pass the caller's own Google sub, or "".
//
// Returns ("", false) when no token is stored, and ("", true) when a token
// exists but has expired (caller should prompt a re-login).
func PersistedBearer(userIDHint string) (token string, expired bool) {
	dt, err := Load(DeviceID(), userIDHint)
	if err != nil || dt == nil {
		return "", false
	}
	if dt.IsExpired() {
		return "", true
	}
	return dt.Token, false
}
