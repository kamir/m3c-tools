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

// PersistedBearer resolves only the native OS token store. It never reads,
// migrates or deletes retired token files. userIDHint remains for compatibility;
// the native store ignores it. Callers handle external tokens separately.
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
