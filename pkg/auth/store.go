package auth

import "errors"

// ErrUnavailable indicates that the native credential store cannot be used.
// It never authorizes a fallback to a file or another persistence backend.
var ErrUnavailable = errors.New("auth: native token store unavailable")

// ErrStorePolicy indicates an unsupported persistence selector.
var ErrStorePolicy = errors.New("auth: token store selector is unsupported; use the native store or an externally supplied token")

// ErrInvalidToken indicates an invalid stored token representation.
var ErrInvalidToken = errors.New("auth: stored token is invalid")

// TokenStore persists exactly one device token at rest.
type TokenStore interface {
	Name() string
	Save(t *DeviceToken) error
	// Load returns (nil, nil) for an empty store. Identity hints are retained
	// for compatibility; the native backend does not derive keys from them.
	Load(deviceID, userID string) (*DeviceToken, error)
	// Clear removes only the native entry. Legacy files are never touched.
	Clear() error
	Has() bool
}

// Save persists only in the native OS store. An unavailable or oversized native
// write is a failure, with no file creation, migration or cleanup.
func Save(t *DeviceToken) error { return newKeyringStore().Save(t) }

// Load reads only the native OS store. Legacy files are ignored and unchanged.
func Load(deviceID, userID string) (*DeviceToken, error) {
	return newKeyringStore().Load(deviceID, userID)
}

// Clear removes only the native entry. Retired files require separate manual
// cleanup; this operation neither reads nor deletes them.
func Clear() error { return newKeyringStore().Clear() }

// HasStoredToken reports whether the selected native store contains a token.
// Unsupported selectors and unavailable stores report false.
func HasStoredToken() bool { return newKeyringStore().Has() }

// ActiveStoreName reports "keychain" only for a populated native store.
func ActiveStoreName() string {
	s := newKeyringStore()
	if s.Has() {
		return s.Name()
	}
	return "none"
}
