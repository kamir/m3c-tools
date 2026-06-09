package auth

import "errors"

// ErrUnavailable indicates a backend cannot be used on this host right now
// (e.g. no Secret Service on a headless Linux box, or a locked keychain).
// Callers treat it as "try the next backend", not a hard failure.
var ErrUnavailable = errors.New("auth: token store unavailable")

// TokenStore persists exactly one device token at rest.
type TokenStore interface {
	// Name is a short identifier for diagnostics ("keychain", "file").
	Name() string
	// Save persists the token, replacing any existing one.
	Save(t *DeviceToken) error
	// Load returns the stored token; (nil, nil) when the store is reachable
	// but empty; (nil, ErrUnavailable) when the backend cannot be used.
	// deviceID/userID are only consumed by the file backend (key derivation).
	Load(deviceID, userID string) (*DeviceToken, error)
	// Clear removes the stored token. An absent token is not an error.
	Clear() error
	// Has reports whether a token is present, as cheaply as the backend allows.
	Has() bool
}

// stores returns the ordered backend preference: the OS keychain first, then
// the host-bound encrypted file as a fallback (headless Linux, CI, a locked
// keyring). Both backends are stateless, so constructing them is free.
func stores() (primary, fallback TokenStore) {
	return newKeyringStore(), newFileStore()
}

// Save persists the device token, preferring the OS keychain. When the keychain
// accepts the token, any legacy encrypted file is removed so the secret is not
// duplicated in two places with weaker protection. If the keychain is
// unavailable, the encrypted file is used instead.
func Save(t *DeviceToken) error {
	primary, fallback := stores()
	if err := primary.Save(t); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return fallback.Save(t)
		}
		return err
	}
	_ = fallback.Clear() // best-effort: drop the weaker legacy file
	return nil
}

// Load reads the device token, preferring the OS keychain. If the keychain is
// reachable but empty and a legacy encrypted file exists, the token is migrated
// into the keychain and the file removed (one-time upgrade on first run).
// Returns (nil, nil) when no token is stored anywhere.
func Load(deviceID, userID string) (*DeviceToken, error) {
	primary, fallback := stores()
	t, err := primary.Load(deviceID, userID)
	switch {
	case err == nil && t != nil:
		return t, nil
	case err != nil && !errors.Is(err, ErrUnavailable):
		return nil, err
	}

	// Keychain is empty (err == nil) or unavailable: consult the file.
	ft, ferr := fallback.Load(deviceID, userID)
	if ferr != nil || ft == nil {
		return ft, ferr
	}

	// Found in the legacy file. If the keychain is usable, migrate the secret
	// into it and remove the file.
	if err == nil {
		if mErr := primary.Save(ft); mErr == nil {
			_ = fallback.Clear()
		}
	}
	return ft, nil
}

// Clear removes the device token from every backend.
func Clear() error {
	primary, fallback := stores()
	e1 := primary.Clear()
	e2 := fallback.Clear()
	if e1 != nil && !errors.Is(e1, ErrUnavailable) {
		return e1
	}
	return e2
}

// HasStoredToken reports whether a device token is persisted in any backend,
// without exporting it. Used to suppress "no auth" warnings and in diagnostics.
func HasStoredToken() bool {
	primary, fallback := stores()
	return primary.Has() || fallback.Has()
}

// ActiveStoreName returns the name of the backend currently holding the token,
// or "none". Used by the doctor command.
func ActiveStoreName() string {
	primary, fallback := stores()
	switch {
	case primary.Has():
		return primary.Name()
	case fallback.Has():
		return fallback.Name()
	default:
		return "none"
	}
}
