package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func sampleToken() *DeviceToken {
	return &DeviceToken{Token: "synthetic-bearer", UserID: "synthetic-user", DeviceID: "synthetic-device"}
}

func isolate(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "keychain")
}

// This opaque retired-file canary is never decrypted by production code.
func legacyCanary(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(os.Getenv("HOME"), ".m3c-tools", "device-token.enc")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("opaque-retired-format-canary")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func assertCanary(t *testing.T, path string, expected []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("native operation modified retired file")
	}
}

func TestNativeAliasesRoundTripPreserveLegacy(t *testing.T) {
	for _, selector := range []string{"", "keychain", "auto", " KEYCHAIN "} {
		t.Run(selector, func(t *testing.T) {
			isolate(t)
			t.Setenv("M3C_TOKEN_STORE", selector)
			path, data := legacyCanary(t)
			if err := Save(sampleToken()); err != nil {
				t.Fatal(err)
			}
			got, err := Load("ignored-device", "ignored-user")
			if err != nil || got == nil || got.Token != sampleToken().Token {
				t.Fatal("native round trip failed")
			}
			if !HasStoredToken() || ActiveStoreName() != "keychain" {
				t.Fatal("native presence not reported")
			}
			assertCanary(t, path, data)
			if err := Clear(); err != nil {
				t.Fatal(err)
			}
			if HasStoredToken() || ActiveStoreName() != "none" {
				t.Fatal("native entry remained after Clear")
			}
			assertCanary(t, path, data)
		})
	}
}

func TestNativeEmptyIgnoresLegacy(t *testing.T) {
	isolate(t)
	path, data := legacyCanary(t)
	got, err := Load("synthetic-device", "synthetic-user")
	if err != nil || got != nil || HasStoredToken() || ActiveStoreName() != "none" {
		t.Fatal("retired file became an active credential")
	}
	if _, err := PersistedBearerReadOnly("synthetic-user"); err == nil {
		t.Fatal("read-only resolver accepted absent native entry")
	}
	if _, err := keyring.Get(keyringService, keyringAccount); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("native read migrated legacy material")
	}
	assertCanary(t, path, data)
}

func TestUnsupportedStoreSelection(t *testing.T) {
	for _, selector := range []string{"file", " FILE ", "unknown", "keyring", "synthetic-secret-selector"} {
		t.Run(selector, func(t *testing.T) {
			isolate(t)
			// If selection reaches the provider, operations return a different
			// classification. A separate private native-trap probe checks this
			// with no in-memory provider at all.
			keyring.MockInitWithError(errors.New("synthetic-provider-secret"))
			t.Setenv("M3C_TOKEN_STORE", selector)
			if err := Save(sampleToken()); !errors.Is(err, ErrStorePolicy) {
				t.Fatal("unsupported Save selection was not refused")
			}
			if tok, err := Load("", ""); tok != nil || !errors.Is(err, ErrStorePolicy) {
				t.Fatal("unsupported Load selection was not refused")
			}
			if err := Clear(); !errors.Is(err, ErrStorePolicy) {
				t.Fatal("unsupported Clear selection was not refused")
			}
			if tok, err := PersistedBearerReadOnly(""); tok != "" || !errors.Is(err, ErrStorePolicy) {
				t.Fatal("unsupported read-only selection was not refused")
			}
			if HasStoredToken() || ActiveStoreName() != "none" {
				t.Fatal("unsupported selection appeared active")
			}
			if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".m3c-tools")); !os.IsNotExist(err) {
				t.Fatal("unsupported operation created state")
			}
		})
	}
}

func TestNativeFailuresNoFallbackOrCleanup(t *testing.T) {
	for _, cause := range []struct {
		name string
		err  error
	}{
		{name: "unavailable", err: errors.New("synthetic-provider-secret")},
		{name: "oversize", err: errors.Join(keyring.ErrSetDataTooBig, errors.New("synthetic-provider-secret"))},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(cause.name+map[bool]string{false: "/empty-home", true: "/legacy-canary"}[existing], func(t *testing.T) {
				isolate(t)
				var path string
				var data []byte
				if existing {
					path, data = legacyCanary(t)
				}
				keyring.MockInitWithError(cause.err)
				for _, operation := range []func() error{
					func() error { return Save(sampleToken()) },
					func() error { _, err := Load("", ""); return err },
					func() error { _, err := PersistedBearerReadOnly(""); return err },
					Clear,
				} {
					err := operation()
					if !errors.Is(err, ErrUnavailable) || errors.Is(err, cause.err) {
						t.Fatal("native failure accepted or raw cause retained")
					}
				}
				if HasStoredToken() || ActiveStoreName() != "none" {
					t.Fatal("unavailable native store appeared active")
				}
				if existing {
					assertCanary(t, path, data)
				} else if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".m3c-tools")); !os.IsNotExist(err) {
					t.Fatal("native failure created fallback state")
				}
			})
		}
	}
}

func TestNativeMissingDoesNotCreateState(t *testing.T) {
	isolate(t)
	if token, err := Load("", ""); token != nil || err != nil {
		t.Fatal("empty native store did not remain empty")
	}
	if token, err := PersistedBearerReadOnly(""); token != "" || err == nil {
		t.Fatal("missing native bearer was accepted")
	}
	if err := Clear(); err != nil {
		t.Fatal("empty native Clear was not idempotent")
	}
	if HasStoredToken() || ActiveStoreName() != "none" {
		t.Fatal("empty native store appeared populated")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".m3c-tools")); !os.IsNotExist(err) {
		t.Fatal("empty native operations created filesystem state")
	}
}
