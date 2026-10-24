package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestNativeProviderErrorRedaction(t *testing.T) {
	raw := errors.New("synthetic-sensitive-provider-diagnostic")
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{name: "locked", cause: raw},
		{name: "oversized", cause: errors.Join(keyring.ErrSetDataTooBig, raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			check := func(service, account string) {
				calls++
				if service != keyringService || account != keyringAccount {
					t.Fatal("wrong native coordinates")
				}
			}
			results := []error{
				saveKeyringToken(sampleToken(), func(s, a, body string) error {
					check(s, a)
					if !strings.Contains(body, sampleToken().Token) {
						t.Fatal("missing native write")
					}
					return tc.cause
				}),
				clearKeyringToken(func(s, a string) error { check(s, a); return tc.cause }),
			}
			_, err := loadKeyringToken(func(s, a string) (string, error) { check(s, a); return "", tc.cause })
			results = append(results, err)
			if calls != 3 {
				t.Fatal("wrong native operation count")
			}
			for _, err := range results {
				if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), raw.Error()) || errors.Is(err, raw) {
					t.Fatal("unsafe native error")
				}
				if errors.Is(tc.cause, keyring.ErrSetDataTooBig) && !errors.Is(err, keyring.ErrSetDataTooBig) {
					t.Fatal("oversize classification lost")
				}
			}
		})
	}
}

func TestNativeProviderMissingAndMalformed(t *testing.T) {
	if token, err := loadKeyringToken(func(string, string) (string, error) { return "", keyring.ErrNotFound }); token != nil || err != nil {
		t.Fatal("absent native item not empty")
	}
	if err := clearKeyringToken(func(string, string) error { return keyring.ErrNotFound }); err != nil {
		t.Fatal("absent native clear not idempotent")
	}
	if token, err := loadKeyringToken(func(string, string) (string, error) { return "synthetic-sensitive-json", nil }); token != nil || !errors.Is(err, ErrInvalidToken) || strings.Contains(err.Error(), "synthetic-sensitive-json") {
		t.Fatal("malformed native content not safely rejected")
	}
	called := false
	if err := saveKeyringToken(nil, func(string, string, string) error { called = true; return nil }); !errors.Is(err, ErrInvalidToken) || called {
		t.Fatal("nil Save reached provider")
	}
}

func TestExternalBearerWorksWithUnsupportedNativeSelection(t *testing.T) {
	isolate(t)
	keyring.MockInitWithError(errors.New("synthetic-unavailable-provider"))
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("ER1_DEVICE_TOKEN", "synthetic-external-bearer")
	req, err := http.NewRequest(http.MethodGet, "https://example.invalid/synthetic", nil)
	if err != nil {
		t.Fatal(err)
	}
	ApplyAuth(req, "")
	if req.Header.Get("Authorization") != "Bearer synthetic-external-bearer" || !HasAuth("") || AuthMethod() != "device token" {
		t.Fatal("external credential incorrectly required a persistent store")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".m3c-tools")); !os.IsNotExist(err) {
		t.Fatal("external credential created persistence")
	}
}

// Pinned v0.2.8 uses a 75-byte fixed command envelope for our native item;
// serialized JSON sizes 3015 and 3016 straddle its 4096-byte command limit.
func TestNativeDarwinPayloadPreflight(t *testing.T) {
	empty, err := json.Marshal(&DeviceToken{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		token    *DeviceToken
		oversize bool
	}{
		{"small", &DeviceToken{Token: "synthetic"}, false},
		{"last accepted byte", &DeviceToken{Token: strings.Repeat("x", 3015-len(empty))}, false},
		{"first refused byte", &DeviceToken{Token: strings.Repeat("x", 3016-len(empty))}, true},
		{"unicode metadata", &DeviceToken{Token: "synthetic", UserName: strings.Repeat("ä", 2048)}, true},
		{"escaped metadata", &DeviceToken{Token: "synthetic", UserName: strings.Repeat("<", 1024)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := saveKeyringToken(tc.token, func(string, string, string) error { calls++; return nil })
			if runtime.GOOS == "darwin" && tc.oversize {
				if calls != 0 || !errors.Is(err, ErrUnavailable) || !errors.Is(err, keyring.ErrSetDataTooBig) {
					t.Fatal("oversize native dispatch was not refused before provider access")
				}
			} else if calls != 1 || err != nil {
				t.Fatal("valid payload or other platform dispatch changed")
			}
		})
	}
}
