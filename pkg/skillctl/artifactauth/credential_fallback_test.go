package artifactauth

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Only injected helpers are called while native controls are cleared here.
func credentialFallbackStubScope(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "")
	t.Setenv("M3C_TEST_KEYCHAIN", "")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
}

func credentialFallbackOrder(keychainHit bool) []string {
	if runtime.GOOS == "darwin" {
		if keychainHit {
			return []string{"keychain"}
		}
		return []string{"keychain", "os-store"}
	}
	return []string{"os-store"}
}

func TestCredentialFallbackLookupPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, environment, keychain, osStore string
	}{
		{"environment-wins", "  synthetic-env-value\n", "synthetic-keychain-value", "synthetic-os-value"},
		{"whitespace-env-falls-back", " \t\n", "synthetic-keychain-value", "synthetic-os-value"},
		{"keychain-before-os", "", "synthetic-keychain-value", "synthetic-os-value"},
		{"os-fallback", "", "", "synthetic-os-value"},
		{"native-missing", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentialFallbackStubScope(t)
			const environment = "M3C_SYNTHETIC_FALLBACK_TOKEN"
			t.Setenv(environment, tc.environment)
			var calls []string
			reader := func(label, value string) func(string, string) string {
				return func(service, host string) string {
					if service != "synthetic-service" || host != "instance.invalid:8443" {
						t.Fatalf("incorrect lookup identity: service=%q host=%q", service, host)
					}
					calls = append(calls, label)
					return value
				}
			}
			got := New().lookupWithNative("registry", environment, "synthetic-service", "instance.invalid:8443", reader("keychain", tc.keychain), reader("os-store", tc.osStore))
			want := strings.TrimSpace(tc.environment)
			var order []string
			if want == "" {
				if runtime.GOOS == "darwin" && tc.keychain != "" {
					want = tc.keychain
				} else {
					want = tc.osStore
				}
				order = credentialFallbackOrder(tc.keychain != "")
			}
			if got != want || !reflect.DeepEqual(calls, order) {
				t.Fatalf("lookup returned incorrect fallback: got=%q want=%q calls=%v wantCalls=%v", got, want, calls, order)
			}
		})
	}
}

func TestCredentialFallbackSourceProvenance(t *testing.T) {
	for _, tier := range []Tier{TierWrite, TierRead} {
		for _, tc := range []struct{ name, environment, keychain, osStore string }{
			{"env", " synthetic-env-value\n", "synthetic-keychain-value", "synthetic-os-value"},
			{"blank-env", " \t\n", "synthetic-keychain-value", "synthetic-os-value"},
			{"keychain", "", "synthetic-keychain-value", "synthetic-os-value"},
			{"os-store", "", "", "synthetic-os-value"},
			{"missing", "", "", ""},
		} {
			t.Run(string(tier)+"/"+tc.name, func(t *testing.T) {
				credentialFallbackStubScope(t)
				service, environment := "m3c-skillctl-registry", "M3C_REGISTRY_TOKEN"
				if tier == TierRead {
					service, environment = "m3c-skillctl-registry-ro", "M3C_REGISTRY_RO_TOKEN"
				}
				t.Setenv(environment, tc.environment)
				var calls []string
				reader := func(label, value string) func(string, string) string {
					return func(gotService, host string) string {
						if gotService != service || host != "instance.invalid" {
							t.Fatalf("incorrect source lookup identity: service=%q host=%q", gotService, host)
						}
						calls = append(calls, label)
						return value
					}
				}
				got := provisionedWithNative("registry", tier, "instance.invalid", reader("keychain", tc.keychain), reader("os-store", tc.osStore))
				want := ""
				var order []string
				switch {
				case strings.TrimSpace(tc.environment) != "":
					want = "env " + environment
				case runtime.GOOS == "darwin" && tc.keychain != "":
					want = "keychain " + service
					order = credentialFallbackOrder(true)
				default:
					if tc.osStore != "" {
						want = "protected store " + service
					}
					order = credentialFallbackOrder(false)
				}
				if got != want || !reflect.DeepEqual(calls, order) {
					t.Fatalf("incorrect source: got=%q want=%q calls=%v wantCalls=%v", got, want, calls, order)
				}
				for _, secret := range []string{"synthetic-env-value", "synthetic-keychain-value", "synthetic-os-value"} {
					if strings.Contains(got, secret) {
						t.Fatal("credential status disclosed synthetic secret instead of source")
					}
				}
			})
		}
	}
}

func TestCredentialFallbackEmptyService(t *testing.T) {
	credentialFallbackStubScope(t)
	unavailable := func(string, string) string {
		t.Fatal("empty service or unknown backend reached native reader")
		return ""
	}
	const environment = "M3C_SYNTHETIC_FALLBACK_TOKEN"
	for _, value := range []string{"", " \t\n", " synthetic-env-value\n"} {
		t.Setenv(environment, value)
		got := New().lookupWithNative("registry", environment, "", "instance.invalid", unavailable, unavailable)
		if got != strings.TrimSpace(value) {
			t.Fatalf("empty-service environment precedence: got=%q", got)
		}
	}
	if got := New().lookupWithNative("registry", "", "", "instance.invalid", unavailable, unavailable); got != "" {
		t.Fatal("missing service returned credential")
	}
	if got := provisionedWithNative("synthetic-unknown-backend", TierRead, "instance.invalid", unavailable, unavailable); got != "" {
		t.Fatal("unknown backend reported credential source")
	}
}

func TestCredentialFallbackNativeManagementResults(t *testing.T) {
	for _, tier := range []Tier{TierRead, TierWrite} {
		for _, fail := range []bool{false, true} {
			name := string(tier) + "/success"
			if fail {
				name = string(tier) + "/native-error"
			}
			t.Run(name, func(t *testing.T) {
				credentialFallbackStubScope(t)
				service := "m3c-skillctl-registry"
				environment := "M3C_REGISTRY_TOKEN"
				if tier == TierRead {
					service = "m3c-skillctl-registry-ro"
					environment = "M3C_REGISTRY_RO_TOKEN"
				}
				nativeErr := errors.New("synthetic native failure")
				var wantErr error
				if fail {
					wantErr = nativeErr
				}
				storeCalls := 0
				err := storeWithNative("registry", tier, "instance.invalid:8443", "synthetic-store-value", func(gotService, host, secret string) error {
					storeCalls++
					if gotService != service || host != "instance.invalid:8443" || secret != "synthetic-store-value" {
						t.Fatal("store changed tier, host or synthetic secret")
					}
					return wantErr
				})
				if HasProtectedStore() {
					if storeCalls != 1 || err != wantErr || !errors.Is(err, wantErr) {
						t.Fatalf("native store result not preserved: calls=%d err=%v", storeCalls, err)
					}
				} else {
					if storeCalls != 0 || err == nil || !strings.Contains(err.Error(), environment) || strings.Contains(err.Error(), "synthetic-store-value") {
						t.Fatalf("unsupported platform should refuse before native callback: calls=%d err=%v", storeCalls, err)
					}
				}
				deleteCalls := 0
				err = deleteWithNative("registry", tier, "instance.invalid:8443", func(gotService, host string) error {
					deleteCalls++
					if gotService != service || host != "instance.invalid:8443" {
						t.Fatal("delete changed tier or host")
					}
					return wantErr
				})
				if deleteCalls != 1 || err != wantErr || !errors.Is(err, wantErr) {
					t.Fatalf("native delete result not preserved: calls=%d err=%v", deleteCalls, err)
				}
			})
		}
	}
}
