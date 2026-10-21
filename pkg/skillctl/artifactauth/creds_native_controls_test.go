package artifactauth

import (
	"strings"
	"testing"
)

func TestLookupExplicitNativeControls(t *testing.T) {
	for _, tc := range []struct{ control, value string }{
		{control: "M3C_TOKEN_STORE", value: "file"},
		{control: "M3C_TEST_KEYCHAIN", value: "0"},
	} {
		t.Run(tc.control, func(t *testing.T) {
			t.Setenv("M3C_TOKEN_STORE", "")
			t.Setenv("M3C_TEST_KEYCHAIN", "")
			t.Setenv(tc.control, tc.value)
			t.Setenv("M3C_SYNTHETIC_TOKEN", "")
			native := func(string, string) string {
				t.Fatal("native credential store read with explicit off control")
				return ""
			}
			t.Setenv("M3C_REGISTRY_TOKEN", "")
			if got := provisionedWithNative("registry", TierWrite, "synthetic-host", native, native); got != "" {
				t.Fatal("native status lookup returned a source")
			}
			t.Setenv("M3C_REGISTRY_TOKEN", "synthetic-env-value")
			if got := provisionedWithNative("registry", TierWrite, "synthetic-host", native, native); got != "env M3C_REGISTRY_TOKEN" {
				t.Fatal("environment source lookup lost")
			}
			r := New()
			if got := r.lookupWithNative("registry", "M3C_SYNTHETIC_TOKEN", "synthetic-service", "synthetic-host", native, native); got != "" {
				t.Fatalf("token %q", got)
			}
			t.Setenv("M3C_SYNTHETIC_TOKEN", "synthetic-env-value")
			if got := r.lookupWithNative("registry", "M3C_SYNTHETIC_TOKEN", "synthetic-service", "synthetic-host", native, native); got != "synthetic-env-value" {
				t.Fatal("explicit environment lookup lost")
			}
		})
	}
}

func TestLookupNativeDefaultRetained(t *testing.T) {
	t.Setenv("M3C_TOKEN_STORE", "")
	t.Setenv("M3C_TEST_KEYCHAIN", "")
	t.Setenv("M3C_SYNTHETIC_TOKEN", "")
	calls := 0
	native := func(string, string) string { calls++; return "synthetic-store-value" }
	got := New().lookupWithNative("registry", "M3C_SYNTHETIC_TOKEN", "synthetic-service", "synthetic-host", native, native)
	if got != "synthetic-store-value" || calls != 1 {
		t.Fatalf("native default got %q calls%d", got, calls)
	}
}

func TestNativeManagementExplicitControls(t *testing.T) {
	for _, tc := range []struct{ control, value string }{
		{control: "M3C_TOKEN_STORE", value: "file"},
		{control: "M3C_TEST_KEYCHAIN", value: "0"},
	} {
		t.Run(tc.control, func(t *testing.T) {
			t.Setenv("M3C_TOKEN_STORE", "")
			t.Setenv("M3C_TEST_KEYCHAIN", "")
			t.Setenv(tc.control, tc.value)
			store := func(string, string, string) error { t.Fatal("native credential write invoked"); return nil }
			remove := func(string, string) error { t.Fatal("native credential delete invoked"); return nil }
			if err := storeWithNative("registry", TierWrite, "synthetic-host", "synthetic-value", store); err == nil || !strings.Contains(err.Error(), "disabled") {
				t.Fatalf("missing disabled write error: %v", err)
			}
			if err := deleteWithNative("registry", TierWrite, "synthetic-host", remove); err == nil || !strings.Contains(err.Error(), "disabled") {
				t.Fatalf("missing disabled delete error: %v", err)
			}
		})
	}
}
