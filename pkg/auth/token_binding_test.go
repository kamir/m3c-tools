package auth

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	keyring "github.com/zalando/go-keyring"
)

func loginToken(t *testing.T, base string) *DeviceToken {
	t.Helper()
	binding, err := NewLoginBinding(base)
	if err != nil {
		t.Fatal(err)
	}
	return &DeviceToken{Token: "synthetic-bound-bearer", Binding: binding}
}

func TestNewLoginBindingCanonicalHTTPS(t *testing.T) {
	for _, tc := range []struct{ base, origin string }{
		{"https://API.example/prefix", "https://api.example:443"},
		{"https://api.example:00443/", "https://api.example:443"},
		{"https://api.example:8443/login", "https://api.example:8443"},
		{"https://[::1]/prefix", "https://[::1]:443"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			b, err := NewLoginBinding(tc.base)
			if err != nil || b == nil || b.Version != 1 || b.Kind != httpsafe.CredentialDeviceBearer || b.Source != observedLoginSource || b.Origin != tc.origin {
				t.Fatal("login binding was not canonical observed HTTPS provenance")
			}
		})
	}
}

func TestBoundBearerInvalidTargetBeforeNativeLoad(t *testing.T) {
	for _, base := range []string{"", "http://localhost", "http://api.example", "https://api.example?synthetic-sensitive", "https://api.example#synthetic-sensitive", "https://synthetic-sensitive@api.example", "https://api.example:0", "https://api.example:65536", " https://api.example", "https://api.example/with space"} {
		t.Run(base, func(t *testing.T) {
			probe := &readOnlyProbeStore{}
			got, err := boundBearerReadOnly(base, probe, "synthetic-device", "synthetic-user")
			if got != "" || !errors.Is(err, httpsafe.ErrInvalidAPIBase) || probe.calls != 0 || strings.Contains(err.Error(), "synthetic-sensitive") {
				t.Fatal("bad expected target reached native reader or unsafe diagnostics")
			}
			if binding, err := NewLoginBinding(base); binding != nil || !errors.Is(err, httpsafe.ErrInvalidAPIBase) {
				t.Fatal("invalid login target produced metadata")
			}
		})
	}
}

func TestBoundBearerRejectsLegacyAndInvalidBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*DeviceToken)
	}{
		{"legacy", func(t *DeviceToken) { t.Binding = nil }},
		{"empty binding", func(t *DeviceToken) { t.Binding = &httpsafe.CredentialBinding{} }},
		{"zero version", func(t *DeviceToken) { t.Binding.Version = 0 }},
		{"negative version", func(t *DeviceToken) { t.Binding.Version = -1 }},
		{"future version", func(t *DeviceToken) { t.Binding.Version = 2 }},
		{"api key kind", func(t *DeviceToken) { t.Binding.Kind = httpsafe.CredentialAPIKey }},
		{"unknown kind", func(t *DeviceToken) { t.Binding.Kind = "device_bearer_future" }},
		{"missing kind", func(t *DeviceToken) { t.Binding.Kind = "" }},
		{"missing source", func(t *DeviceToken) { t.Binding.Source = "" }},
		{"env source", func(t *DeviceToken) { t.Binding.Source = "sync-operator-assignment" }},
		{"source spaces", func(t *DeviceToken) { t.Binding.Source = " client-observed-login " }},
		{"source case", func(t *DeviceToken) { t.Binding.Source = "CLIENT-OBSERVED-LOGIN" }},
		{"foreign origin", func(t *DeviceToken) { t.Binding.Origin = "https://foreign.example:443" }},
		{"foreign port", func(t *DeviceToken) { t.Binding.Origin = "https://api.example:8443" }},
		{"missing origin", func(t *DeviceToken) { t.Binding.Origin = "" }},
		{"noncanonical implicit port", func(t *DeviceToken) { t.Binding.Origin = "https://api.example" }},
		{"noncanonical case", func(t *DeviceToken) { t.Binding.Origin = "https://API.example:443" }},
		{"noncanonical port", func(t *DeviceToken) { t.Binding.Origin = "https://api.example:00443" }},
		{"origin path", func(t *DeviceToken) { t.Binding.Origin = "https://api.example:443/prefix" }},
		{"origin trailing slash", func(t *DeviceToken) { t.Binding.Origin = "https://api.example:443/" }},
		{"origin query", func(t *DeviceToken) { t.Binding.Origin = "https://api.example:443?synthetic-sensitive" }},
		{"origin userinfo", func(t *DeviceToken) { t.Binding.Origin = "https://synthetic-sensitive@api.example:443" }},
		{"origin malformed", func(t *DeviceToken) { t.Binding.Origin = "\x00synthetic-sensitive" }},
		{"origin insecure", func(t *DeviceToken) { t.Binding.Origin = "http://api.example:80" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := loginToken(t, "https://api.example")
			tc.mutate(token)
			before, err := json.Marshal(token)
			if err != nil {
				t.Fatal(err)
			}
			probe := &readOnlyProbeStore{token: token}
			got, err := boundBearerReadOnly("https://api.example/upload", probe, "synthetic-device", "synthetic-user")
			if got != "" || !errors.Is(err, ErrCredentialBinding) || !errors.Is(err, httpsafe.ErrCredentialBinding) || probe.calls != 1 {
				t.Fatal("legacy or invalid stored binding accepted")
			}
			if !strings.Contains(err.Error(), "re-login") || strings.Contains(err.Error(), "synthetic-sensitive") || strings.Contains(err.Error(), token.Token) {
				t.Fatal("binding refusal lacks constant safe recovery guidance")
			}
			after, marshalErr := json.Marshal(token)
			if marshalErr != nil || string(before) != string(after) {
				t.Fatal("reader modified or adopted stored metadata")
			}
		})
	}
}

func TestBoundBearerSelectedValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*DeviceToken)
		deny   bool
	}{
		{"valid", func(*DeviceToken) {}, false},
		{"trim", func(t *DeviceToken) { t.Token = " \tsynthetic-bound-bearer \t" }, false},
		{"expired", func(t *DeviceToken) { t.ExpiresAt = "2000-01-01T00:00:00Z" }, true},
		{"bad expiry", func(t *DeviceToken) { t.ExpiresAt = "invalid" }, true},
		{"empty", func(t *DeviceToken) { t.Token = "" }, true},
		{"blank", func(t *DeviceToken) { t.Token = " \t" }, true},
		{"header injection", func(t *DeviceToken) { t.Token = "synthetic\r\ninjected" }, true},
		{"null injection", func(t *DeviceToken) { t.Token = "synthetic\x00injected" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := loginToken(t, "https://api.example")
			tc.mutate(token)
			probe := &readOnlyProbeStore{token: token}
			got, err := boundBearerReadOnly("https://API.example:00443/other-prefix", probe, "synthetic-device", "synthetic-user")
			if (err != nil) != tc.deny || probe.calls != 1 || (!tc.deny && got != "synthetic-bound-bearer") || (tc.deny && got != "") {
				t.Fatal("selected bound token value mismatch")
			}
			if err != nil && strings.Contains(err.Error(), "synthetic") {
				t.Fatal("selected bearer reflected in error")
			}
		})
	}
	for _, cause := range []error{ErrUnavailable, ErrStorePolicy, ErrInvalidToken} {
		probe := &readOnlyProbeStore{err: cause}
		got, err := boundBearerReadOnly("https://api.example", probe, "synthetic-device", "synthetic-user")
		if got != "" || !errors.Is(err, cause) || probe.calls != 1 {
			t.Fatal("native failure hidden or fallback attempted")
		}
	}
	probe := &readOnlyProbeStore{}
	if got, err := boundBearerReadOnly("https://api.example", probe, "synthetic-device", "synthetic-user"); got != "" || !errors.Is(err, ErrCredentialBinding) || probe.calls != 1 {
		t.Fatal("missing native entry silently accepted")
	}
}

func TestBoundBearerReloginReplacesLegacyExplicitly(t *testing.T) {
	isolate(t)
	path, canary := legacyCanary(t)
	legacy := sampleToken()
	if err := Save(legacy); err != nil {
		t.Fatal(err)
	}
	before, err := keyring.Get(keyringService, keyringAccount)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := BoundBearerReadOnly("https://api.example", "synthetic-user"); value != "" || !errors.Is(err, ErrCredentialBinding) {
		t.Fatal("unbound native entry implicitly adopted")
	}
	after, err := keyring.Get(keyringService, keyringAccount)
	if err != nil || after != before {
		t.Fatal("refused read rewrote legacy native entry")
	}
	if _, err := NewLoginBinding("https://synthetic-sensitive@api.example"); err == nil {
		t.Fatal("invalid new login target accepted")
	}
	after, err = keyring.Get(keyringService, keyringAccount)
	if err != nil || after != before {
		t.Fatal("failed login metadata construction changed entry")
	}
	bound := loginToken(t, "https://api.example/login-prefix")
	if err := Save(bound); err != nil {
		t.Fatal(err)
	}
	if value, err := BoundBearerReadOnly("https://api.example/upload", "synthetic-user"); err != nil || value != bound.Token {
		t.Fatal("explicit new login binding unusable")
	}
	if value, err := BoundBearerReadOnly("https://foreign.example", "synthetic-user"); value != "" || !errors.Is(err, ErrCredentialBinding) {
		t.Fatal("new login binding usable against foreign origin")
	}
	assertCanary(t, path, canary)
}
