package httpsafe

import (
	"errors"
	"strings"
	"testing"
)

func syntheticBinding() CredentialBinding {
	return CredentialBinding{Version: CredentialBindingVersion, Kind: CredentialAPIKey, Origin: "https://API.example:443", Source: "operator_configured"}
}

func TestResolveCredentialDeferredSuccess(t *testing.T) {
	for _, kind := range []CredentialKind{CredentialAPIKey, CredentialDeviceBearer} {
		t.Run(string(kind), func(t *testing.T) {
			calls := 0
			binding := syntheticBinding()
			binding.Kind = kind
			got, err := ResolveCredential("https://api.example/prefix/v1", false, DeferredSecret{Binding: binding, Read: func() ([]byte, error) {
				calls++
				return []byte("synthetic-key"), nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || string(got.Secret) != "synthetic-key" || got.Base.URL != "https://api.example:443/prefix/v1" || got.Binding.Origin != "https://api.example:443" || got.Binding.Kind != kind || got.Binding.Source != binding.Source {
				t.Fatal("selected source, secret, prefix or provenance lost")
			}
		})
	}
}

func TestResolveCredentialDeniesBeforeRead(t *testing.T) {
	cases := []struct {
		name, target string
		mutate       func(*CredentialBinding)
		want         error
	}{
		{"invalid target", "https://synthetic:secret@api.example", nil, ErrInvalidAPIBase},
		{"query target", "https://api.example/?synthetic", nil, ErrInvalidAPIBase},
		{"legacy unbound", "https://api.example", func(b *CredentialBinding) { *b = CredentialBinding{} }, ErrCredentialBinding},
		{"unknown version", "https://api.example", func(b *CredentialBinding) { b.Version = 2 }, ErrCredentialBinding},
		{"negative version", "https://api.example", func(b *CredentialBinding) { b.Version = -1 }, ErrCredentialBinding},
		{"missing origin", "https://api.example", func(b *CredentialBinding) { b.Origin = "" }, ErrCredentialBinding},
		{"unknown kind", "https://api.example", func(b *CredentialBinding) { b.Kind = "session" }, ErrCredentialBinding},
		{"empty source", "https://api.example", func(b *CredentialBinding) { b.Source = "" }, ErrCredentialBinding},
		{"source whitespace", "https://api.example", func(b *CredentialBinding) { b.Source = " env " }, ErrCredentialBinding},
		{"source control", "https://api.example", func(b *CredentialBinding) { b.Source = "env\n" }, ErrCredentialBinding},
		{"foreign origin", "https://other.example", nil, ErrCredentialBinding},
		{"suffix origin", "https://api.example.evil", nil, ErrCredentialBinding},
		{"foreign port", "https://api.example:8443", nil, ErrCredentialBinding},
		{"binding path", "https://api.example", func(b *CredentialBinding) { b.Origin += "/prefix" }, ErrCredentialBinding},
		{"binding query", "https://api.example", func(b *CredentialBinding) { b.Origin += "?synthetic" }, ErrCredentialBinding},
		{"binding userinfo", "https://api.example", func(b *CredentialBinding) { b.Origin = "https://synthetic:secret@api.example" }, ErrCredentialBinding},
		{"binding insecure", "https://api.example", func(b *CredentialBinding) { b.Origin = "http://api.example" }, ErrCredentialBinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binding := syntheticBinding()
			if tc.mutate != nil {
				tc.mutate(&binding)
			}
			calls := 0
			got, err := ResolveCredential(tc.target, false, DeferredSecret{Binding: binding, Read: func() ([]byte, error) { calls++; return []byte("must-not-read"), nil }})
			if !errors.Is(err, tc.want) || calls != 0 || got.Secret != nil || got.Base != (APIBase{}) {
				t.Fatalf("wrong rejection or premature read: calls=%d err=%v", calls, err)
			}
			if strings.Contains(err.Error(), "synthetic") {
				t.Fatal("raw input reflected in diagnostic")
			}
		})
	}
}

func TestResolveCredentialLoopbackBinding(t *testing.T) {
	selected := DeferredSecret{Binding: CredentialBinding{Version: 1, Kind: CredentialAPIKey, Origin: "http://localhost", Source: "operator_configured"}, Read: func() ([]byte, error) { return []byte("synthetic-dev-key"), nil }}
	if _, err := ResolveCredential("http://LOCALHOST:80/api", false, selected); !errors.Is(err, ErrInvalidAPIBase) {
		t.Fatalf("implicit HTTP accepted: %v", err)
	}
	if _, err := ResolveCredential("http://LOCALHOST:80/api", true, selected); err != nil {
		t.Fatal(err)
	}
	calls := 0
	selected.Read = func() ([]byte, error) { calls++; return nil, nil }
	if _, err := ResolveCredential("https://localhost/api", true, selected); !errors.Is(err, ErrCredentialBinding) || calls != 0 {
		t.Fatal("scheme change accepted or read before match")
	}
}

func TestResolveCredentialReaderFailureDoesNotExposeSecret(t *testing.T) {
	cause := errors.New("synthetic-key and private path must stay hidden")
	calls := 0
	selected := DeferredSecret{Binding: syntheticBinding(), Read: func() ([]byte, error) { calls++; return []byte("partial-secret"), cause }}
	got, err := ResolveCredential("https://api.example", false, selected)
	if !errors.Is(err, ErrSecretRead) || !errors.Is(err, cause) || err.Error() != ErrSecretRead.Error() || calls != 1 || got.Secret != nil {
		t.Fatalf("error identity/redaction or partial-secret failure: %v", err)
	}
	selected.Read = nil
	if _, err := ResolveCredential("https://api.example", false, selected); !errors.Is(err, ErrSecretRead) {
		t.Fatal("nil reader accepted")
	}
	selected.Read = func() ([]byte, error) { return nil, nil }
	if _, err := ResolveCredential("https://api.example", false, selected); !errors.Is(err, ErrEmptySecret) {
		t.Fatal("empty secret accepted")
	}
}
