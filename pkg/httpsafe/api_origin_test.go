package httpsafe

import (
	"errors"
	"testing"
)

func TestParseAPIBaseCanonical(t *testing.T) {
	cases := []struct {
		name, raw    string
		http         bool
		origin, base string
	}{
		{"HTTPS case and prefix", "HTTPS://API.Example/api/v1/", false, "https://api.example:443", "https://api.example:443/api/v1/"},
		{"explicit default", "https://api.example:00443/root", false, "https://api.example:443", "https://api.example:443/root"},
		{"custom port", "https://api.example:8443/a%2Fb", false, "https://api.example:8443", "https://api.example:8443/a%2Fb"},
		{"IPv6", "https://[0:0:0:0:0:0:0:1]/api", false, "https://[::1]:443", "https://[::1]:443/api"},
		{"localhost HTTP", "http://LOCALHOST/api", true, "http://localhost:80", "http://localhost:80/api"},
		{"numeric loopback HTTP", "http://127.10.20.30:8080/api", true, "http://127.10.20.30:8080", "http://127.10.20.30:8080/api"},
		{"IPv6 loopback HTTP", "http://[::1]/", true, "http://[::1]:80", "http://[::1]:80/"},
		{"mapped loopback HTTP", "http://[::ffff:127.0.0.1]/", true, "http://127.0.0.1:80", "http://127.0.0.1:80/"},
		{"minimum port", "https://api.example:1", false, "https://api.example:1", "https://api.example:1"},
		{"maximum port", "https://api.example:65535", false, "https://api.example:65535", "https://api.example:65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAPIBase(tc.raw, tc.http)
			if err != nil {
				t.Fatal(err)
			}
			if got.Origin.String() != tc.origin || got.URL != tc.base {
				t.Fatalf("got %#v, want origin %q and base %q", got, tc.origin, tc.base)
			}
			again, err := ParseAPIBase(got.URL, tc.http)
			if err != nil || got != again {
				t.Fatalf("not idempotent: %#v, %v", again, err)
			}
		})
	}
}

func TestParseAPIBaseRejectsUnsafe(t *testing.T) {
	cases := []string{
		"", "api.example", "//api.example/a", "https:api.example", "ftp://api.example", "http://api.example", "http://localhost", "http://127.0.0.1", "http://[::1]",
		"https://user:synthetic@api.example", "https://api.example?", "https://api.example?key=synthetic", "https://api.example#", "https://api.example#synthetic",
		" https://api.example", "https://api.example\n", "https://api.example/\t", "https://api.example/%0d%0A", "https://api.example/%7f", "https://api.example/\\x", "https://api.example/%5Cx",
		"https://api.example:", "https://api.example:0", "https://api.example:65536", "https://api.example:-1", "https://api.example:+443", "https://api.example:abc", "https://api.example:999999999999999999999",
		"https://", "https://.example", "https://example..com", "https://-example.com", "https://example-.com", "https://exa_mple.com", "https://éxample.com", "https://[example.com]", "https://[127.0.0.1]", "https://::1:443", "https://[fe80::1%25lo0]", "https://api.example/%XX",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			got, err := ParseAPIBase(raw, false)
			if !errors.Is(err, ErrInvalidAPIBase) || got != (APIBase{}) {
				t.Fatalf("invalid URL accepted: %#v, %v", got, err)
			}
		})
	}
}

func TestParseAPIBaseLoopbackIsExplicitAndNumeric(t *testing.T) {
	for _, raw := range []string{"http://localhost.evil.example", "http://localhost.", "http://127.1", "http://2130706433", "http://0x7f000001", "http://192.168.1.1", "http://[::]", "http://[::ffff:192.168.1.1]", "http://loopback.example"} {
		if _, err := ParseAPIBase(raw, true); !errors.Is(err, ErrInvalidAPIBase) {
			t.Errorf("nonliteral/nonloopback HTTP accepted: %s", raw)
		}
	}
}

func TestAPIOriginsAreDistinct(t *testing.T) {
	base, err := ParseAPIBase("https://api.example/a", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://api.example.evil/a", "https://other.example/a", "https://api.example:8443/a", "http://localhost/a"} {
		other, err := ParseAPIBase(raw, true)
		if err != nil {
			t.Fatal(err)
		}
		if base.Origin == other.Origin {
			t.Errorf("distinct origin matched: %s", raw)
		}
	}
	same, err := ParseAPIBase("https://API.EXAMPLE:443/other", false)
	if err != nil || same.Origin != base.Origin {
		t.Fatalf("path incorrectly changes origin: %#v, %v", same, err)
	}
}
