package plaud

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizePlaudToken(t *testing.T) {
	const tok = "eyJhbGciOiJIUzI1NiJ9.payloadpayloadpayload.sigsigsig"
	cases := []struct {
		name, in, want string
	}{
		{"bare", tok, tok},
		{"double-quoted", `"` + tok + `"`, tok},
		{"single-quoted", "'" + tok + "'", tok},
		{"quoted with whitespace", "  \"" + tok + "\"\n", tok},
		{"empty", "", ""},
		{"lone quote", `"`, `"`},
		{"unmatched quotes untouched", `"` + tok, `"` + tok},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizePlaudToken(c.in); got != c.want {
				t.Errorf("sanitizePlaudToken(%q) = %q, want %q", c.in, got, c.want)
			}
			// Idempotent: sanitizing an already-clean token is a no-op.
			if got := sanitizePlaudToken(c.want); got != c.want {
				t.Errorf("not idempotent: sanitizePlaudToken(%q) = %q", c.want, got)
			}
		})
	}
}

// TestLoadToken_SelfHealsQuotedToken guards the -3900 "invalid auth header" fix:
// a session file written by an older extractor with a JSON-encoded (quoted)
// token must load as the bare credential, no re-authentication required.
func TestLoadToken_SelfHealsQuotedToken(t *testing.T) {
	const bare = "eyJhbGciOiJIUzI1NiJ9.payloadpayloadpayload.sigsigsig"
	path := filepath.Join(t.TempDir(), "plaud-session.json")
	data, err := json.Marshal(TokenSession{Token: `"` + bare + `"`, SavedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadToken(path)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if s.Token != bare {
		t.Errorf("LoadToken token = %q, want bare %q", s.Token, bare)
	}
}

func TestParsePlaudCandidates(t *testing.T) {
	jwtA := "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaa.sigA"
	jwtB := "eyJhbGciOiJIUzI1NiJ9.bbbbbbbbbbbbbbbbbbbb.sigB"

	t.Run("sanitizes, dedupes, preserves order", func(t *testing.T) {
		raw := `{"candidates":[` +
			`{"v":"\"` + jwtA + `\"","src":"LS:jwt"},` + // quote-wrapped → sanitized
			`{"v":"` + jwtA + `","src":"SS:jwt"},` + // duplicate of A → dropped
			`{"v":"` + jwtB + `","src":"LS:name"}]}`
		got := parsePlaudCandidates(raw)
		if len(got) != 2 {
			t.Fatalf("got %d candidates, want 2: %+v", len(got), got)
		}
		if got[0].Value != jwtA || got[0].Src != "LS:jwt" {
			t.Errorf("candidate[0] = %+v, want {%q, LS:jwt}", got[0], jwtA)
		}
		if got[1].Value != jwtB {
			t.Errorf("candidate[1].Value = %q, want %q", got[1].Value, jwtB)
		}
	})

	t.Run("drops implausible and empty values", func(t *testing.T) {
		raw := `{"candidates":[{"v":"abc","src":"LS:name"},{"v":"null","src":"LS:jwt"},{"v":"","src":"SS"}]}`
		if got := parsePlaudCandidates(raw); len(got) != 0 {
			t.Errorf("expected no candidates, got %+v", got)
		}
	})

	t.Run("malformed json → nil", func(t *testing.T) {
		if got := parsePlaudCandidates("not json"); got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("rejects control chars (CRLF header-injection / false-unreachable)", func(t *testing.T) {
		raw := `{"candidates":[{"v":"eyJhbGci.payloadpayload.sig\r\nX-Evil: 1","src":"LS:jwt"}]}`
		if got := parsePlaudCandidates(raw); len(got) != 0 {
			t.Errorf("expected control-char candidate dropped, got %+v", got)
		}
	})

	t.Run("rejects over-length values", func(t *testing.T) {
		big := "eyJhbGci." + strings.Repeat("a", maxCandidateLen) + ".sig"
		raw := `{"candidates":[{"v":"` + big + `","src":"LS:jwt"}]}`
		if got := parsePlaudCandidates(raw); len(got) != 0 {
			t.Errorf("expected over-length candidate dropped, got %d", len(got))
		}
	})

	t.Run("coerces unknown src label (log-injection guard)", func(t *testing.T) {
		raw := `{"candidates":[{"v":"` + jwtA + `","src":"bogus-injected-label"}]}`
		got := parsePlaudCandidates(raw)
		if len(got) != 1 || got[0].Src != "unknown" {
			t.Errorf("expected src coerced to \"unknown\", got %+v", got)
		}
	})
}

func TestIsAllowedPlaudDomain(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://api.plaud.ai", true},
		{"https://api.plaud.ai/file/simple/web", true},
		{"https://eu.plaud.ai", true},   // regional subdomain
		{"http://api.plaud.ai", false},  // cleartext downgrade
		{"https://evilplaud.ai", false}, // no leading dot
		{"https://plaud.ai.evil.com", false},
		{"https://evil.example", false},
		{"://bad", false},
	}
	for _, c := range cases {
		if got := isAllowedPlaudDomain(c.url); got != c.want {
			t.Errorf("isAllowedPlaudDomain(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestLoadConfig_RejectsUntrustedAPIURL(t *testing.T) {
	cases := []struct {
		name, env, want string
	}{
		{"unset → default", "", defaultPlaudAPIURL},
		{"valid regional host kept", "https://eu.plaud.ai", "https://eu.plaud.ai"},
		{"attacker host → default", "https://evil.example", defaultPlaudAPIURL},
		{"http downgrade → default", "http://api.plaud.ai", defaultPlaudAPIURL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("PLAUD_API_URL", c.env)
			if got := LoadConfig().APIURL; got != c.want {
				t.Errorf("LoadConfig().APIURL = %q, want %q", got, c.want)
			}
		})
	}
}

// TestPlaudTokenCandidatesJS_Shape guards the harvester JS: it must scan BOTH
// localStorage and sessionStorage, emit the {candidates:[…]} envelope, and stay
// a single backtick-free line so it embeds in the JXA osascript path.
func TestPlaudTokenCandidatesJS_Shape(t *testing.T) {
	js := plaudTokenCandidatesJS
	for _, must := range []string{"localStorage", "sessionStorage", "candidates", "JSON.stringify"} {
		if !strings.Contains(js, must) {
			t.Errorf("plaudTokenCandidatesJS missing %q: a harvest path was lost", must)
		}
	}
	if strings.ContainsAny(js, "\n\r") {
		t.Error("plaudTokenCandidatesJS must be single-line so it embeds in the JXA osascript path")
	}
	if strings.Contains(js, "`") {
		t.Error("plaudTokenCandidatesJS must not contain a backtick (breaks the Go raw-string embedding)")
	}
}
