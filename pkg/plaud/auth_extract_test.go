package plaud

import (
	"strings"
	"testing"
)

func TestParsePlaudTokenResult(t *testing.T) {
	longTok := "eyJhbGciOiJIUzI1NiJ9.payloadpayloadpayload.sigsigsig"
	cases := []struct {
		name      string
		raw       string
		wantTok   string
		wantVia   string
		wantEmpty bool
	}{
		{"known tokenstr", `{"token":"` + longTok + `","via":"tokenstr"}`, longTok, "tokenstr", false},
		{"renamed pld_tokenstr", `{"token":"` + longTok + `","via":"pld_tokenstr"}`, longTok, "pld_tokenstr", false},
		{"name-has-token fallback", `{"token":"` + longTok + `","via":"name-has-token"}`, longTok, "name-has-token", false},
		{"jwt-shape fallback", `{"token":"` + longTok + `","via":"jwt-shape"}`, longTok, "jwt-shape", false},
		{"empty result", `{"token":"","via":""}`, "", "", true},
		{"too-short token rejected", `{"token":"abc","via":"tokenstr"}`, "", "", true},
		{"literal null rejected", `{"token":"null","via":"x"}`, "", "", true},
		{"malformed json", `not json at all`, "", "", true},
		{"surrounding whitespace", "  " + `{"token":"` + longTok + `","via":"tokenstr"}` + "\n", longTok, "tokenstr", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok, via := parsePlaudTokenResult(c.raw)
			if c.wantEmpty {
				if tok != "" {
					t.Errorf("expected empty token, got %q (via %q)", tok, via)
				}
				return
			}
			if tok != c.wantTok {
				t.Errorf("token: got %q want %q", tok, c.wantTok)
			}
			if via != c.wantVia {
				t.Errorf("via: got %q want %q", via, c.wantVia)
			}
		})
	}
}

// TestPlaudTokenExtractJS_Shape guards the extractor JS against regressions that
// would silently disable the resilient fallbacks: it must probe both known keys
// and carry the JWT-shape + name-based fallbacks, and stay a single line so it
// embeds in the JXA path.
func TestPlaudTokenExtractJS_Shape(t *testing.T) {
	js := plaudTokenExtractJS
	for _, must := range []string{`"tokenstr"`, `"pld_tokenstr"`, "name-has-token", "jwt-shape", "localStorage", "JSON.stringify"} {
		if !strings.Contains(js, must) {
			t.Errorf("plaudTokenExtractJS missing %q — a fallback path was lost", must)
		}
	}
	if strings.ContainsAny(js, "\n\r") {
		t.Error("plaudTokenExtractJS must be single-line so it embeds in the JXA osascript path")
	}
	if strings.Contains(js, "`") {
		t.Error("plaudTokenExtractJS must not contain a backtick (breaks the Go raw-string embedding)")
	}
}
