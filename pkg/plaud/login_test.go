package plaud

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeJWT builds an unsigned JWT whose payload carries the given exp (seconds).
// jwtExpiry only decodes the payload, so the signature is irrelevant.
func makeJWT(expUnix int64) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"iat":1}`, expUnix)))
	return hdr + "." + payload + ".sig"
}

func TestPostAccessToken(t *testing.T) {
	exp := time.Now().Add(300 * 24 * time.Hour).Unix()
	jwt := makeJWT(exp)

	var gotCT, gotUser, gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotCT = r.Header.Get("Content-Type")
		gotUser = r.PostFormValue("username")
		gotPass = r.PostFormValue("password")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":0,"access_token":%q,"token_type":"Bearer"}`, jwt)
	}))
	defer srv.Close()

	tok, err := postAccessToken(srv.URL, "me@example.com", "s3cret")
	if err != nil {
		t.Fatalf("postAccessToken: %v", err)
	}
	if tok != jwt {
		t.Errorf("token = %q, want %q", tok, jwt)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotUser != "me@example.com" || gotPass != "s3cret" {
		t.Errorf("form = %q/%q, want me@example.com/s3cret", gotUser, gotPass)
	}
}

func TestPostAccessToken_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":-1,"msg":"wrong password"}`)
	}))
	defer srv.Close()

	if _, err := postAccessToken(srv.URL, "me@example.com", "bad"); err == nil ||
		!strings.Contains(err.Error(), "wrong password") {
		t.Errorf("err = %v, want it to carry the API msg", err)
	}
}

func TestPostAccessToken_RejectsUntrustedRegionRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":-302,"data":{"domains":{"api":"https://evil.example"}}}`)
	}))
	defer srv.Close()

	if _, err := postAccessToken(srv.URL, "me@example.com", "pw"); err == nil ||
		!strings.Contains(err.Error(), "untrusted") {
		t.Errorf("err = %v, want untrusted-redirect rejection", err)
	}
}

func TestLogin_RejectsNonPlaudHost(t *testing.T) {
	cfg := &Config{APIURL: "https://evil.example"}
	if _, err := Login(cfg, "me@example.com", "pw"); err == nil {
		t.Error("expected Login to refuse a non-plaud.ai API base")
	}
	if _, err := Login(&Config{APIURL: "https://api.plaud.ai"}, "", "pw"); err == nil {
		t.Error("expected Login to require an email")
	}
}

func TestJWTExpiry(t *testing.T) {
	want := time.Now().Add(200 * 24 * time.Hour).Truncate(time.Second)
	if got := jwtExpiry(makeJWT(want.Unix())); !got.Equal(want) {
		t.Errorf("jwtExpiry = %v, want %v", got, want)
	}
	for _, bad := range []string{"", "a.b", "not.a.jwt", "x.@@@.y"} {
		if got := jwtExpiry(bad); !got.IsZero() {
			t.Errorf("jwtExpiry(%q) = %v, want zero", bad, got)
		}
	}
}

func TestTokenSession_IsExpired(t *testing.T) {
	future := &TokenSession{Token: "t", SavedAt: time.Now().Add(-365 * 24 * time.Hour), ExpiresAt: time.Now().Add(90 * 24 * time.Hour)}
	if future.IsExpired(DefaultMaxTokenAge) {
		t.Error("token with a far-future ExpiresAt must NOT be expired despite an old SavedAt")
	}
	past := &TokenSession{Token: "t", SavedAt: time.Now(), ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if !past.IsExpired(DefaultMaxTokenAge) {
		t.Error("token past its ExpiresAt must be expired")
	}
	// Regression: a freshly-captured ~1-day token must NOT be considered expired
	// (the margin must be far smaller than the token's lifetime).
	oneDay := &TokenSession{Token: "t", SavedAt: time.Now(), ExpiresAt: time.Now().Add(23 * time.Hour)}
	if oneDay.IsExpired(DefaultMaxTokenAge) {
		t.Error("a fresh ~1-day token must be usable, not treated as expired by the margin")
	}
	// No ExpiresAt → age-based cap applies (scraped-token behavior preserved).
	old := &TokenSession{Token: "t", SavedAt: time.Now().Add(-8 * 24 * time.Hour)}
	if !old.IsExpired(DefaultMaxTokenAge) {
		t.Error("token older than maxAge (no ExpiresAt) must be expired")
	}
	fresh := &TokenSession{Token: "t", SavedAt: time.Now()}
	if fresh.IsExpired(DefaultMaxTokenAge) {
		t.Error("fresh token (no ExpiresAt) must not be expired")
	}
}

func TestNewImportedTokenSession(t *testing.T) {
	exp := time.Now().Add(200 * 24 * time.Hour).Unix()
	jwt := makeJWT(exp)

	t.Run("strips Bearer prefix and quotes, records expiry", func(t *testing.T) {
		for _, in := range []string{jwt, "Bearer " + jwt, `"` + jwt + `"`, `"Bearer ` + jwt + `"`, "  Bearer " + jwt + "  "} {
			s := NewImportedTokenSession(in)
			if s.Token != jwt {
				t.Errorf("import(%q).Token = %q, want bare %q", in, s.Token, jwt)
			}
			if s.ExpiresAt.IsZero() {
				t.Errorf("import(%q) did not record expiry", in)
			}
		}
	})

	t.Run("recovers the JWT from a messy paste", func(t *testing.T) {
		// A whole header line, and a Network-table row with tabs/newlines around it.
		for _, in := range []string{
			"authorization: Bearer " + jwt,
			"GET\tfile/simple/web\t200\t" + jwt + "\txhr\n",
			"authorization: Bearer " + jwt, // stray nbsp
		} {
			if s := NewImportedTokenSession(in); s.Token != jwt {
				t.Errorf("import(%q).Token = %q, want recovered %q", in, s.Token, jwt)
			}
		}
	})

	t.Run("empty / no-JWT input rejected", func(t *testing.T) {
		for _, in := range []string{"", "   ", "no token here", "Bearer not-a-jwt"} {
			if s := NewImportedTokenSession(in); s.Token != "" {
				t.Errorf("import(%q).Token = %q, want empty (rejected)", in, s.Token)
			}
		}
	})
}

func TestBoundedTokenExpiry(t *testing.T) {
	// A sane exp is preserved; a bogus far-future exp is clamped.
	sane := time.Now().Add(100 * 24 * time.Hour).Truncate(time.Second)
	if got := boundedTokenExpiry(makeJWT(sane.Unix())); !got.Equal(sane) {
		t.Errorf("sane exp: got %v want %v", got, sane)
	}
	year9999 := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	got := boundedTokenExpiry(makeJWT(year9999))
	if got.After(time.Now().Add(maxTokenLifetime + time.Hour)) {
		t.Errorf("far-future exp not clamped: %v", got)
	}
	if boundedTokenExpiry("not.a.jwt") != (time.Time{}) {
		t.Error("unparseable JWT should yield zero expiry")
	}
}

func TestBearerHeader(t *testing.T) {
	if got := bearerHeader("eyJ.a.b"); got != "Bearer eyJ.a.b" {
		t.Errorf("bearerHeader added wrong prefix: %q", got)
	}
	if got := bearerHeader("Bearer eyJ.a.b"); got != "Bearer eyJ.a.b" {
		t.Errorf("bearerHeader must not double the prefix: %q", got)
	}
}
