package plaud

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// jwtPattern matches a JWT-shaped token (header.payload.signature). Plaud's
// bearer is a JWT, so this recovers it from a messy paste (a whole "authorization:
// Bearer …" line, a copied Network-table row with tabs, etc.).
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}`)

// findJWT returns the first JWT-shaped substring in s, or "".
func findJWT(s string) string { return jwtPattern.FindString(s) }

// Login performs a Plaud consumer password-grant login and returns a session
// holding the access token — a long-lived (~300-day) Bearer JWT. This is the
// robust replacement for browser token-scraping: it POSTs form-encoded
// username/password to /auth/access-token exactly as the Plaud web app does, so
// it does not depend on any localStorage/cookie implementation detail.
//
// The API base comes from cfg.APIURL (LoadConfig validates it is an https
// *.plaud.ai host and defaults to the US endpoint https://api.plaud.ai; EU
// accounts set PLAUD_API_URL=https://api-euc1.plaud.ai). A -302 region redirect
// is followed once to the (allowlisted) regional host.
//
// The returned session carries the JWT's real ExpiresAt so LoadToken honors the
// ~300-day lifetime instead of the 7-day scraped-token cap.
func Login(cfg *Config, email, password string) (*TokenSession, error) {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return nil, fmt.Errorf("plaud: login requires both an email and a password")
	}
	if !isAllowedPlaudDomain(cfg.APIURL) {
		return nil, fmt.Errorf("plaud: refusing to send credentials — API base is not an https *.plaud.ai host")
	}

	access, err := postAccessToken(cfg.APIURL, email, password)
	if err != nil {
		return nil, err
	}

	sess := &TokenSession{Token: access, SavedAt: time.Now()}
	sess.ExpiresAt = boundedTokenExpiry(access)
	return sess, nil
}

// maxTokenLifetime clamps the locally-trusted expiry. jwtExpiry reads an
// UNSIGNED `exp`, so a bogus far-future value could otherwise disable the
// staleness re-auth net. The API stays the auth authority regardless; this only
// bounds how long we skip a proactive re-login.
const maxTokenLifetime = 400 * 24 * time.Hour

// boundedTokenExpiry returns the JWT's exp, clamped to [now, now+maxTokenLifetime].
// Returns the zero time when no usable exp is present (caller falls back to the
// age-based cap).
func boundedTokenExpiry(jwt string) time.Time {
	exp := jwtExpiry(jwt)
	if exp.IsZero() {
		return time.Time{}
	}
	if max := time.Now().Add(maxTokenLifetime); exp.After(max) {
		return max
	}
	return exp
}

// postAccessToken issues the password-grant request, following a single Plaud
// region redirect (status -302, {data:{domains:{api}}}) to the regional host.
func postAccessToken(base, email, password string) (string, error) {
	form := url.Values{"username": {email}, "password": {password}}.Encode()
	// Refuse HTTP-level redirects: Plaud signals region changes at the application
	// layer (status -302, re-validated below), so a transport 3xx must never
	// replay the password body to another (possibly http:// or non-plaud) host.
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", base+"/auth/access-token", strings.NewReader(form))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("app-platform", "web")
		req.Header.Set("edit-from", "web")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("plaud: login request: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close() //nolint:errcheck // best-effort close of the read-only response body already read above

		var r struct {
			Status      int    `json:"status"`
			Msg         string `json:"msg"`
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Data        struct {
				Domains struct {
					API string `json:"api"`
				} `json:"domains"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return "", fmt.Errorf("plaud: login: unexpected response (%d bytes)", len(body))
		}

		// Region redirect: retry once against the regional host (allowlisted).
		if r.Status == -302 && r.Data.Domains.API != "" && attempt == 0 {
			if !isAllowedPlaudDomain(r.Data.Domains.API) {
				return "", fmt.Errorf("plaud: login region redirect to untrusted host")
			}
			base = r.Data.Domains.API
			continue
		}
		if r.Status != 0 || r.AccessToken == "" {
			msg := r.Msg
			if msg == "" {
				msg = fmt.Sprintf("status %d", r.Status)
			}
			return "", fmt.Errorf("plaud: login failed: %s", msg)
		}
		return r.AccessToken, nil
	}
	return "", fmt.Errorf("plaud: login failed after region redirect")
}

// NewImportedTokenSession builds a session from a raw token value the user
// pasted or imported — e.g. the `Authorization` value copied from the DevTools
// Network tab of a logged-in web.plaud.ai (the reliable path for Google/Apple
// SSO accounts, whose bearer never lands in localStorage). It strips an optional
// "Bearer " scheme prefix and surrounding quotes, and records the JWT's real
// expiry when present so a long-lived token is not capped at the 7-day
// scraped-token age.
func NewImportedTokenSession(raw string) *TokenSession {
	// Recover the JWT from anywhere in the input — a bare token, "Bearer eyJ…",
	// a full "authorization: …" header line, a quoted value, or a copied
	// Network-table row with tabs. Plaud's bearer is always a JWT, so a single
	// pattern match both extracts it and validates the shape.
	tok := findJWT(raw)
	if tok == "" {
		return &TokenSession{}
	}
	return &TokenSession{Token: tok, SavedAt: time.Now(), ExpiresAt: boundedTokenExpiry(tok)}
}

// DefaultMCPTokenPath returns the path where `npx @plaud-ai/mcp login` writes
// its OAuth token (~/.plaud/tokens-mcp.json).
func DefaultMCPTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".plaud", "tokens-mcp.json")
	}
	return filepath.Join(home, ".plaud", "tokens-mcp.json")
}

// mcpAccessTokenKeys are the field names under which the official MCP token file
// may hold the consumer ACCESS token (checked before falling back to "first JWT",
// so we never grab the refresh token by mistake).
var mcpAccessTokenKeys = []string{"access_token", "accessToken", "token", "access"}

// LoadMCPTokenFile reads the OAuth token minted by `npx @plaud-ai/mcp login`
// (~300-day, auto-refreshing, Google-SSO first-class) and returns a session for
// the ACCESS token. This is the durable, no-DevTools path for SSO accounts. It
// prefers an explicit access-token field (top-level or one level nested) and
// falls back to the first JWT found in the file, so it tolerates schema drift.
func LoadMCPTokenFile(path string) (*TokenSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plaud: read %s: %w", path, err)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) == nil {
		if s := pickJWTField(obj, mcpAccessTokenKeys); s != "" {
			return NewImportedTokenSession(s), nil
		}
		for _, raw := range obj { // one level of nesting (e.g. {"tokens":{...}})
			var inner map[string]json.RawMessage
			if json.Unmarshal(raw, &inner) == nil {
				if s := pickJWTField(inner, mcpAccessTokenKeys); s != "" {
					return NewImportedTokenSession(s), nil
				}
			}
		}
	}
	if j := findJWT(string(data)); j != "" { // last resort: first JWT in the file
		return NewImportedTokenSession(j), nil
	}
	return nil, fmt.Errorf("plaud: no access token (JWT) found in %s", path)
}

// pickJWTField returns the first string value among keys that is JWT-shaped.
func pickJWTField(m map[string]json.RawMessage, keys []string) string {
	for _, k := range keys {
		raw, ok := m[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && jwtPattern.MatchString(s) {
			return s
		}
	}
	return ""
}

// jwtClaimString returns a string claim from a JWT payload (unverified decode);
// "" on any failure. Used for a STABLE account id — the `sub` survives a token
// refresh, unlike a hash of the whole (rotating) token.
func jwtClaimString(jwt, claim string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return ""
	}
	if s, ok := m[claim].(string); ok {
		return s
	}
	return ""
}

// jwtExpiry decodes a JWT's `exp` claim into a time. Returns the zero time on any
// parse failure — callers then fall back to the age-based expiry heuristic.
func jwtExpiry(jwt string) time.Time {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return time.Time{}
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}
