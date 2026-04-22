// auth.go — HMAC bearer middleware.
//
// SPEC-0167 §Service Components §api requires tokens be HMAC-signed
// and encode user_context_id + expiry; engine rejects any token
// whose context_id does not match its own. The scheme is:
//
//   Authorization: Bearer base64url(ctx_id|expiry|nonce|HMAC-SHA256)
//
// where HMAC-SHA256 covers ctx_id|expiry|nonce with a shared secret
// known to the Flask bridge and this engine. Engine's ctx_id is its
// startup flag; tokens for any other ctx are 401'd.

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// Claims is the decoded content of a bearer token.
type Claims struct {
	CtxID  string
	Expiry time.Time
	Nonce  string
}

// SignToken returns a Bearer-ready token string for the given
// claims + secret. Exposed for the Flask bridge + tests.
func SignToken(secret []byte, c Claims) string {
	payload := fmt.Sprintf("%s|%d|%s", c.CtxID, c.Expiry.Unix(), c.Nonce)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	raw := payload + "|" + base64.RawURLEncoding.EncodeToString(sig)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// VerifyToken parses + verifies a token. Returns the decoded claims
// on success; error otherwise.
func VerifyToken(secret []byte, token string) (Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: token not base64url: %w", err)
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 {
		return Claims{}, errors.New("auth: token format ctx|expiry|nonce|sig required")
	}
	ctxID, expStr, nonce, sigB64 := parts[0], parts[1], parts[2], parts[3]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: signature not base64url: %w", err)
	}
	payload := fmt.Sprintf("%s|%s|%s", ctxID, expStr, nonce)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return Claims{}, errors.New("auth: HMAC mismatch")
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: bad expiry: %w", err)
	}
	expT := time.Unix(exp, 0).UTC()
	if time.Now().UTC().After(expT) {
		return Claims{}, errors.New("auth: token expired")
	}
	return Claims{CtxID: ctxID, Expiry: expT, Nonce: nonce}, nil
}

// AuthMiddleware returns an HTTP middleware enforcing bearer-HMAC
// against ownerRaw. Requests for routes in bypass are served without
// a token (e.g. /v1/health).
func AuthMiddleware(secret []byte, owner mctx.Raw, bypass map[string]bool) func(http.Handler) http.Handler {
	ownerID := owner.Value()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bypass[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				writeAuthError(w, "missing bearer token")
				return
			}
			tok := strings.TrimPrefix(h, "Bearer ")
			claims, err := VerifyToken(secret, tok)
			if err != nil {
				writeAuthError(w, err.Error())
				return
			}
			if claims.CtxID != ownerID {
				writeAuthError(w, "token ctx mismatch")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"unauthorized","detail":%q}`, msg)))
}
