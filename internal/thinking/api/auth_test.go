package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

func TestSignAndVerifyRoundtrip(t *testing.T) {
	secret := []byte("shhh")
	c := Claims{CtxID: "user-A", Expiry: time.Now().Add(time.Minute), Nonce: "n1"}
	tok := SignToken(secret, c)
	got, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.CtxID != "user-A" || got.Nonce != "n1" {
		t.Errorf("claims mismatch: %+v", got)
	}
}

func TestVerifyRejectsBadSig(t *testing.T) {
	secret := []byte("shhh")
	c := Claims{CtxID: "user-A", Expiry: time.Now().Add(time.Minute), Nonce: "n1"}
	tok := SignToken(secret, c)
	if _, err := VerifyToken([]byte("other"), tok); err == nil {
		t.Errorf("expected HMAC mismatch")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	secret := []byte("shhh")
	c := Claims{CtxID: "user-A", Expiry: time.Now().Add(-time.Second), Nonce: "n1"}
	tok := SignToken(secret, c)
	if _, err := VerifyToken(secret, tok); err == nil {
		t.Errorf("expected expiry error")
	}
}

func TestMiddlewareRejectsForeignCtx(t *testing.T) {
	secret := []byte("shhh")
	ownerRaw, _ := mctx.NewRaw("user-A")
	mw := AuthMiddleware(secret, ownerRaw, map[string]bool{"/v1/health": true})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// health bypass
	req := httptest.NewRequest("GET", "/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health bypass failed: %d", rec.Code)
	}

	// no token → 401
	req = httptest.NewRequest("GET", "/v1/process/p-1", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing-token should be 401, got %d", rec.Code)
	}

	// foreign ctx token → 401
	tok := SignToken(secret, Claims{CtxID: "user-B", Expiry: time.Now().Add(time.Minute), Nonce: "n"})
	req = httptest.NewRequest("GET", "/v1/process/p-1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("foreign-ctx should be 401, got %d", rec.Code)
	}

	// valid ctx token → 200
	tok = SignToken(secret, Claims{CtxID: "user-A", Expiry: time.Now().Add(time.Minute), Nonce: "n"})
	req = httptest.NewRequest("GET", "/v1/process/p-1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid token should be 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}
