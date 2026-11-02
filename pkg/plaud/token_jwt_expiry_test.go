package plaud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// BUG-0446: a token saved without ExpiresAt (the CDP and ER1-vault capture
// paths) was trusted for the 7-day age cap even when its own JWT `exp` had
// passed long ago. The token itself is the authority on that bound.
func TestTokenSession_IsExpired_HonorsJWTExpWhenExpiresAtUnset(t *testing.T) {
	expired := &TokenSession{Token: makeJWT(time.Now().Add(-822 * time.Hour).Unix()), SavedAt: time.Now()}
	if !expired.IsExpired(DefaultMaxTokenAge) {
		t.Error("a token whose JWT exp passed 822h ago must be expired, even when saved just now")
	}
	live := &TokenSession{Token: makeJWT(time.Now().Add(20 * time.Hour).Unix()), SavedAt: time.Now()}
	if live.IsExpired(DefaultMaxTokenAge) {
		t.Error("a token whose JWT exp is 20h ahead must not be expired")
	}
	// The JWT exp only tightens: a far-future exp does not lift the age cap
	// for a token saved without ExpiresAt.
	oldFarFuture := &TokenSession{Token: makeJWT(time.Now().Add(300 * 24 * time.Hour).Unix()), SavedAt: time.Now().Add(-8 * 24 * time.Hour)}
	if !oldFarFuture.IsExpired(DefaultMaxTokenAge) {
		t.Error("a far-future JWT exp must not lift the 7-day cap when ExpiresAt is unset")
	}
}

func TestLoadToken_RefusesJWTExpiredTokenAndSaysWhen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	sess := &TokenSession{Token: makeJWT(time.Now().Add(-822 * time.Hour).Unix()), SavedAt: time.Now()}
	if err := SaveToken(path, sess); err != nil {
		t.Fatal(err)
	}
	got, err := LoadToken(path)
	if err == nil {
		t.Fatalf("LoadToken accepted a token that expired 822h ago: %+v", got)
	}
	if !strings.Contains(err.Error(), "822h") {
		t.Errorf("error %q does not say how long ago the token expired", err)
	}
	_ = os.Remove(path)
}
