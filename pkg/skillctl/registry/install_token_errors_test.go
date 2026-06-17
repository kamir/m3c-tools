package registry

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Guards the token-error CLASSIFICATION so pull can map each to a clear,
// actionable message. (Refusal behaviour itself is covered by
// TestInstall_TokenForgedRefuses / TestInstall_Overwrite_RequiresTokenViaTwoStep.)
func TestVerifyInstallToken_ErrorClasses(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // installTokenKey persists a per-user 0600 key here

	plan := &InstallPlan{
		IssuedAt:   time.Now().UTC().Unix(),
		Overwrites: []PlanRow{{Name: "demo", Version: "1.0.0", NewDigest: "sha256:abc"}},
	}
	good, err := mintInstallToken(plan)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// valid token → no error
	if err := verifyInstallToken(plan, good); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	// malformed (no "." separator) → ErrTokenInvalid
	if err := verifyInstallToken(plan, "sha256:deadbeef"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("malformed: got %v, want ErrTokenInvalid", err)
	}

	// non-numeric issued_at → ErrTokenInvalid
	if err := verifyInstallToken(plan, "notanumber.AAAA"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("bad issued_at: got %v, want ErrTokenInvalid", err)
	}

	// right shape, wrong signature → ErrPlanDrift (forged/tampered)
	tampered := strings.SplitN(good, ".", 2)[0] + ".AAAA"
	if err := verifyInstallToken(plan, tampered); !errors.Is(err, ErrPlanDrift) {
		t.Fatalf("tampered: got %v, want ErrPlanDrift", err)
	}

	// validly-signed but old issued_at → ErrTokenExpired
	oldPlan := *plan
	oldPlan.IssuedAt = time.Now().UTC().Add(-10 * time.Minute).Unix()
	oldTok, err := mintInstallToken(&oldPlan)
	if err != nil {
		t.Fatalf("mint old: %v", err)
	}
	if err := verifyInstallToken(&oldPlan, oldTok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: got %v, want ErrTokenExpired", err)
	}
}
