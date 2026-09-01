// SPEC-0198 author-identity revocation — verifier-layer test suite (BUG-0144).
//
// Closes Layer 3 of the BUG-0144 acceptance:
//   pkg/skillctl/verify/Verify must return ErrIdentityRevoked (not
//   ErrAuthorSigInvalid) for any bundle whose author identity has been
//   revoked via SPEC-0198 §3. The numeric exit code is 17 (theme
//   "data-source / source-policy", same as DataSourceDenied — see
//   pkg/skillctl/exitcode RevokeIdentityRevoked).
//
// These tests are intentionally minimal: they rely on the fakeFetcher /
// happyOpts helpers already in verify_test.go and assert (1) the
// sentinel, (2) the exit-code mapping, (3) the rationale/timestamp
// survive in the error message so operators see the cause.

package verify

import (
	"errors"
	"strings"
	"testing"
)

// TestVerify_IdentityRevoke_Sentinel — the canonical happy path: an
// active identity verifies, then we flip its RevokedAt and the same
// verify call now returns ErrIdentityRevoked. Same bundle, same
// signature, only the identity row changed.
func TestVerify_IdentityRevoke_Sentinel(t *testing.T) {
	opts, _ := happyOpts(t)

	// Confirm baseline.
	if _, err := Verify(opts); err != nil {
		t.Fatalf("baseline verify failed: %v", err)
	}

	// Flip the revoke bit.
	ident := opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"]
	ident.RevokedAt = "2026-05-09T00:00:00Z"

	_, err := Verify(opts)
	if err == nil {
		t.Fatalf("revoked identity: expected error, got nil")
	}
	if !errors.Is(err, ErrIdentityRevoked) {
		t.Errorf("revoked identity: want ErrIdentityRevoked, got %v", err)
	}
}

// TestVerify_IdentityRevoke_ExitCode — the registry contract: revoked
// authors map to 17, not 11. This is what `skillctl install` exits
// with, and what the e2e harness asserts.
func TestVerify_IdentityRevoke_ExitCode(t *testing.T) {
	opts, _ := happyOpts(t)
	opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"].RevokedAt = "2026-05-09T00:00:00Z"

	_, err := Verify(opts)
	if got := ExitCode(err); got != 17 {
		t.Errorf("ExitCode = %d, want 17 (RevokeIdentityRevoked)", got)
	}

	// Defense-in-depth: explicitly assert it's NOT the
	// pre-BUG-0144 exit-11 mapping.
	if got := ExitCode(err); got == ExitAuthorSigInvalid {
		t.Errorf("ExitCode collided with ExitAuthorSigInvalid (%d); should be 17", got)
	}
}

// TestVerify_IdentityRevoke_ErrorContext — the operator MUST see the
// identity id + revoke timestamp in the error message so they can
// look up the SPEC-0198 audit row.
func TestVerify_IdentityRevoke_ErrorContext(t *testing.T) {
	opts, _ := happyOpts(t)
	revokedAt := "2026-05-09T00:01:00Z"
	opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"].RevokedAt = revokedAt

	_, err := Verify(opts)
	if err == nil {
		t.Fatalf("expected revoke error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "id:author@m3c") {
		t.Errorf("error message missing identity id: %q", msg)
	}
	if !strings.Contains(msg, revokedAt) {
		t.Errorf("error message missing revoked_at timestamp: %q", msg)
	}
}

// TestVerify_ActiveIdentity_NoRevoke — sanity: an identity with empty
// RevokedAt continues to verify cleanly (no false positives).
func TestVerify_ActiveIdentity_NoRevoke(t *testing.T) {
	opts, _ := happyOpts(t)
	ident := opts.IdentityFetcher.(*fakeFetcher).identities["id:author@m3c"]
	if ident.RevokedAt != "" {
		t.Fatalf("test setup: baseline identity should not be revoked, got %q", ident.RevokedAt)
	}

	_, err := Verify(opts)
	if errors.Is(err, ErrIdentityRevoked) {
		t.Errorf("active identity wrongly classified as revoked: %v", err)
	}
}

// TestExitCode_IdentityRevokeDistinctFromAuthorSig — the registry
// invariant: ErrIdentityRevoked must not alias ErrAuthorSigInvalid.
// Pre-BUG-0144 the verifier wrapped the revoke path into
// ErrAuthorSigInvalid; a regression that re-wraps would break the
// numeric distinction.
func TestExitCode_IdentityRevokeDistinctFromAuthorSig(t *testing.T) {
	if errors.Is(ErrIdentityRevoked, ErrAuthorSigInvalid) {
		t.Error("ErrIdentityRevoked should NOT be an alias of ErrAuthorSigInvalid")
	}
	if ExitCode(ErrIdentityRevoked) == ExitCode(ErrAuthorSigInvalid) {
		t.Errorf("exit codes collided: revoked=%d author_sig=%d",
			ExitCode(ErrIdentityRevoked), ExitCode(ErrAuthorSigInvalid))
	}
}
