package verify

// Tests for the SPEC-0188 §7 step 5.5 tenant-block check (G-18 closure,
// 2026-05-06). The fixtures reuse the helpers (happyOpts, mustKeypair,
// goodMeta, ...) from verify_test.go in this same package; we only add
// what's specific to the tenant gate here.
//
// Coverage:
//   - happy: tenant pinned, only green tenant-scoped attestation → ok
//   - failure: tenant pinned, red tenant-scoped attestation → ErrTenantBlocked
//                                                              + exit 16
//   - non-target tenant: red attestation belongs to a DIFFERENT tenant → ok
//   - global attestation: red attestation has empty tenant_scope → does NOT
//     trip step 5.5 (the global gate is stepCheckGovernance, exercised
//     elsewhere). Confirms we only block on tenant-scoped rows.
//   - precedence: CLI tenant wins over trust-roots tenant (asserted at the
//     CLI helper level — see TestResolveTenant_CLIBeatsTrustRoots in
//     install_cmds_test.go for the integration; here we cover the verifier-
//     level surface, which only sees one Tenant string).
//   - exit-code mapping: ExitCode(ErrTenantBlocked) == 16 and the constant
//     is distinct from the other six.

import (
	"errors"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// withTenantAttestations returns a happyOpts (passing chain) with the given
// list of tenant-scoped attestation rows appended to the bundle's
// Attestations. The returned opts.Tenant is the caller's chosen pin.
func withTenantAttestations(t *testing.T, tenant string, rows []registry.AttestationRow) VerifyOpts {
	t.Helper()
	opts, _ := happyOpts(t)
	opts.Tenant = tenant
	// happyOpts already seeds one global green attestation; append the
	// tenant-scoped rows after it so the test mirrors the real registry
	// shape (newest-first ordering is the registry's responsibility, not
	// the verifier's).
	opts.BundleMeta.Attestations = append(opts.BundleMeta.Attestations, rows...)
	return opts
}

// TestVerifierAcceptsTenantWithGreenAttestation: a tenant-scoped GREEN
// attestation is advisory at step 5.5 — it documents approval but does
// not block. The chain still passes.
func TestVerifierAcceptsTenantWithGreenAttestation(t *testing.T) {
	opts := withTenantAttestations(t, "kup-berlin", []registry.AttestationRow{
		{
			AttestationID: "att:tenant-green-001",
			Level:         "green",
			ReviewerID:    "id:ciso@kup-berlin",
			AttestedAt:    "2026-05-05T20:00:00Z",
			TenantScope:   "kup-berlin",
			Status:        "active",
		},
	})

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify with tenant-green attestation: %v", err)
	}
	if res.GovernanceLevel != "green" {
		t.Errorf("GovernanceLevel = %q, want green", res.GovernanceLevel)
	}
}

// TestVerifierRefusesTenantWithRedAttestation: the load-bearing case. A
// tenant-scoped RED attestation MUST fail closed with ErrTenantBlocked
// (exit 16), even though the global chain otherwise validates. The error
// message MUST cite the attestation_id and reviewer_id for forensic
// triage (per SPEC-0188 §7 step 5.5).
func TestVerifierRefusesTenantWithRedAttestation(t *testing.T) {
	opts := withTenantAttestations(t, "kup-berlin", []registry.AttestationRow{
		{
			AttestationID: "att:tenant-red-007",
			Level:         "red",
			ReviewerID:    "id:ciso@kup-berlin",
			AttestedAt:    "2026-05-06T09:00:00Z",
			TenantScope:   "kup-berlin",
			Rationale:     "Skill performs an undeclared external POST.",
			Status:        "active",
		},
	})

	_, err := Verify(opts)
	if err == nil {
		t.Fatalf("Verify accepted a tenant-blocked bundle (want ErrTenantBlocked)")
	}
	if !errors.Is(err, ErrTenantBlocked) {
		t.Fatalf("err is not ErrTenantBlocked: %v", err)
	}
	if got := ExitCode(err); got != ExitTenantBlocked {
		t.Errorf("ExitCode = %d, want %d", got, ExitTenantBlocked)
	}

	// Forensic clarity: SPEC §7 step 5.5 mandates the stderr message
	// cites attestation_id, signed_by, signed_at.
	msg := err.Error()
	for _, want := range []string{"att:tenant-red-007", "id:ciso@kup-berlin", "2026-05-06T09:00:00Z"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q; got: %s", want, msg)
		}
	}

	// And the tenant being blocked is in the message so the operator
	// knows WHICH tenant scope is in effect.
	if !strings.Contains(msg, "kup-berlin") {
		t.Errorf("error message missing tenant id; got: %s", msg)
	}
}

// TestVerifierIgnoresAttestationsForOtherTenants: a red attestation scoped
// to tenant=A must NOT block an install pinned to tenant=B. This is the
// guarantee that one tenant CISO cannot brick another tenant's deploys.
func TestVerifierIgnoresAttestationsForOtherTenants(t *testing.T) {
	// We pin the install to tenant=cflt; the red attestation belongs to
	// tenant=kup-berlin. Step 5.5 must not match.
	opts := withTenantAttestations(t, "cflt", []registry.AttestationRow{
		{
			AttestationID: "att:other-tenant-red",
			Level:         "red",
			ReviewerID:    "id:ciso@kup-berlin",
			AttestedAt:    "2026-05-05T20:00:00Z",
			TenantScope:   "kup-berlin",
			Status:        "active",
		},
	})

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify wrongly blocked on a foreign-tenant attestation: %v", err)
	}
	if res.GovernanceLevel != "green" {
		t.Errorf("GovernanceLevel = %q, want green", res.GovernanceLevel)
	}
}

// TestVerifierIgnoresAttestationsWithoutTenantScope: a GLOBAL attestation
// (empty tenant_scope) is the registry's verdict, which feeds
// CurrentGovernance and is gated by stepCheckGovernance. Step 5.5 must NOT
// fire on global rows even when they're red — that path is covered by the
// existing governance gate (exit 13), and routing a global red through
// step 5.5 would emit the wrong exit code (16 instead of 13).
//
// We exercise this by pinning a tenant AND attaching a global red row; the
// verifier should refuse the bundle with ErrGovernanceBelowMin (because
// CurrentGovernance != red here — we've left the chain otherwise green —
// and global red rows in Attestations don't, on their own, trigger 5.5).
func TestVerifierIgnoresAttestationsWithoutTenantScope(t *testing.T) {
	opts := withTenantAttestations(t, "kup-berlin", []registry.AttestationRow{
		{
			AttestationID: "att:global-red-not-step-55",
			Level:         "red",
			ReviewerID:    "id:reviewer@m3c",
			AttestedAt:    "2026-05-05T20:00:00Z",
			// TenantScope deliberately empty — this is a global row.
			Status: "active",
		},
	})

	// CurrentGovernance is still "green" (set by happyOpts/goodMeta) so
	// the existing governance gate passes; the test asserts step 5.5
	// does NOT block on the empty-tenant_scope row.
	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("step 5.5 wrongly tripped on a global attestation: %v", err)
	}
	if errors.Is(err, ErrTenantBlocked) {
		t.Fatalf("global red attestation must not trigger ErrTenantBlocked")
	}
	if res.GovernanceLevel != "green" {
		t.Errorf("GovernanceLevel = %q, want green", res.GovernanceLevel)
	}
}

// TestVerifierUsesCliFlagOverTrustRootsTenant: the precedence rule lives
// at the CLI boundary (resolveTenant in install_cmds.go). The verifier
// itself takes a single Tenant string; this test asserts that whatever the
// CLI passes is what gets honored.
//
// We mimic the "CLI flag overrides trust-roots" semantics by setting
// opts.Tenant to "cflt" while the tenant-scoped red attestation in the
// fixture is for "kup-berlin" (which would be the trust-roots-pinned
// tenant in a real run). The verifier sees only "cflt" and lets the
// install through — that's the desired precedence.
//
// The integration of resolveTenant() itself is exercised in
// install_cmds_test.go (TestResolveTenant_*).
func TestVerifierUsesCliFlagOverTrustRootsTenant(t *testing.T) {
	opts := withTenantAttestations(t, "cflt", []registry.AttestationRow{
		{
			AttestationID: "att:tenant-red-007",
			Level:         "red",
			ReviewerID:    "id:ciso@kup-berlin",
			AttestedAt:    "2026-05-06T09:00:00Z",
			TenantScope:   "kup-berlin",
			Status:        "active",
		},
	})

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify with --tenant=cflt wrongly tripped on a kup-berlin red row: %v", err)
	}
	if res.GovernanceLevel != "green" {
		t.Errorf("GovernanceLevel = %q, want green", res.GovernanceLevel)
	}
}

// TestVerifierExitCodeMapping: ErrTenantBlocked maps to 16, distinct from
// the other six numbered codes (10..15). Pairs with TestExitCode_DistinctNumbers
// in errors_test.go which only covers the original six.
func TestVerifierExitCodeMapping(t *testing.T) {
	if got := ExitCode(ErrTenantBlocked); got != ExitTenantBlocked {
		t.Errorf("ExitCode(ErrTenantBlocked) = %d, want %d", got, ExitTenantBlocked)
	}
	// Wrapped sentinel survives.
	wrapped := errors.Join(ErrTenantBlocked, errors.New("context"))
	if got := ExitCode(wrapped); got != ExitTenantBlocked {
		t.Errorf("ExitCode(wrapped ErrTenantBlocked) = %d, want %d", got, ExitTenantBlocked)
	}

	// Distinctness: 16 must not collide with any of the existing codes.
	allCodes := map[int]string{
		ExitDigestMismatch:     "ExitDigestMismatch",
		ExitAuthorSigInvalid:   "ExitAuthorSigInvalid",
		ExitRegistryNotTrusted: "ExitRegistryNotTrusted",
		ExitGovernanceBelowMin: "ExitGovernanceBelowMin",
		ExitDepsUnsatisfied:    "ExitDepsUnsatisfied",
		ExitBlobMissing:        "ExitBlobMissing",
		ExitTenantBlocked:      "ExitTenantBlocked",
	}
	if len(allCodes) != 7 {
		t.Errorf("expected 7 distinct exit codes (10..16), got %d (collision)", len(allCodes))
	}
	if ExitTenantBlocked != 16 {
		t.Errorf("ExitTenantBlocked = %d, want 16 (SPEC-0188 §11)", ExitTenantBlocked)
	}
}

// TestVerifierStep55_NoOpWhenTenantEmpty asserts the explicit no-op contract:
// when opts.Tenant == "", even a red tenant-scoped row in BundleMeta does
// not block. The bundle's tenant-scoped governance only applies when the
// consumer is pinned to that tenant — an untenanted machine does not see
// per-tenant policy.
func TestVerifierStep55_NoOpWhenTenantEmpty(t *testing.T) {
	opts := withTenantAttestations(t, "", []registry.AttestationRow{
		{
			AttestationID: "att:should-be-ignored",
			Level:         "red",
			ReviewerID:    "id:ciso@kup-berlin",
			AttestedAt:    "2026-05-06T09:00:00Z",
			TenantScope:   "kup-berlin",
			Status:        "active",
		},
	})

	if _, err := Verify(opts); err != nil {
		t.Fatalf("untenanted Verify wrongly blocked on a tenant-scoped red row: %v", err)
	}
}

// TestVerifierStep55_RevokedAttestationDoesNotBlock asserts that a
// tenant-scoped row whose status is "revoked" is skipped by step 5.5 —
// revocation supersedes the verdict (matching the existing pattern in
// pickSingleSignature). A re-attest-green by the same CISO would land as
// a separate active row.
func TestVerifierStep55_RevokedAttestationDoesNotBlock(t *testing.T) {
	opts := withTenantAttestations(t, "kup-berlin", []registry.AttestationRow{
		{
			AttestationID: "att:revoked-red",
			Level:         "red",
			ReviewerID:    "id:ciso@kup-berlin",
			AttestedAt:    "2026-05-06T09:00:00Z",
			TenantScope:   "kup-berlin",
			Status:        "revoked", // <-- key: not active
		},
	})

	if _, err := Verify(opts); err != nil {
		t.Fatalf("revoked tenant-scoped red row wrongly blocked the install: %v", err)
	}
}
