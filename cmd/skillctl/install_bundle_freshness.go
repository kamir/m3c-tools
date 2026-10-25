package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// evaluateInstallBundleFreshness adds a full-snapshot age precondition to local
// managed installs. The caller supplies metadata from the authenticated list.
// This checks the current wall clock, not durable clock/epoch history; it does
// not replace the separately required mutation-state adapter.
func evaluateInstallBundleFreshness(in freshnessInputs) freshnessOutcome {
	if in.now.IsZero() {
		in.now = time.Now().UTC()
	}
	if in.root.IsManaged() {
		in.risk = verify.RiskHigh
	}
	// Preserve explicit checkpoint and emergency verification, including refusals.
	out := evaluateFreshness(in)
	if out.Err != nil || !in.root.IsManaged() {
		return out
	}
	policy, err := in.root.Freshness()
	if err != nil {
		return freshnessOutcome{Err: fmt.Errorf("managed install freshness policy: %w", err)}
	}
	// Always use the original full list and fail-closed action class. Neither
	// execution availability policy nor a checkpoint authenticates a newer set.
	dec, err := verify.EvaluateFreshness(in.syncedEpoch, in.syncedIssuedAt, policy, verify.RiskHigh, in.now)
	out = freshnessOutcome{Decision: dec, Err: err}
	issued, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(in.syncedIssuedAt))
	if parseErr != nil || issued.IsZero() || issued.After(in.now) {
		out.Decision.Allowed = false
		out.Decision.Reason = "managed_install_invalid_revocation_issuance"
		out.Err = fmt.Errorf("managed install requires a valid nonfuture revocation issuance: %w", verify.ErrRevocationStale)
		return out
	}
	if in.syncedEpoch <= 0 {
		out.Decision.Allowed = false
		out.Decision.Reason = "managed_install_requires_versioned_revocation_list"
		out.Err = fmt.Errorf("managed install requires a versioned signed revocation list: %w", verify.ErrRegistryNotTrusted)
		return out
	}
	return out
}
