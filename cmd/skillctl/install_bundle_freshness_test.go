package main

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func TestManagedInstallSnapshotBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		issued   string
		epoch    int
		ceiling  string
		wantCode int
	}{
		{"exact_24h", now.Add(-24 * time.Hour).Format(time.RFC3339Nano), 1, "", 0},
		{"over_24h", now.Add(-24*time.Hour - time.Nanosecond).Format(time.RFC3339Nano), 1, "", 22},
		{"shorter_policy", now.Add(-3 * time.Hour).Format(time.RFC3339Nano), 1, "2h", 22},
		{"future_one_nanosecond", now.Add(time.Nanosecond).Format(time.RFC3339Nano), 1, "", 22},
		{"missing_issuance", "", 1, "", 22},
		{"invalid_issuance", "invalid", 1, "", 22},
		{"unversioned_epoch", now.Add(-time.Hour).Format(time.RFC3339Nano), 0, "", 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &verify.TrustRoot{MaxStaleness: tc.ceiling, OfflinePolicy: &verify.OfflinePolicyBlock{Enterprise: true}}
			out := evaluateInstallBundleFreshness(freshnessInputs{root: root, syncedEpoch: tc.epoch, syncedIssuedAt: tc.issued, risk: verify.RiskLow, now: now})
			if got := freshnessExitCode(out); got != tc.wantCode {
				t.Fatalf("exit=%d want=%d decision=%+v err=%v", got, tc.wantCode, out.Decision, out.Err)
			}
			if out.Decision.Allowed != (tc.wantCode == 0) || out.Decision.CheckpointReset {
				t.Fatalf("incorrect final snapshot decision: %+v", out.Decision)
			}
		})
	}
}
