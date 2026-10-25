package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func TestManagedInstallDeniedCandidatePreservesEpochActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, tc := range []struct {
		name    string
		revoked bool
		code    int
	}{
		{"revoked_subject", true, 17},
		{"invalid_optional_checkpoint", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := buildInstallableFixture(t)
			managedEvidenceRoots(t, f, true, "closed")
			old := mutationCLIList(t, f, "old-unrevoked", 1, time.Now().UTC().Add(-90*time.Minute))
			var digests []string
			if tc.revoked {
				digests = []string{f.digest}
			}
			list, err := verify.NewSignedRevocationList(f.regURL, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano), 2, digests, f.regPriv)
			if err != nil {
				t.Fatal(err)
			}
			next := filepath.Join(f.dir, "new-epoch.json")
			writeJSON(t, next, list)
			extra := []string{"--revocations", next}
			if !tc.revoked {
				extra = append(extra, "--checkpoint", filepath.Join(f.dir, "missing-checkpoint.json"))
			}
			runManagedEvidenceInstall(t, binary, f, tc.code, extra...)
			status := decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
			if status.Epoch != 2 {
				t.Fatalf("denied install forgot accepted signed epoch: %+v", status)
			}
			runManagedEvidenceInstall(t, binary, f, 22, "--revocations", old)
			status = decodeMutationStatus(t, mutationStateCLI(t, binary, f, 0, "status"), f)
			if status.Epoch != 2 {
				t.Fatalf("old candidate lowered epoch: %+v", status)
			}
		})
	}
}
