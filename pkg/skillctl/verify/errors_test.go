package verify

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func TestExitCode_Nil(t *testing.T) {
	if got := ExitCode(nil); got != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", got)
	}
}

func TestExitCode_Sentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"native source transport", fmt.Errorf("wrapped: %w", ErrNativeEvidenceSourceIO), 1},
		{"native source and trust", errors.Join(registry.ErrNativeEvidenceInvalid, ErrNativeEvidenceSourceIO), 1},
		{"native source and stale", errors.Join(registry.ErrNativeHistoryStale, registry.ErrNativeEvidenceSourceIO), 1},
		{"native source and legacy trust", errors.Join(ErrRegistryNotTrusted, registry.ErrNativeEvidenceSourceIO), 1},
		{"native stale and persistence", errors.Join(registry.ErrNativeHistoryStale, registry.ErrNativePersistence), 1},
		{"native stale and cancel", errors.Join(registry.ErrNativeHistoryStale, context.Canceled), 1},
		{"legacy trust precedence retained", errors.Join(ErrRegistryNotTrusted, context.Canceled), 12},
		{"native session unavailable", registry.ErrNativeSessionUnavailable, 22},
		{"native enrollment exists", registry.ErrNativeHistoryExists, 22},
		{"native dependencies", fmt.Errorf("wrapped: %w", registry.ErrNativeDependenciesUnavailable), 14},
		{"native revoked", fmt.Errorf("wrapped: %w", registry.ErrNativeSubjectRevoked), 17},
		{"native history missing", fmt.Errorf("wrapped: %w", registry.ErrNativeHistoryRequired), 22},
		{"native history invalid", fmt.Errorf("wrapped: %w", registry.ErrNativeHistoryInvalid), 22},
		{"native history stale", fmt.Errorf("wrapped: %w", registry.ErrNativeHistoryStale), 22},
		{"native persistence", fmt.Errorf("wrapped: %w", registry.ErrNativePersistence), 1},
		{"native evidence invalid", fmt.Errorf("wrapped: %w", registry.ErrNativeEvidenceInvalid), 12},
		{"native consent", fmt.Errorf("wrapped: %w", registry.ErrNativeConsentInvalid), 12},
		{"digest mismatch", ErrDigestMismatch, ExitDigestMismatch},
		{"author sig invalid", ErrAuthorSigInvalid, ExitAuthorSigInvalid},
		{"registry not trusted", ErrRegistryNotTrusted, ExitRegistryNotTrusted},
		{"governance below min", ErrGovernanceBelowMin, ExitGovernanceBelowMin},
		{"deps unsatisfied", ErrDepsUnsatisfied, ExitDepsUnsatisfied},
		{"blob missing", ErrBlobMissing, ExitBlobMissing},
		{"intent inconsistent", ErrIntentInconsistent, ExitIntentInconsistent},
		{"identity mismatch", ErrIdentityMismatch, ExitIdentityMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.err); got != tc.want {
				t.Errorf("ExitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestExitCode_Wrapped(t *testing.T) {
	// Wrapping with %w is the standard pattern callers will use to add
	// context. ExitCode must see through arbitrary wrapping depth.
	wrapped := fmt.Errorf("verify step 3: %w", ErrDigestMismatch)
	if got := ExitCode(wrapped); got != ExitDigestMismatch {
		t.Errorf("wrapped ErrDigestMismatch → %d, want %d", got, ExitDigestMismatch)
	}

	// Doubly wrapped: survives.
	doubled := fmt.Errorf("install: %w", wrapped)
	if got := ExitCode(doubled); got != ExitDigestMismatch {
		t.Errorf("double-wrapped → %d, want %d", got, ExitDigestMismatch)
	}
}

func TestExitCode_Unknown(t *testing.T) {
	// Any error not matching a sentinel maps to 1 (generic).
	other := errors.New("unrelated")
	if got := ExitCode(other); got != 1 {
		t.Errorf("ExitCode(unknown) = %d, want 1", got)
	}
}

func TestExitCode_DistinctNumbers(t *testing.T) {
	// Defensive check: each sentinel maps to a unique number. If a
	// future maintainer collapses two codes by accident this catches it.
	codes := map[int]string{}
	for _, sent := range []struct {
		err  error
		name string
	}{
		{ErrDigestMismatch, "digest"},
		{ErrAuthorSigInvalid, "author"},
		{ErrRegistryNotTrusted, "registry"},
		{ErrGovernanceBelowMin, "governance"},
		{ErrDepsUnsatisfied, "deps"},
		{ErrBlobMissing, "blob"},
	} {
		c := ExitCode(sent.err)
		if other, dup := codes[c]; dup {
			t.Errorf("collision: code %d used by both %s and %s", c, other, sent.name)
		}
		codes[c] = sent.name
	}
	if len(codes) != 6 {
		t.Errorf("expected 6 distinct codes, got %d", len(codes))
	}
}
