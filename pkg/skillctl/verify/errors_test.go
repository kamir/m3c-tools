package verify

import (
	"errors"
	"fmt"
	"testing"
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

	// Doubly wrapped — survives.
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
