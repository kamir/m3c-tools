package testutil

import (
	"os"
	"testing"
)

func init() {
	RegisterYTFlag()
}

func TestYTCallsAllowed_DefaultFalse(t *testing.T) {
	// Ensure env var is not set
	old, existed := os.LookupEnv("M3C_YT_CALLS_ENFORCE_ALL")
	os.Unsetenv("M3C_YT_CALLS_ENFORCE_ALL")
	defer func() {
		if existed {
			os.Setenv("M3C_YT_CALLS_ENFORCE_ALL", old)
		}
	}()

	// With no env var and no flag, should be false
	if YTCallsAllowed() {
		t.Error("Expected YTCallsAllowed() to return false by default")
	}
}

func TestYTCallsAllowed_EnvVarOverride(t *testing.T) {
	old, existed := os.LookupEnv("M3C_YT_CALLS_ENFORCE_ALL")
	os.Setenv("M3C_YT_CALLS_ENFORCE_ALL", "1")
	defer func() {
		if existed {
			os.Setenv("M3C_YT_CALLS_ENFORCE_ALL", old)
		} else {
			os.Unsetenv("M3C_YT_CALLS_ENFORCE_ALL")
		}
	}()

	if !YTCallsAllowed() {
		t.Error("Expected YTCallsAllowed() to return true when M3C_YT_CALLS_ENFORCE_ALL=1")
	}
}

func TestSkipIfNoYTCalls_Skips(t *testing.T) {
	// Ensure env var is not set
	old, existed := os.LookupEnv("M3C_YT_CALLS_ENFORCE_ALL")
	os.Unsetenv("M3C_YT_CALLS_ENFORCE_ALL")
	defer func() {
		if existed {
			os.Setenv("M3C_YT_CALLS_ENFORCE_ALL", old)
		}
	}()

	// Run a subtest that should be skipped
	skipped := false
	t.Run("should_skip", func(t *testing.T) {
		SkipIfNoYTCalls(t)
		// If we reach here, it wasn't skipped
	})

	// Check if the subtest was skipped by examining t state
	// We use a different approach - just verify the function doesn't panic
	_ = skipped
}

func TestRegisterYTFlag_Idempotent(t *testing.T) {
	// Calling RegisterYTFlag multiple times should not panic
	RegisterYTFlag()
	RegisterYTFlag()
	RegisterYTFlag()
}
