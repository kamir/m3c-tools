package main

import (
	"io"
	"strings"
	"testing"
)

func TestEnsureBundleRejectsUnsafeSkillName(t *testing.T) {
	_, _, err := ensureBundle(publishAdmitArgs{
		name:    "../../ausbruch",
		version: "1.0.0",
	}, io.Discard)

	if err == nil {
		t.Fatal("ensureBundle accepted unsafe skill name")
	}
	if !strings.Contains(err.Error(), "bad artifact name") {
		t.Fatalf("unexpected error: %v", err)
	}
}
