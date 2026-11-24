// flag_order_test.go: BUG-0450.
//
// Go's flag package stops at the first non-flag argument. `secretctl
// inventory demo --registry <path>` therefore ended with a usage line, while
// `skillctl publish <name> --kind agent` in the same repository accepts flags
// after the name. Both orders must mean the same thing.
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBUG0450_InventoryAcceptsFlagsAfterName(t *testing.T) {
	incompleteTestSource(t, true)
	path := incompleteTestRegistry(t, []Holder{incompleteTestFileHolder(t)}, "")
	for _, args := range [][]string{
		{"--registry", path, "demo"},
		{"demo", "--registry", path},
		{"demo", "--registry=" + path},
	} {
		var stdout, stderr bytes.Buffer
		if code := cmdInventory(args, &stdout, &stderr); code != 0 {
			t.Fatalf("args %q: exit=%d stdout=%s stderr=%s", args, code, &stdout, &stderr)
		}
		if strings.Contains(stdout.String(), syntheticSecret) {
			t.Fatal("secret in inventory output")
		}
	}
}

func TestBUG0450_VerifyAcceptsFlagsAfterName(t *testing.T) {
	incompleteTestSource(t, true)
	path := incompleteTestRegistry(t, []Holder{incompleteTestCloudHolder()}, "http://127.0.0.1:1/")
	// Only the parsing is under test: an unprobed cloud holder ends in 1
	// ("NICHT PRUEFBAR") without any request, a parse failure ends in 2.
	for _, args := range [][]string{
		{"--registry", path, "--old", "demo"},
		{"demo", "--registry", path, "--old"},
		{"demo", "--old", "--registry", path},
	} {
		var stdout, stderr bytes.Buffer
		code := cmdVerify(args, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), "NICHT PRUEFBAR") {
			t.Fatalf("args %q: exit=%d stdout=%s stderr=%s", args, code, &stdout, &stderr)
		}
	}
}

// A second positional is still an error, `--` still ends flag parsing, and
// a value flag without a value is still a usage error.
func TestBUG0450_StrayArgumentsStayUsageErrors(t *testing.T) {
	path := incompleteTestRegistry(t, nil, "")
	for _, args := range [][]string{
		{"demo", "extra", "--registry", path},
		{"--registry", path, "--", "demo", "--old"},
		{"demo", "--no-such-flag"},
		{"demo", "--registry"},
		{"demo", "--old", "--registry"},
		{"--registry"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cmdVerify(args, &stdout, &stderr); code != 2 {
			t.Fatalf("args %q: exit=%d, want 2 (usage)", args, code)
		}
	}
}
