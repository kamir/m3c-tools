package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBundleDigest(t *testing.T) {
	// 1) explicit --digest wins, verbatim
	if got, err := resolveBundleDigest("sha256:abc", "", "x", "1"); err != nil || got != "sha256:abc" {
		t.Fatalf("digest passthrough: got %q err %v", got, err)
	}

	// 2) --bundle <path> → sha256 of the file
	dir := t.TempDir()
	bp := filepath.Join(dir, "b.skb")
	if err := os.WriteFile(bp, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveBundleDigest("", bp, "x", "1")
	if err != nil || got == "" || got[:7] != "sha256:" {
		t.Fatalf("bundle digest: got %q err %v", got, err)
	}

	// 3) default ./<name>@<version>.skb in CWD (the publish-admit output)
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(dir)
	if err := os.WriteFile("didactic-session@0.1.0.skb", []byte("bundle-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := resolveBundleDigest("", "", "didactic-session", "0.1.0")
	if err != nil || d[:7] != "sha256:" {
		t.Fatalf("default skb digest: got %q err %v", d, err)
	}

	// 4) nothing available → clear error
	if _, err := resolveBundleDigest("", "", "nope", "9.9.9"); err == nil {
		t.Fatal("expected error when no digest/bundle/skb")
	}
}
