package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeKitBundleName(t *testing.T) {
	for _, name := range []string{"demo@1.0.0.skb", "Demo_1+test-2.skb"} {
		if !safeKitBundleName(name) {
			t.Errorf("safe name rejected: %q", name)
		}
	}
	for _, name := range []string{"../demo.skb", `a\b.skb`, "a:b.skb", "$(touch pwned).skb", "`id`.skb", `a".skb`, "a\n.skb", "CON.skb", "lpt1.skb", ".skb", "demo.skb "} {
		if safeKitBundleName(name) {
			t.Errorf("unsafe name accepted: %q", name)
		}
	}
}

func TestExportKitRejectsScriptFilename(t *testing.T) {
	f := buildBundleFixture(t)
	bad := filepath.Join(t.TempDir(), "$(touch pwned).skb")
	for src, dst := range map[string]string{f.skbPath: bad, f.metaPath: defaultMetaSidecar(bad)} {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	kit := filepath.Join(t.TempDir(), "kit")
	var out, stderr bytes.Buffer
	if code := runExportKit([]string{"--bundle", bad, "--trust-roots", f.trPath, "--out", kit}, &out, &stderr); code != exitGeneric {
		t.Fatalf("code %d: %s", code, &stderr)
	}
	if _, err := os.Stat(kit); !os.IsNotExist(err) {
		t.Fatalf("unsafe name created output: %v", err)
	}
}

func TestWriteNewKitFilePreservesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeNewKitFile(root, "bundle.skb", []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeNewKitFile(root, "bundle.skb", []byte("replacement"), 0644); !errors.Is(err, os.ErrExist) {
		t.Fatalf("want existence error, got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "bundle.skb"))
	if err != nil || string(got) != "original" {
		t.Fatalf("original changed: %q %v", got, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.skb")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.skb")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeNewKitFile(root, "link.skb", []byte("replacement"), 0644); err == nil {
		t.Fatal("symlink accepted")
	}
	got, err = os.ReadFile(outside)
	if err != nil || string(got) != "outside" {
		t.Fatalf("symlink target changed: %q %v", got, err)
	}
}

func TestExportKitZipExcludesUnrelatedFiles(t *testing.T) {
	f := buildBundleFixture(t)
	kit := filepath.Join(t.TempDir(), "kit")
	if err := os.Mkdir(kit, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kit, "unrelated-secret.txt"), []byte("not for publication"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := runExportKit([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--out", kit, "--zip"}, &out, &stderr); code != exitOK {
		t.Fatalf("code %d: %s", code, &stderr)
	}
	zr, err := zip.OpenReader(kit + ".zip")
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 5 {
		t.Fatalf("want five generated files, got %d", len(zr.File))
	}
	for _, f := range zr.File {
		if f.Name == "unrelated-secret.txt" {
			t.Fatal("unrelated file leaked into archive")
		}
		if f.Name == "verify.sh" && f.Mode().Perm() != 0755 {
			t.Fatalf("script mode %v", f.Mode())
		}
	}
}

func TestZipKitFilesPreservesExistingArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "kit.zip")
	if err := os.WriteFile(archive, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := zipKitFiles(map[string][]byte{"bundle.skb": []byte("bundle")}, archive); !errors.Is(err, os.ErrExist) {
		t.Fatalf("want collision error, got %v", err)
	}
	got, err := os.ReadFile(archive)
	if err != nil || string(got) != "original" {
		t.Fatalf("archive changed: %q %v", got, err)
	}
	link := filepath.Join(dir, "link.zip")
	if err := os.Symlink(archive, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := zipKitFiles(map[string][]byte{"bundle.skb": []byte("bundle")}, link); err == nil {
		t.Fatal("symlink archive accepted")
	}
	got, err = os.ReadFile(archive)
	if err != nil || string(got) != "original" {
		t.Fatalf("symlink target changed: %q %v", got, err)
	}
}
