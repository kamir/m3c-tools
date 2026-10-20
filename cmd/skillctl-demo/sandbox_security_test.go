package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sandboxTestHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestSandboxRejectsEscapingSkillNames(t *testing.T) {
	sandboxTestHome(t)
	sb := &Sandbox{Base: t.TempDir()}
	sb.Home = filepath.Join(sb.Base, "home")
	for _, name := range []string{"", ".", "..", "../escape", "/escape", `..\escape`, "a/b", "a\nb"} {
		if err := sb.installManaged(name); err == nil {
			t.Errorf("installManaged(%q) accepted invalid name", name)
		}
		if err := sb.placeUnverified(name); err == nil {
			t.Errorf("placeUnverified(%q) accepted invalid name", name)
		}
	}
	entries, err := os.ReadDir(sb.Base)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid names modified sandbox: %v, %v", entries, err)
	}
}

func TestSandboxCopyConfinesSourceAndDestination(t *testing.T) {
	sandboxTestHome(t)
	sb := &Sandbox{Base: t.TempDir()}
	outside := t.TempDir()
	source := filepath.Join(sb.Base, "source")
	if err := os.WriteFile(source, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(outsideFile, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sb.copyFile(source, outsideFile); err == nil {
		t.Fatal("copy accepted destination outside sandbox")
	}
	if err := sb.copyFile(outsideFile, filepath.Join(sb.Base, "outside-copy")); err == nil {
		t.Fatal("copy accepted source outside sandbox")
	}
	destination := filepath.Join(sb.Base, "nested", "copy")
	if err := sb.copyFile(source, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "fixture" {
		t.Fatalf("copied content = %q, %v", content, err)
	}
	if err := os.Symlink(outside, filepath.Join(sb.Base, "escape")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := sb.copyFile(source, filepath.Join(sb.Base, "escape", "sentinel")); err == nil {
		t.Fatal("copy followed destination symlink outside sandbox")
	}
	if err := sb.copyFile(filepath.Join(sb.Base, "escape", "sentinel"), destination); err == nil {
		t.Fatal("copy followed source symlink outside sandbox")
	}
	content, err = os.ReadFile(outsideFile)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("outside sentinel changed: %q, %v", content, err)
	}
}

func TestSandboxInstallRejectsEscapingSkillDirectory(t *testing.T) {
	sandboxTestHome(t)
	sb, err := NewSandbox()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sb.Cleanup)
	if err := sb.wipeSkills(); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(sb.skillsDir(), demoSkillName)); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := sb.installManaged(demoSkillName); err == nil {
		t.Fatal("install followed skill directory symlink outside sandbox")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("installation wrote outside sandbox: %v, %v", entries, err)
	}
}

func TestSandboxInstallAndCopyDoNotOverwriteHardlinks(t *testing.T) {
	sandboxTestHome(t)
	sb, err := NewSandbox()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sb.Cleanup)
	outside := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		filepath.Join(sb.Base, "install", demoSkillName+".skb"),
		filepath.Join(sb.skillsDir(), demoSkillName, demoSkillName+".skb"),
	} {
		if err := sb.wipeSkills(); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Link(outside, target); err != nil {
			t.Skipf("hardlinks unavailable: %v", err)
		}
		// A stale intermediate bundle is unused; a planted final bundle is
		// rejected. Either way, the outside inode must remain untouched.
		_ = sb.installManaged(demoSkillName)
		content, err := os.ReadFile(outside)
		if err != nil || string(content) != "unchanged" {
			t.Fatalf("install changed hardlink target: %q, %v", content, err)
		}
	}
	copyTarget := filepath.Join(sb.Base, "copy-hardlink")
	if err := os.Link(outside, copyTarget); err != nil {
		t.Fatal(err)
	}
	if err := sb.copyFile(sb.GoodMeta, copyTarget); err == nil {
		t.Fatal("copy accepted existing hardlink")
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("copy changed hardlink target: %q, %v", content, err)
	}
}
