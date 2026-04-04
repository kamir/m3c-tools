package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAndApplyInitCfg_NoFile(t *testing.T) {
	// With no init file, should return Found=false
	result := CheckAndApplyInitCfg()
	if result.Found {
		t.Error("expected Found=false when no init file exists")
	}
}

func TestCheckAndApplyInitCfg_ValidFile(t *testing.T) {
	home, _ := os.UserHomeDir()
	initPath := filepath.Join(home, InitCfgFilename)
	consumedPath := initPath + InitCfgConsumedSuffix

	// Clean up before and after
	os.Remove(initPath)
	os.Remove(consumedPath)
	defer os.Remove(initPath)
	defer os.Remove(consumedPath)

	// Write a test init config
	content := `# Test init config
PROFILE_NAME=test-customer
ER1_API_URL=https://test.example.com/upload_2
ER1_API_KEY=test-key-abc123
`
	if err := os.WriteFile(initPath, []byte(content), 0600); err != nil {
		t.Fatalf("write init config: %v", err)
	}

	result := CheckAndApplyInitCfg()
	if !result.Found {
		t.Error("expected Found=true")
	}
	if !result.Imported {
		t.Errorf("expected Imported=true, got error: %v", result.Error)
	}
	if result.ProfileName != "test-customer" {
		t.Errorf("ProfileName = %q, want test-customer", result.ProfileName)
	}

	// Init file should be renamed
	if _, err := os.Stat(initPath); !os.IsNotExist(err) {
		t.Error("init file should have been renamed")
	}
	if _, err := os.Stat(consumedPath); os.IsNotExist(err) {
		t.Error("consumed file should exist")
	}

	// Env vars should be set
	if os.Getenv("ER1_API_KEY") != "test-key-abc123" {
		t.Errorf("ER1_API_KEY = %q, want test-key-abc123", os.Getenv("ER1_API_KEY"))
	}

	// Profile should exist
	pm := NewProfileManager()
	profile, err := pm.GetProfile("test-customer")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if profile.Vars["ER1_API_URL"] != "https://test.example.com/upload_2" {
		t.Errorf("ER1_API_URL = %q", profile.Vars["ER1_API_URL"])
	}

	// Clean up profile
	pm.DeleteProfile("test-customer")
}

func TestCheckAndApplyInitCfg_DefaultsApplied(t *testing.T) {
	home, _ := os.UserHomeDir()
	initPath := filepath.Join(home, InitCfgFilename)
	consumedPath := initPath + InitCfgConsumedSuffix
	os.Remove(initPath)
	os.Remove(consumedPath)
	defer os.Remove(initPath)
	defer os.Remove(consumedPath)

	// Minimal init file — only API key, everything else should get defaults
	content := "ER1_API_KEY=minimal-key\n"
	os.WriteFile(initPath, []byte(content), 0600)

	result := CheckAndApplyInitCfg()
	if !result.Imported {
		t.Fatalf("import failed: %v", result.Error)
	}
	// Should default to "cloud" profile
	if result.ProfileName != "cloud" {
		t.Errorf("ProfileName = %q, want cloud", result.ProfileName)
	}

	pm := NewProfileManager()
	profile, _ := pm.GetProfile("cloud")
	if profile.Vars["ER1_VERIFY_SSL"] != "true" {
		t.Error("default ER1_VERIFY_SSL should be true")
	}
	if profile.Vars["ER1_API_URL"] != "https://onboarding.guide/upload_2" {
		t.Error("default ER1_API_URL should be onboarding.guide")
	}
}

func TestGenerateInitCfg(t *testing.T) {
	cfg := GenerateInitCfg("customer-key-xyz", "https://custom.server/upload_2", "kup-berlin")

	if !strings.Contains(cfg, "ER1_API_KEY=customer-key-xyz") {
		t.Error("missing API key")
	}
	if !strings.Contains(cfg, "PROFILE_NAME=kup-berlin") {
		t.Error("missing profile name")
	}
	if !strings.Contains(cfg, "https://custom.server/upload_2") {
		t.Error("missing server URL")
	}
	if !strings.Contains(cfg, "m3c-tools.init.cfg") {
		t.Error("missing save instructions")
	}
}

func TestCheckAndApplyInitCfg_NotReprocessed(t *testing.T) {
	home, _ := os.UserHomeDir()
	initPath := filepath.Join(home, InitCfgFilename)
	consumedPath := initPath + InitCfgConsumedSuffix
	os.Remove(initPath)
	os.Remove(consumedPath)
	defer os.Remove(initPath)
	defer os.Remove(consumedPath)

	content := "ER1_API_KEY=once-only\nPROFILE_NAME=once-test\n"
	os.WriteFile(initPath, []byte(content), 0600)

	// First call imports
	r1 := CheckAndApplyInitCfg()
	if !r1.Imported {
		t.Fatal("first import should succeed")
	}

	// Second call should find nothing (file renamed)
	r2 := CheckAndApplyInitCfg()
	if r2.Found {
		t.Error("second call should not find init file")
	}

	NewProfileManager().DeleteProfile("once-test")
}
