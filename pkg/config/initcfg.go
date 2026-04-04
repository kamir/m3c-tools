// Package config — Init Config Bootstrap
//
// On first start, m3c-tools looks for ~/m3c-tools.init.cfg — a file sent
// by the admin as an email attachment. If found, it auto-configures the
// user's profile and deletes the init file (one-time bootstrap).
//
// File format (simple key=value, same as .env):
//
//   # m3c-tools configuration — sent by your admin
//   ER1_API_URL=https://onboarding.guide/upload_2
//   ER1_API_KEY=kup-abc123def456
//   ER1_CONTEXT_ID=
//   PROFILE_NAME=cloud
//
// The ER1_CONTEXT_ID is intentionally blank — it gets filled in after
// the user signs in with Google (OAuth callback sets it).
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	// InitCfgFilename is the file users drop in their home directory.
	InitCfgFilename = "m3c-tools.init.cfg"

	// InitCfgConsumedSuffix is appended after successful import.
	InitCfgConsumedSuffix = ".imported"
)

// InitCfgResult describes what happened when checking for an init config.
type InitCfgResult struct {
	Found       bool
	ProfileName string
	Imported    bool
	Error       error
}

// CheckAndApplyInitCfg looks for ~/m3c-tools.init.cfg and, if found,
// creates/updates a profile from its contents. After successful import,
// the file is renamed to ~/m3c-tools.init.cfg.imported so it's not
// re-processed on next start.
//
// Returns a result describing what happened. Safe to call every startup.
func CheckAndApplyInitCfg() InitCfgResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return InitCfgResult{Error: fmt.Errorf("cannot find home dir: %w", err)}
	}

	initPath := filepath.Join(home, InitCfgFilename)

	// Check if init file exists
	if _, err := os.Stat(initPath); os.IsNotExist(err) {
		return InitCfgResult{Found: false}
	}

	log.Printf("[config] found init config at %s", initPath)

	// Parse the init file
	profile, err := ParseEnvFile(initPath)
	if err != nil {
		return InitCfgResult{Found: true, Error: fmt.Errorf("parse init config: %w", err)}
	}

	// Determine profile name (default: "cloud")
	profileName := "cloud"
	if name, ok := profile.Vars["PROFILE_NAME"]; ok && strings.TrimSpace(name) != "" {
		profileName = strings.TrimSpace(name)
		delete(profile.Vars, "PROFILE_NAME") // Don't store meta-field in profile
	}

	// Fill defaults for any missing fields
	defaults := map[string]string{
		"ER1_API_URL":        "https://onboarding.guide/upload_2",
		"ER1_CONTENT_TYPE":   "YouTube-Video-Impression",
		"ER1_UPLOAD_TIMEOUT": "600",
		"ER1_VERIFY_SSL":     "true",
		"ER1_RETRY_INTERVAL": "300",
		"ER1_MAX_RETRIES":    "10",
	}
	for k, v := range defaults {
		if _, exists := profile.Vars[k]; !exists {
			profile.Vars[k] = v
		}
	}

	// Create/update the profile
	pm := NewProfileManager()
	if err := pm.EnsureDefaults(); err != nil {
		return InitCfgResult{Found: true, Error: fmt.Errorf("ensure defaults: %w", err)}
	}

	desc := "Configured via init file"
	if err := pm.CreateProfile(profileName, desc, profile.Vars); err != nil {
		return InitCfgResult{Found: true, ProfileName: profileName, Error: fmt.Errorf("create profile: %w", err)}
	}

	// Switch to this profile
	if err := pm.SwitchProfile(profileName); err != nil {
		log.Printf("[config] warning: could not switch to profile %s: %v", profileName, err)
	}

	// Apply to current process
	for k, v := range profile.Vars {
		os.Setenv(k, v)
	}

	// Rename init file so it's not re-processed
	consumedPath := initPath + InitCfgConsumedSuffix
	if err := os.Rename(initPath, consumedPath); err != nil {
		log.Printf("[config] warning: could not rename init config: %v", err)
		// Not fatal — profile was created successfully
	} else {
		log.Printf("[config] init config consumed: %s -> %s", initPath, consumedPath)
	}

	log.Printf("[config] profile '%s' created from init config with %d vars", profileName, len(profile.Vars))

	return InitCfgResult{
		Found:       true,
		ProfileName: profileName,
		Imported:    true,
	}
}

// GenerateInitCfg creates an init config file for a customer.
// Used by admins: m3c-tools admin generate-config --user-id X --api-key Y
func GenerateInitCfg(apiKey, serverURL, profileName string) string {
	if serverURL == "" {
		serverURL = "https://onboarding.guide/upload_2"
	}
	if profileName == "" {
		profileName = "cloud"
	}

	return fmt.Sprintf(`# m3c-tools configuration
# Save this file as: m3c-tools.init.cfg in your home folder
# Windows: C:\Users\YourName\m3c-tools.init.cfg
# macOS:   /Users/YourName/m3c-tools.init.cfg
#
# Then start m3c-tools — it will configure itself automatically.

PROFILE_NAME=%s
ER1_API_URL=%s
ER1_API_KEY=%s
ER1_CONTENT_TYPE=YouTube-Video-Impression
ER1_UPLOAD_TIMEOUT=600
ER1_VERIFY_SSL=true
`, profileName, serverURL, apiKey)
}
