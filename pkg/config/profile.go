// Package config provides configuration profile management for m3c-tools.
//
// Profiles are .env files stored in ~/.m3c-tools/profiles/ that contain
// ER1 connection settings and other environment variables. One profile
// is active at a time, recorded in ~/.m3c-tools/active-profile.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// ProfilesDir is the subdirectory under BaseDir that holds profile .env files.
	ProfilesDir = "profiles"

	// ActiveProfileFile is the filename that stores the currently active profile name.
	ActiveProfileFile = "active-profile"
)

// Profile represents a named configuration profile loaded from a .env file.
type Profile struct {
	Name        string            // profile name (filename stem, e.g. "dev")
	Description string            // from "# Description:" comment header
	Vars        map[string]string // key=value pairs from the .env file
	Path        string            // full path to the .env file
}

// ProfileManager provides operations on the profile directory under BaseDir.
type ProfileManager struct {
	BaseDir string // typically ~/.m3c-tools/
}

// NewProfileManager creates a ProfileManager rooted at ~/.m3c-tools/.
func NewProfileManager() *ProfileManager {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return &ProfileManager{
		BaseDir: filepath.Join(home, ".m3c-tools"),
	}
}

// profilesDir returns the full path to the profiles directory.
func (pm *ProfileManager) profilesDir() string {
	return filepath.Join(pm.BaseDir, ProfilesDir)
}

// activeProfilePath returns the full path to the active-profile file.
func (pm *ProfileManager) activeProfilePath() string {
	return filepath.Join(pm.BaseDir, ActiveProfileFile)
}

// EnsureDefaults creates the profiles directory and default profiles if they
// do not already exist. Called lazily on first profile operation.
func (pm *ProfileManager) EnsureDefaults() error {
	dir := pm.profilesDir()
	if _, err := os.Stat(dir); err == nil {
		return nil // already exists
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create profiles dir: %w", err)
	}

	// Create default dev profile.
	devVars := map[string]string{
		"ER1_API_URL":        "https://127.0.0.1:8081/upload_2",
		"ER1_API_KEY":        "democredential-er1-api-key",
		"ER1_CONTEXT_ID":     "107677460544181387647___mft",
		"ER1_CONTENT_TYPE":   "YouTube-Video-Impression",
		"ER1_UPLOAD_TIMEOUT": "600",
		"ER1_VERIFY_SSL":     "false",
		"ER1_RETRY_INTERVAL": "300",
		"ER1_MAX_RETRIES":    "10",
	}
	if err := pm.CreateProfile("dev", "Local Docker development", devVars); err != nil {
		return fmt.Errorf("create dev profile: %w", err)
	}

	// Create default cloud profile.
	cloudVars := map[string]string{
		"ER1_API_URL":        "https://onboarding.guide/upload_2",
		"ER1_API_KEY":        "",
		"ER1_CONTEXT_ID":     "",
		"ER1_CONTENT_TYPE":   "YouTube-Video-Impression",
		"ER1_UPLOAD_TIMEOUT": "600",
		"ER1_VERIFY_SSL":     "true",
		"ER1_RETRY_INTERVAL": "300",
		"ER1_MAX_RETRIES":    "10",
	}
	if err := pm.CreateProfile("cloud", "SaaS cloud", cloudVars); err != nil {
		return fmt.Errorf("create cloud profile: %w", err)
	}

	// Set dev as the default active profile.
	return pm.writeActiveProfile("dev")
}

// ListProfiles scans the profiles directory for *.env files and returns them.
func (pm *ProfileManager) ListProfiles() ([]Profile, error) {
	if err := pm.EnsureDefaults(); err != nil {
		return nil, err
	}

	dir := pm.profilesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read profiles dir: %w", err)
	}

	var profiles []Profile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".env") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".env")
		p, err := pm.GetProfile(name)
		if err != nil {
			continue // skip malformed profiles
		}
		profiles = append(profiles, *p)
	}
	return profiles, nil
}

// GetProfile loads a specific profile by name from the profiles directory.
func (pm *ProfileManager) GetProfile(name string) (*Profile, error) {
	path := filepath.Join(pm.profilesDir(), name+".env")
	return ParseEnvFile(path)
}

// ActiveProfileName reads the active-profile file and returns the profile name.
// Returns empty string if no active profile is set.
func (pm *ProfileManager) ActiveProfileName() string {
	data, err := os.ReadFile(pm.activeProfilePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ActiveProfile loads the currently active profile. Returns an error if no
// active profile is set or the profile file cannot be read.
func (pm *ProfileManager) ActiveProfile() (*Profile, error) {
	name := pm.ActiveProfileName()
	if name == "" {
		return nil, fmt.Errorf("no active profile set")
	}
	return pm.GetProfile(name)
}

// SwitchProfile writes the given name to the active-profile file and applies
// the profile's environment variables to the current process.
// BUG-0089: Added round-trip verification and detailed error logging to
// diagnose silent failures on Windows where file writes may not persist.
func (pm *ProfileManager) SwitchProfile(name string) error {
	p, err := pm.GetProfile(name)
	if err != nil {
		return fmt.Errorf("profile %q not found: %w", name, err)
	}
	if err := pm.writeActiveProfile(name); err != nil {
		return fmt.Errorf("persist profile switch to %q: %w", name, err)
	}
	// Round-trip verification: read back the active-profile file to confirm
	// the write actually landed on disk. This catches Windows NTFS deferred
	// writes and permission issues that os.WriteFile silently swallows.
	readBack := pm.ActiveProfileName()
	if readBack != name {
		return fmt.Errorf("profile switch verification failed: wrote %q but read back %q (path: %s)",
			name, readBack, pm.activeProfilePath())
	}
	return pm.ApplyProfile(p)
}

// ApplyProfile sets all environment variables from the profile using os.Setenv.
// Existing env vars are overwritten to ensure a clean switch.
func (pm *ProfileManager) ApplyProfile(p *Profile) error {
	for k, v := range p.Vars {
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("setenv %s: %w", k, err)
		}
	}
	return nil
}

// CreateProfile writes a new profile .env file to the profiles directory.
func (pm *ProfileManager) CreateProfile(name, description string, vars map[string]string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if err := os.MkdirAll(pm.profilesDir(), 0700); err != nil {
		return fmt.Errorf("create profiles dir: %w", err)
	}

	path := filepath.Join(pm.profilesDir(), name+".env")

	var b strings.Builder
	fmt.Fprintf(&b, "# M3C Profile: %s\n", name)
	fmt.Fprintf(&b, "# Description: %s\n", description)
	fmt.Fprintf(&b, "# Created: %s\n", time.Now().Format("2006-01-02"))
	b.WriteString("\n")

	// Write vars in a stable order: known ER1 keys first, then any extras.
	knownKeys := []string{
		"ER1_API_URL", "ER1_API_KEY", "ER1_CONTEXT_ID", "ER1_CONTENT_TYPE",
		"ER1_UPLOAD_TIMEOUT", "ER1_VERIFY_SSL", "ER1_RETRY_INTERVAL", "ER1_MAX_RETRIES",
		"PLAUD_DEFAULT_TAGS",
	}
	written := map[string]bool{}
	for _, k := range knownKeys {
		if v, ok := vars[k]; ok {
			b.WriteString(fmt.Sprintf("%s=%s\n", k, v))
			written[k] = true
		}
	}
	// Write remaining keys alphabetically.
	for k, v := range vars {
		if !written[k] {
			b.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write profile %q: %w", name, err)
	}
	return nil
}

// DeleteProfile removes a profile file. Returns an error if the profile is
// currently active.
func (pm *ProfileManager) DeleteProfile(name string) error {
	active := pm.ActiveProfileName()
	if active == name {
		return fmt.Errorf("cannot delete active profile %q — switch to another profile first", name)
	}
	path := filepath.Join(pm.profilesDir(), name+".env")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("profile %q does not exist", name)
	}
	return os.Remove(path)
}

// ImportProfile copies an existing .env file into the profiles directory
// under the given name. The file is parsed to validate its format.
func (pm *ProfileManager) ImportProfile(name, envFilePath string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if err := os.MkdirAll(pm.profilesDir(), 0700); err != nil {
		return fmt.Errorf("create profiles dir: %w", err)
	}

	// Parse the source file to extract vars and validate format.
	src, err := ParseEnvFile(envFilePath)
	if err != nil {
		return fmt.Errorf("parse source file: %w", err)
	}

	description := src.Description
	if description == "" {
		description = fmt.Sprintf("Imported from %s", filepath.Base(envFilePath))
	}

	return pm.CreateProfile(name, description, src.Vars)
}

// TestConnection loads ER1 config from the profile's vars and performs a
// health check against the ER1 server.
func (pm *ProfileManager) TestConnection(p *Profile) error {
	// Temporarily apply the profile vars so er1.LoadConfig picks them up.
	// Save and restore original values afterward.
	keys := []string{
		"ER1_API_URL", "ER1_API_KEY", "ER1_CONTEXT_ID",
		"ER1_VERIFY_SSL", "ER1_UPLOAD_TIMEOUT",
	}
	saved := map[string]string{}
	for _, k := range keys {
		saved[k] = os.Getenv(k)
	}
	defer func() {
		for k, v := range saved {
			os.Setenv(k, v)
		}
	}()

	for k, v := range p.Vars {
		os.Setenv(k, v)
	}

	// SPEC-0143: Device token (loaded at startup) provides auth without API key.
	// We only need the URL to test connectivity; auth is handled by the loaded token
	// or the profile's API key if present.
	apiURL := p.Vars["ER1_API_URL"]
	if apiURL == "" {
		return fmt.Errorf("profile %q has no ER1_API_URL", p.Name)
	}

	// Lightweight health check — tests server reachability via /health endpoint.
	// Auth validation happens separately in the doctor/check-er1 commands.
	return healthCheckER1(apiURL, p.Vars["ER1_VERIFY_SSL"])
}

// writeActiveProfile persists the active profile name to disk.
// BUG-0089: Uses explicit file open + sync to ensure data is flushed
// to disk on Windows, where os.WriteFile may not persist immediately.
func (pm *ProfileManager) writeActiveProfile(name string) error {
	if err := os.MkdirAll(pm.BaseDir, 0700); err != nil {
		return fmt.Errorf("create base dir: %w", err)
	}
	path := pm.activeProfilePath()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open active-profile file: %w", err)
	}
	if _, err := f.WriteString(name + "\n"); err != nil {
		f.Close()
		return fmt.Errorf("write active-profile: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync active-profile: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close active-profile: %w", err)
	}
	return nil
}

// ParseEnvFile reads a .env file and extracts the profile metadata and
// key=value pairs. Comment lines starting with "# M3C Profile:" and
// "# Description:" are parsed for metadata.
func ParseEnvFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	p := &Profile{
		Vars: make(map[string]string),
		Path: path,
	}

	// Derive name from filename.
	base := filepath.Base(path)
	p.Name = strings.TrimSuffix(base, filepath.Ext(base))

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Check for metadata comments.
			comment := strings.TrimPrefix(line, "#")
			comment = strings.TrimSpace(comment)
			if strings.HasPrefix(comment, "M3C Profile:") {
				p.Name = strings.TrimSpace(strings.TrimPrefix(comment, "M3C Profile:"))
			} else if strings.HasPrefix(comment, "Description:") {
				p.Description = strings.TrimSpace(strings.TrimPrefix(comment, "Description:"))
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		// Strip surrounding quotes.
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		p.Vars[k] = v
	}

	return p, nil
}

// MaskAPIKey returns a masked version of an API key, showing only the first 4
// and last 4 characters. Keys shorter than 10 characters are fully masked.
func MaskAPIKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	if len(key) < 10 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}
