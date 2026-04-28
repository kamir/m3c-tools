// preferences.go — global preferences layer (SPEC-0175 P0 §3 "profile cliff" fix).
//
// The m3c-tools config is layered:
//
//   1. Constants            — hardcoded in Go, never user-set (e.g. default
//                             API URLs, content-type prefixes).
//   2. Global preferences   — settings that DON'T switch with the active
//                             profile because they describe the user's
//                             machine, not their account: Whisper model,
//                             screenshot capture mode, retry behaviour.
//                             Stored at ~/.m3c-tools/preferences.env.
//   3. Active profile       — settings that DO switch when the user picks a
//                             different account: ER1 server URL + auth +
//                             context_id, Plaud session, Pocket API key.
//                             Stored at ~/.m3c-tools/profiles/<name>.env.
//   4. Project .env         — local overrides for development.
//
// This file owns layer (2). It does NOT touch layers (3) or (4) — the
// existing ProfileManager + er1.LoadDotenv handle those.
package config

import (
	"errors"
	"os"
	"path/filepath"
)

// PreferencesPath returns the canonical path to the global preferences file.
// SPEC-0175 P0: this replaces the legacy ~/.m3c-tools.env. The legacy path is
// still read by main.go's startup as a fallback.
func PreferencesPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".m3c-tools", "preferences.env")
}

// LegacyPreferencesPath returns the pre-SPEC-0175 location. Read it on startup
// for back-compat with users who set up before the migration.
func LegacyPreferencesPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".m3c-tools.env")
}

// PreferencesExist returns true if the canonical OR the legacy preferences
// file exists. Used by first-launch detection (SPEC-0175 §3.1).
func PreferencesExist() bool {
	for _, p := range []string{PreferencesPath(), LegacyPreferencesPath()} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// MigrateLegacyPreferences moves ~/.m3c-tools.env → ~/.m3c-tools/preferences.env
// if (a) the legacy file exists, (b) the canonical doesn't yet exist, and
// (c) the parent directory is writable. No-op otherwise.
//
// Returns the path that ended up in use (may be the legacy path if migration
// was skipped or failed) and an error only on hard filesystem failure.
func MigrateLegacyPreferences() (string, error) {
	canonical := PreferencesPath()
	legacy := LegacyPreferencesPath()
	if canonical == "" || legacy == "" {
		return "", errors.New("home directory not resolvable")
	}

	if _, err := os.Stat(canonical); err == nil {
		// Canonical already exists — nothing to migrate.
		return canonical, nil
	}
	if _, err := os.Stat(legacy); err != nil {
		// Legacy doesn't exist either — fresh install. Canonical is the path
		// to use even though it doesn't exist yet (write on first save).
		return canonical, nil
	}

	// Migrate. Create parent dir if missing.
	if err := os.MkdirAll(filepath.Dir(canonical), 0o700); err != nil {
		// Migration failed — fall back to reading the legacy path.
		return legacy, err
	}

	data, err := os.ReadFile(legacy)
	if err != nil {
		return legacy, err
	}
	if err := os.WriteFile(canonical, data, 0o600); err != nil {
		return legacy, err
	}
	// Don't delete the legacy file — leave it as a back-compat read. Annotate
	// it instead so a curious user knows the migration happened.
	annotation := []byte("\n# (Migrated to ~/.m3c-tools/preferences.env on first launch — see SPEC-0175.)\n# This file is still read for back-compat but the canonical location is the new one.\n")
	_ = os.WriteFile(legacy, append(data, annotation...), 0o600)

	return canonical, nil
}
