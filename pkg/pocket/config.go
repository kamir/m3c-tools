// Package pocket implements sync for the Pocket USB audio recorder (SPEC-0119).
package pocket

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Config holds Pocket device and staging settings.
type Config struct {
	RecordPath   string   // Device recording dir (default: /Volumes/Pocket/RECORD)
	StagingDir   string   // Local staging root (default: ~/m3c-data/pocket/staging)
	RawDir       string   // Permanent raw archive (default: ~/m3c-data/pocket/raw)
	MergedDir    string   // Merged group output (default: ~/m3c-data/pocket/merged)
	DefaultTags  []string // Default tags for uploads
	ContentType  string   // ER1 content-type label
	WhisperModel string   // Whisper model override
	APIKey       string   // Pocket Cloud API key (Phase 2)
	APIURL       string   // Pocket Cloud API base URL
	SyncMode     string   // "usb" (default) or "api"
}

// LoadConfig reads Pocket config from environment variables with sensible defaults.
func LoadConfig() *Config {
	home, _ := os.UserHomeDir()
	dataRoot := filepath.Join(home, "m3c-data", "pocket")

	cfg := &Config{
		RecordPath:   envOrDefault("POCKET_RECORD_PATH", "/Volumes/Pocket/RECORD"),
		StagingDir:   envOrDefault("POCKET_STAGING_DIR", filepath.Join(dataRoot, "staging")),
		RawDir:       envOrDefault("POCKET_RAW_DIR", filepath.Join(dataRoot, "raw")),
		MergedDir:    envOrDefault("POCKET_MERGED_DIR", filepath.Join(dataRoot, "merged")),
		ContentType:  envOrDefault("POCKET_CONTENT_TYPE", "Pocket-Fieldnote"),
		// SPEC-0175 P2: POCKET_WHISPER_MODEL overrides M3C_WHISPER_MODEL for
		// Pocket recordings only. The fallback to M3C_WHISPER_MODEL is
		// intentional — it lets a user configure Whisper once globally
		// (in preferences.env) and have it apply to all sources.
		WhisperModel: envOrDefault("POCKET_WHISPER_MODEL", os.Getenv("M3C_WHISPER_MODEL")),
		APIKey:       os.Getenv("POCKET_API_KEY"),
		// SPEC-0175 P1: single source of truth — DefaultAPIBaseURL is the
		// canonical default (was duplicated in 3 files until this commit).
		APIURL:       envOrDefault("POCKET_API_URL", DefaultAPIBaseURL),
		// SPEC-0174 §3.1: empty = auto-detect via Mode().
		// Honoured values: "usb" (force USB-only opt-out), unset/"" (auto).
		SyncMode:     os.Getenv("POCKET_SYNC_MODE"),
	}

	// SPEC-0175 P1: warn when POCKET_SYNC_MODE is set to "api" — that value
	// is now a no-op (auto-detect supersedes it). The user likely copied
	// this from old docs / .env.example. Tell them once and move on.
	if rawMode := os.Getenv("POCKET_SYNC_MODE"); rawMode == "api" {
		log.Printf("[pocket] POCKET_SYNC_MODE=api is deprecated and ignored — auto-detect from POCKET_API_KEY presence (SPEC-0174 §3.1). Remove the env var to silence this warning.")
	}

	tagsStr := envOrDefault("POCKET_DEFAULT_TAGS", "pocket,fieldnote,Pocket Audio-Tracker")
	for _, t := range strings.Split(tagsStr, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			cfg.DefaultTags = append(cfg.DefaultTags, t)
		}
	}

	return cfg
}

// IsDeviceConnected checks if the Pocket recording directory exists and is readable.
//
// Future: fsnotify could watch /Volumes/ for mount/unmount events to provide
// instant device detection without polling. For now, the periodic menu label
// refresh in the menubar handles device connect/disconnect detection. See
// SPEC-0119 Section 5 (Device Detection) for the planned fsnotify approach.
func (c *Config) IsDeviceConnected() bool {
	info, err := os.Stat(c.RecordPath)
	return err == nil && info.IsDir()
}

// IsAPIMode returns true if API mode is active per Mode().
func (c *Config) IsAPIMode() bool {
	m := c.Mode()
	return m == ModeAPI || m == ModeBoth
}

// SyncModeKind enumerates the runtime-resolved Pocket sync modes (SPEC-0174 §3.1).
type SyncModeKind string

const (
	// ModeOff means neither cloud credentials nor a USB device are present.
	ModeOff SyncModeKind = "off"
	// ModeAPI means the cloud-API path is active (POCKET_API_KEY is set).
	ModeAPI SyncModeKind = "api"
	// ModeUSB means a Pocket USB volume is mounted and no cloud key is set.
	ModeUSB SyncModeKind = "usb"
	// ModeBoth means cloud credentials AND a USB volume are present — both
	// paths are offered to the user via the menubar (SPEC-0174 §3.4).
	ModeBoth SyncModeKind = "both"
)

// Mode resolves the active Pocket sync mode at call time. SPEC-0174 §3.1:
// drop the POCKET_SYNC_MODE env var as a hard switch; auto-detect from
// credentials + device presence. POCKET_SYNC_MODE=usb is still honoured as
// an explicit opt-out of cloud mode for users who want USB-only behaviour.
func (c *Config) Mode() SyncModeKind {
	hasKey := c.APIKey != ""
	hasUSB := c.IsDeviceConnected()
	// Explicit opt-out: POCKET_SYNC_MODE=usb forces USB even if a key is set.
	if c.SyncMode == "usb" {
		if hasUSB {
			return ModeUSB
		}
		return ModeOff
	}
	switch {
	case hasKey && hasUSB:
		return ModeBoth
	case hasKey:
		return ModeAPI
	case hasUSB:
		return ModeUSB
	default:
		return ModeOff
	}
}

// EnsureDirs creates the staging, raw, and merged directories if they don't exist.
func (c *Config) EnsureDirs() error {
	for _, dir := range []string{c.StagingDir, c.RawDir, c.MergedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
