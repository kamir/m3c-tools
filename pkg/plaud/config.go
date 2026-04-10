package plaud

import (
	"os"
	"path/filepath"
	"strings"
)

// TranscribeMode controls what happens when Plaud has no transcript for a recording.
type TranscribeMode string

const (
	// TranscribeModeQueue sends DO_TRANSCRIBE=true — server transcribes immediately.
	TranscribeModeQueue TranscribeMode = "queue"
	// TranscribeModeLazy adds todo.transcribe tag — background workers pick it up.
	TranscribeModeLazy TranscribeMode = "lazy"
	// TranscribeModeOff sends no transcription signal — audio stored as-is.
	TranscribeModeOff TranscribeMode = "off"
)

// Config holds Plaud API connection settings.
type Config struct {
	APIURL          string         // Plaud API base URL
	TokenPath       string         // path to session token JSON file
	ContentType     string         // ER1 content-type label for Plaud uploads
	DefaultTags     string         // default tags prepended to every plaud sync upload
	TranscribeMode  TranscribeMode // what to do when Plaud has no transcript (queue|lazy|off)
}

// LoadConfig reads Plaud settings from environment variables with defaults.
func LoadConfig() *Config {
	return &Config{
		APIURL:         envOr("PLAUD_API_URL", "https://api.plaud.ai"),
		TokenPath:      envOr("PLAUD_TOKEN_FILE", defaultTokenPath()),
		ContentType:    envOr("PLAUD_CONTENT_TYPE", "Plaud-Fieldnote"),
		DefaultTags:    os.Getenv("PLAUD_DEFAULT_TAGS"),
		TranscribeMode: parseTranscribeMode(os.Getenv("PLAUD_TRANSCRIBE_MODE")),
	}
}

func parseTranscribeMode(s string) TranscribeMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "queue":
		return TranscribeModeQueue
	case "off":
		return TranscribeModeOff
	default:
		return TranscribeModeLazy
	}
}

func defaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "plaud-session.json")
	}
	return filepath.Join(home, ".m3c-tools", "plaud-session.json")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
