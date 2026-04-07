package plaud

import (
	"os"
	"path/filepath"
)

// Config holds Plaud API connection settings.
type Config struct {
	APIURL      string // Plaud API base URL
	TokenPath   string // path to session token JSON file
	ContentType string // ER1 content-type label for Plaud uploads
	DefaultTags string // default tags prepended to every plaud sync upload
}

// LoadConfig reads Plaud settings from environment variables with defaults.
func LoadConfig() *Config {
	return &Config{
		APIURL:      envOr("PLAUD_API_URL", "https://api.plaud.ai"),
		TokenPath:   envOr("PLAUD_TOKEN_FILE", defaultTokenPath()),
		ContentType: envOr("PLAUD_CONTENT_TYPE", "Plaud-Fieldnote"),
		DefaultTags: os.Getenv("PLAUD_DEFAULT_TAGS"),
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
