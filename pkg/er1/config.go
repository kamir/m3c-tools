// Package er1 handles ER1 server configuration, multipart uploads,
// and offline retry queuing.
package er1

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds ER1 server connection settings, loaded from environment variables.
type Config struct {
	APIURL        string // ER1 upload endpoint (default: https://127.0.0.1:8081/upload_2)
	APIKey        string // X-API-KEY header value
	ContextID     string // context_id form field
	ContentType   string // content_type form field
	UploadTimeout int    // HTTP timeout in seconds
	VerifySSL     bool   // whether to verify TLS certificates
	RetryInterval int    // seconds between retry cycles
	MaxRetries    int    // max retry attempts before dropping
}

// LoadConfig reads ER1 settings from environment variables.
func LoadConfig() *Config {
	return &Config{
		APIURL:        envOr("ER1_API_URL", "https://127.0.0.1:8081/upload_2"),
		APIKey:        os.Getenv("ER1_API_KEY"),
		ContextID:     envOr("ER1_CONTEXT_ID", "107677460544181387647___mft"),
		ContentType:   envOr("ER1_CONTENT_TYPE", "YouTube-Video-Impression"),
		UploadTimeout: envInt("ER1_UPLOAD_TIMEOUT", 600),
		VerifySSL:     envBool("ER1_VERIFY_SSL", false),
		RetryInterval: envInt("ER1_RETRY_INTERVAL", 300),
		MaxRetries:    envInt("ER1_MAX_RETRIES", 10),
	}
}

// AuthHeaders returns HTTP headers with X-API-KEY if configured.
func (c *Config) AuthHeaders() map[string]string {
	h := map[string]string{}
	if c.APIKey != "" {
		h["X-API-KEY"] = c.APIKey
	}
	return h
}

// Summary returns a human-readable one-liner for logging.
func (c *Config) Summary() string {
	masked := "(none)"
	if len(c.APIKey) > 4 {
		masked = c.APIKey[:4] + "..."
	}
	return fmt.Sprintf("ER1 -> %s key=%s ctx=%s timeout=%ds",
		c.APIURL, masked, c.ContextID, c.UploadTimeout)
}

// LoadDotenv loads a .env file into os.Environ (does not override existing vars).
func LoadDotenv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(os.Getenv(key))
	switch v {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return fallback
}
