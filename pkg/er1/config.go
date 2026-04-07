// Package er1 handles ER1 server configuration, multipart uploads,
// and offline retry queuing.
package er1

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	cfg := &Config{
		APIURL:        envOr("ER1_API_URL", "https://127.0.0.1:8081/upload_2"),
		APIKey:        os.Getenv("ER1_API_KEY"),
		ContextID:     envOr("ER1_CONTEXT_ID", "107677460544181387647___mft"),
		ContentType:   envOr("ER1_CONTENT_TYPE", "YouTube-Video-Impression"),
		UploadTimeout: envInt("ER1_UPLOAD_TIMEOUT", 600),
		VerifySSL:     envBool("ER1_VERIFY_SSL", true),
		RetryInterval: envInt("ER1_RETRY_INTERVAL", 300),
		MaxRetries:    envInt("ER1_MAX_RETRIES", 10),
	}
	// BUG-0093 + SPEC-0143: Only warn when NO auth is available.
	// Device token (SPEC-0127) is the primary auth method; API key is fallback for dev/CI.
	if cfg.APIKey == "" && os.Getenv("ER1_DEVICE_TOKEN") == "" {
		log.Println("[er1] WARNING: No authentication configured — log in with 'm3c-tools login' or set ER1_API_KEY in your profile.")
	}
	return cfg
}

// AuthHeaders returns HTTP headers for ER1 authentication.
// Prefers device token (Bearer) over API key (SPEC-0127).
func (c *Config) AuthHeaders() map[string]string {
	h := map[string]string{}
	if token := os.Getenv("ER1_DEVICE_TOKEN"); token != "" {
		h["Authorization"] = "Bearer " + token
	} else if c.APIKey != "" {
		h["X-API-KEY"] = c.APIKey
	}
	if c.ContextID != "" {
		h["X-Context-ID"] = c.ContextID
	}
	return h
}

// HealthCheck validates ER1 connectivity and authentication by sending a GET request
// to the ER1 base URL. Accepts device token (Bearer) or API key (X-API-KEY).
// Returns nil if the server is reachable and the credentials are accepted.
func (c *Config) HealthCheck() error {
	if c.APIKey == "" && os.Getenv("ER1_DEVICE_TOKEN") == "" {
		return fmt.Errorf("no authentication configured (no device token, no API key)")
	}
	// Derive base URL from upload URL (strip /upload_2 suffix).
	baseURL := c.APIURL
	if idx := strings.LastIndex(baseURL, "/upload"); idx > 0 {
		baseURL = baseURL[:idx]
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if !c.VerifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", baseURL+"/api/plm/projects", nil)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	for k, v := range c.AuthHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ER1 server unreachable: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("ER1 API key is invalid or expired (HTTP 401)")
	case http.StatusForbidden:
		return fmt.Errorf("ER1 API key is rejected (HTTP 403)")
	default:
		return fmt.Errorf("ER1 health check returned HTTP %d", resp.StatusCode)
	}
}

// Summary returns a human-readable one-liner for logging.
func (c *Config) Summary() string {
	authInfo := "(none)"
	if token := os.Getenv("ER1_DEVICE_TOKEN"); token != "" {
		authInfo = "device-token"
	} else if c.APIKey != "" {
		authInfo = fmt.Sprintf("api-key(%d chars)", len(c.APIKey))
	}
	return fmt.Sprintf("ER1 -> %s auth=%s ctx=%s timeout=%ds ssl=%v",
		c.APIURL, authInfo, c.ContextID, c.UploadTimeout, c.VerifySSL)
}

// LoadDotenv loads a .env file into os.Environ (does not override existing vars).
func LoadDotenv(path string) error {
	info, statErr := os.Stat(path)
	if statErr != nil {
		return statErr
	}
	if info.Mode().Perm()&0077 != 0 {
		fmt.Fprintf(os.Stderr, "Warning: %s has permissive permissions (%04o). Consider: chmod 600 %s\n",
			path, info.Mode().Perm(), path)
	}

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
		// Strip surrounding quotes
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
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

// WriteConfig writes ER1 and Plaud configuration to ~/.m3c-tools.env.
// It creates or overwrites the file with 0600 permissions.
func WriteConfig(apiURL, apiKey, contextID string, verifySSL bool, defaultTags string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	path := filepath.Join(home, ".m3c-tools.env")

	now := time.Now().Format("2006-01-02")
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by m3c-tools setup on %s\n", now)
	fmt.Fprintf(&b, "ER1_API_URL=%s\n", apiURL)
	fmt.Fprintf(&b, "ER1_API_KEY=%s\n", apiKey)
	fmt.Fprintf(&b, "ER1_CONTEXT_ID=%s\n", contextID)
	fmt.Fprintf(&b, "ER1_VERIFY_SSL=%v\n", verifySSL)
	b.WriteString("\n# Plaud sync defaults\n")
	fmt.Fprintf(&b, "PLAUD_DEFAULT_TAGS=%s\n", defaultTags)

	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// ConfigPath returns the path to ~/.m3c-tools.env.
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".m3c-tools.env")
}
