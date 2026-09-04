// Package er1 handles ER1 server configuration, multipart uploads,
// and offline retry queuing.
package er1

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/config"
	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

// placeholderFatalOnce ensures the FATAL log for a placeholder ER1_API_KEY
// fires at most once per process, even when LoadConfig() is called from
// multiple startup paths (PLM sync, retry scheduler, menubar init, …).
var placeholderFatalOnce sync.Once

// insecureTLSWarnOnce ensures the SEC-M7 warning about disabled TLS
// verification fires at most once per process, even though LoadConfig() is
// called from many startup paths.
var insecureTLSWarnOnce sync.Once

// isLoopbackURL reports whether the host component of rawURL is a loopback
// address (127.0.0.0/8, ::1, or the literal "localhost"). Self-contained so
// the SEC-M7 fail-closed gate does not depend on helpers in sibling packages.
//
// Pure (no DNS): a hostname that merely *resolves* to loopback is NOT treated
// as loopback, only literal loopback hosts are allowed to skip verification.
func isLoopbackURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// applyTLSVerificationPolicy enforces the SEC-M7 fail-closed rule on a freshly
// loaded Config: when TLS verification is disabled (ER1_VERIFY_SSL=false) it is
// only honoured for a loopback target. For any non-loopback host the request to
// skip verification is REFUSED. Verification is forced back on so every
// downstream HTTP client (10+ call sites all derive from cfg.VerifySSL) stays
// fail-closed. A loud one-time warning is emitted whenever verification is
// (or was about to be) disabled.
func applyTLSVerificationPolicy(cfg *Config) {
	if cfg.VerifySSL {
		return // verification on: nothing to police
	}
	if isLoopbackURL(cfg.APIURL) {
		insecureTLSWarnOnce.Do(func() {
			log.Printf("[er1] WARNING: TLS verification is DISABLED (ER1_VERIFY_SSL=false) for loopback target %q. This is only safe for local development with self-signed certs.", cfg.APIURL)
		})
		return
	}
	// Non-loopback host with verification disabled: refuse (fail-closed).
	insecureTLSWarnOnce.Do(func() {
		log.Printf("[er1] SECURITY: REFUSING to disable TLS verification (ER1_VERIFY_SSL=false) for NON-loopback host %q: re-enabling certificate verification. ER1_VERIFY_SSL=false is only honoured for 127.0.0.1/localhost.", cfg.APIURL)
	})
	cfg.VerifySSL = true
}

// hasDeviceTokenAuth reports whether device-token (Bearer) auth is available
// either via the ER1_DEVICE_TOKEN env var or a persisted token (OS keychain or
// the encrypted fallback file). On the UPLOAD path a device token makes the
// X-API-KEY fallback unused (see AuthHeaders), so any ER1_API_KEY value,
// placeholders included, is irrelevant there and must NOT produce a FATAL
// warning.
//
// FR-0096: that is true of /upload_2, not of the whole API. The /memory PATCH
// route enforces CSRF for Bearer-only requests and exempts API-key clients, so
// there the key is the ONLY auth that works and a device token cannot stand in
// for it. Do not read this function as "auth is covered".
func hasDeviceTokenAuth() bool {
	if os.Getenv("ER1_DEVICE_TOKEN") != "" {
		return true
	}
	return auth.HasStoredToken()
}

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
	// SEC-M7: ER1_VERIFY_SSL=false silently disabled TLS verification for any
	// host. Warn once when it is disabled, and refuse (fail-closed: force
	// verification back on) for non-loopback hosts. Allowed only for
	// 127.0.0.1/localhost. Applied here so all downstream clients inherit the
	// vetted cfg.VerifySSL value.
	applyTLSVerificationPolicy(cfg)
	// BUG-0137 + BUG-0163: refuse to use a placeholder API key against a
	// non-local URL, but only when the API key would actually be sent.
	// Device token (SPEC-0127) is the primary auth method and takes
	// precedence in AuthHeaders(), so on the upload path a placeholder is
	// merely useless and gets cleared silently. The FATAL warning is only
	// meaningful when the API key WOULD be the active auth mechanism.
	//
	// FR-0096 corrects the old claim that the X-API-KEY path is "dead-code"
	// whenever a device token exists: on the /memory PATCH route the key is
	// NOT a fallback but the only auth form that clears CSRF (see the note in
	// PatchMemoryCurrentTime). A missing key there is a hard failure, an
	// HTML 400 that reads like a server fault, which is why the Keychain
	// fallback below runs regardless of the device token.
	deviceToken := hasDeviceTokenAuth()
	if config.IsBlockingPlaceholder(cfg.APIKey, cfg.APIURL) {
		if !deviceToken {
			placeholderFatalOnce.Do(func() {
				log.Printf("[er1] FATAL: ER1_API_KEY is a placeholder (%q) targeting %q: refusing to upload. Run 'm3c-tools doctor' or fix the active profile.",
					cfg.APIKey, cfg.APIURL)
			})
		}
		cfg.APIKey = ""
	}
	// FR-0096: last link of the documented credential chain: Keychain → Secret
	// Manager → file. Every other credential loader in this binary already reads
	// the same `aims-core-er1` item (pkg/session, pkg/skillctl/artifactauth);
	// LoadConfig was the one place where the chain stopped at the environment,
	// and it is the place all uploads and patches go through. Only consulted
	// when nothing usable came from the environment, so an explicit key and the
	// localhost demo credential both still win.
	if cfg.APIKey == "" {
		if k := cachedKeychainAPIKey(); k != "" {
			keychainSourceOnce.Do(func() {
				log.Printf("[er1] API key resolved from the macOS Keychain (%s)", keychainService)
			})
			cfg.APIKey = k
		}
	}
	// BUG-0093 + SPEC-0143: Only warn when NO auth is available at all.
	if cfg.APIKey == "" && !deviceToken {
		log.Println("[er1] WARNING: No authentication configured: log in with 'm3c-tools login' or set ER1_API_KEY in your profile.")
	}
	return cfg
}

// keychainService is the macOS Keychain service name holding the ER1 maindrec
// key. Add or rotate it with:
//
//	security add-generic-password -s aims-core-er1 -a "$USER" -w '<key>' -U
const keychainService = "aims-core-er1"

var (
	// keychainLookup is a package variable so tests can exercise the precedence
	// without a real Keychain. Production always points at keychainAPIKey.
	keychainLookup = keychainAPIKey

	keychainOnce       sync.Once
	keychainCached     string
	keychainSourceOnce sync.Once
)

// cachedKeychainAPIKey resolves the key at most once per process. LoadConfig is
// called from several startup paths (PLM sync, retry scheduler, menubar init),
// and each miss would otherwise spawn another subprocess.
//
// The M3C_ER1_KEYCHAIN=off switch is honoured HERE rather than inside the lookup,
// because the cache would otherwise defeat it: once any earlier call has resolved
// a key, a later check at lookup time never runs again. It mirrors
// M3C_TOKEN_STORE=file for the device token, and has two uses. A test that must
// observe "no credential configured" on a developer machine that HAS the item
// (HOME=t.TempDir() cannot isolate the Keychain), and an operator who wants a run
// to use strictly what the environment gives it.
func cachedKeychainAPIKey() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("M3C_ER1_KEYCHAIN")), "off") {
		return ""
	}
	keychainOnce.Do(func() { keychainCached = keychainLookup() })
	return keychainCached
}

// keychainAPIKey reads the ER1 key from the macOS Keychain.
//
// Three deliberate choices: the ABSOLUTE /usr/bin/security, so a `security`
// planted on PATH cannot be run instead (same reasoning as
// pkg/skillctl/artifactauth); a TIMEOUT, because a hung credential lookup inside
// a launchd run would be worse than a missing key; and a fallback from the
// account-qualified query to the service-only one, since the item may have been
// added either way. Returns "" on any failure: the caller then behaves exactly
// as before this change.
func keychainAPIKey() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	queries := [][]string{}
	if u, err := user.Current(); err == nil && u.Username != "" {
		queries = append(queries, []string{"find-generic-password", "-s", keychainService, "-a", u.Username, "-w"})
	}
	queries = append(queries, []string{"find-generic-password", "-s", keychainService, "-w"})

	for _, q := range queries {
		out, err := exec.CommandContext(ctx, "/usr/bin/security", q...).Output()
		if err != nil {
			continue
		}
		// A placeholder in the Keychain is no better than one in a profile.
		if k := strings.TrimSpace(string(out)); k != "" && !config.IsPlaceholderKey(k) {
			return k
		}
	}
	return ""
}

// MemoryItemURL returns the ER1 memory-viewer URL for a document:
//
//	<base>/memory/<context_id>/<docID>
//
// where <base> is APIURL with the /upload_2 (or /upload) suffix stripped.
// Returns "" when docID is empty. Used to make a synced item openable from the
// Plaud sync panel and to print item links in `plaud list` / `plaud check`.
func (c *Config) MemoryItemURL(docID string) string {
	if docID == "" {
		return ""
	}
	base := strings.TrimSuffix(c.APIURL, "/upload_2")
	base = strings.TrimSuffix(base, "/upload")
	base = strings.TrimSuffix(base, "/")
	return fmt.Sprintf("%s/memory/%s/%s", base, c.ContextID, docID)
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

	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: httpsafe.NoCredentialRedirect} // SEC F25
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
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck // draining the response body for connection reuse; the data is discarded

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
			os.Setenv(k, v) //nolint:errcheck // best-effort .env->process env; a malformed key is simply skipped, same as an absent line
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
