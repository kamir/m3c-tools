// doctor_cmd.go — "m3c-tools doctor" connectivity & config diagnostics (SPEC-0143).
//
// This file has no build tags so it compiles on both darwin and non-darwin platforms.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/config"
	"github.com/kamir/m3c-tools/pkg/diag"
	"github.com/kamir/m3c-tools/pkg/er1"
)

func cmdDoctor() {
	report := diag.Report{}

	report.Sections = append(report.Sections, doctorProfile())
	report.Sections = append(report.Sections, doctorAuth())
	report.Sections = append(report.Sections, doctorConfigConsistency())
	report.Sections = append(report.Sections, doctorConnectivity())

	report.Print()

	if report.HasFailures() {
		os.Exit(1)
	}
}

// doctorProfile checks the active profile and file existence.
func doctorProfile() diag.Section {
	s := diag.Section{Title: "Profile"}

	pm := config.NewProfileManager()
	name := pm.ActiveProfileName()
	if name == "" {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Active profile", Status: diag.Fail, Detail: "no active profile — run 'm3c-tools config switch <name>'",
		})
		return s
	}

	s.Checks = append(s.Checks, diag.Check{
		Name: "Active profile", Status: diag.OK, Detail: name,
	})

	p, err := pm.GetProfile(name)
	if err != nil {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Profile file", Status: diag.Fail, Detail: fmt.Sprintf("cannot load: %v", err),
		})
	} else {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Profile file", Status: diag.OK, Detail: p.Path,
		})
	}

	return s
}

// doctorAuth checks device token and API key status.
func doctorAuth() diag.Section {
	s := diag.Section{Title: "Authentication"}

	home, _ := os.UserHomeDir()
	tokenPath := filepath.Join(home, ".m3c-tools", "device-token.enc")

	// Check device token file.
	tokenEnv := os.Getenv("ER1_DEVICE_TOKEN")
	if tokenEnv != "" {
		// Token was loaded at startup — check for expiration info.
		dt := loadTokenForDoctor()
		if dt != nil {
			if dt.IsExpired() {
				s.Checks = append(s.Checks, diag.Check{
					Name: "Device token", Status: diag.Fail,
					Detail: fmt.Sprintf("expired (%s) — run 'm3c-tools login' to refresh", dt.ExpiresAt),
				})
			} else {
				if dt.ExpiresAt != "" {
					exp, err := time.Parse(time.RFC3339, dt.ExpiresAt)
					if err == nil {
						remaining := time.Until(exp).Truncate(time.Hour * 24)
						detail := fmt.Sprintf("valid (expires %s, %s remaining)", dt.ExpiresAt[:10], remaining)
						if remaining < 7*24*time.Hour {
							s.Checks = append(s.Checks, diag.Check{
								Name: "Device token", Status: diag.Warn,
								Detail: fmt.Sprintf("expiring soon (%s) — consider re-login", dt.ExpiresAt[:10]),
							})
						} else {
							s.Checks = append(s.Checks, diag.Check{
								Name: "Device token", Status: diag.OK, Detail: detail,
							})
						}
					} else {
						s.Checks = append(s.Checks, diag.Check{
							Name: "Device token", Status: diag.OK, Detail: "valid (no expiry parsed)",
						})
					}
				} else {
					s.Checks = append(s.Checks, diag.Check{
						Name: "Device token", Status: diag.OK, Detail: "valid (no expiry set)",
					})
				}
			}
		} else {
			s.Checks = append(s.Checks, diag.Check{
				Name: "Device token", Status: diag.OK, Detail: "loaded (in env)",
			})
		}
	} else if _, err := os.Stat(tokenPath); err == nil {
		// File exists but wasn't loaded — likely decryption failed or expired at startup.
		s.Checks = append(s.Checks, diag.Check{
			Name: "Device token", Status: diag.Warn,
			Detail: fmt.Sprintf("file exists (%s) but not loaded — may be expired or wrong device", tokenPath),
		})
	} else {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Device token", Status: diag.Skipped, Detail: "not configured",
		})
	}

	// Check API key.
	apiKey := os.Getenv("ER1_API_KEY")
	if tokenEnv != "" {
		// Token is active — API key is optional.
		if apiKey != "" {
			s.Checks = append(s.Checks, diag.Check{
				Name: "API key", Status: diag.Skipped, Detail: "set but not needed (token active)",
			})
		} else {
			s.Checks = append(s.Checks, diag.Check{
				Name: "API key", Status: diag.Skipped, Detail: "not needed (token active)",
			})
		}
	} else if apiKey != "" {
		s.Checks = append(s.Checks, diag.Check{
			Name: "API key", Status: diag.Warn,
			Detail: fmt.Sprintf("active (%d chars) — consider pairing device for token auth", len(apiKey)),
		})
	} else {
		s.Checks = append(s.Checks, diag.Check{
			Name: "API key", Status: diag.Fail, Detail: "not set",
		})
	}

	// Auth method summary.
	method := auth.AuthMethod()
	switch method {
	case "device token":
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth method", Status: diag.OK, Detail: "Bearer token (SPEC-0127)",
		})
	case "API key":
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth method", Status: diag.Warn, Detail: "API key (legacy)",
		})
	default:
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth method", Status: diag.Fail, Detail: "NO AUTH — run 'm3c-tools login' or set ER1_API_KEY",
		})
	}

	return s
}

// loadTokenForDoctor loads the device token for display purposes.
func loadTokenForDoctor() *auth.DeviceToken {
	cfg := er1.LoadConfig()
	userPart := strings.SplitN(cfg.ContextID, "___", 2)[0]
	if userPart == "" {
		return nil
	}
	dt, err := auth.Load(auth.DeviceID(), userPart)
	if err != nil || dt == nil {
		return nil
	}
	return dt
}

// doctorConfigConsistency compares config values across sources.
func doctorConfigConsistency() diag.Section {
	s := diag.Section{Title: "Config Consistency"}

	home, _ := os.UserHomeDir()

	// Load values from each source independently.
	sources := []struct {
		name string
		path string
	}{
		{"profile", ""},
		{"legacy", filepath.Join(home, ".m3c-tools.env")},
		{"repo", ".env"},
	}

	// Get profile path.
	pm := config.NewProfileManager()
	if p, err := pm.ActiveProfile(); err == nil {
		sources[0].path = p.Path
	}

	// Read raw values from each file.
	var loaded []envSource
	for _, src := range sources {
		if src.path == "" {
			continue
		}
		vars := readEnvFile(src.path)
		if vars != nil {
			loaded = append(loaded, envSource{name: src.name, vars: vars})
		}
	}

	// Check ER1_API_URL consistency.
	checkKey := "ER1_API_URL"
	effective := os.Getenv(checkKey)
	if effective == "" {
		s.Checks = append(s.Checks, diag.Check{
			Name: checkKey, Status: diag.Fail, Detail: "not set in any source",
		})
	} else {
		conflicts := findConflicts(loaded, checkKey, effective)
		if conflicts != "" {
			s.Checks = append(s.Checks, diag.Check{
				Name: checkKey, Status: diag.Warn, Detail: conflicts,
			})
		} else {
			s.Checks = append(s.Checks, diag.Check{
				Name: checkKey, Status: diag.OK, Detail: effective,
			})
		}
	}

	// Check ER1_CONTEXT_ID: token may override profile value.
	ctxProfile := ""
	for _, sv := range loaded {
		if v, ok := sv.vars["ER1_CONTEXT_ID"]; ok && v != "" {
			ctxProfile = v
			break
		}
	}
	ctxEffective := os.Getenv("ER1_CONTEXT_ID")
	if ctxEffective != "" && ctxProfile != "" && ctxProfile != ctxEffective {
		s.Checks = append(s.Checks, diag.Check{
			Name: "ER1_CONTEXT_ID", Status: diag.OK,
			Detail: fmt.Sprintf("token overrides profile (%s -> %s)", maskID(ctxProfile), maskID(ctxEffective)),
		})
	} else if ctxEffective != "" {
		s.Checks = append(s.Checks, diag.Check{
			Name: "ER1_CONTEXT_ID", Status: diag.OK, Detail: maskID(ctxEffective),
		})
	} else {
		s.Checks = append(s.Checks, diag.Check{
			Name: "ER1_CONTEXT_ID", Status: diag.Fail, Detail: "not set",
		})
	}

	// Check for stale init config.
	initPath := filepath.Join(home, "m3c-tools.init.cfg")
	if _, err := os.Stat(initPath); err == nil {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Init config", Status: diag.Warn,
			Detail: fmt.Sprintf("%s exists but was not imported — run 'm3c-tools config import'", initPath),
		})
	}

	// Check file permissions on sensitive files.
	for _, sv := range loaded {
		if info, err := os.Stat(sv.name); err == nil {
			if info.Mode().Perm()&0077 != 0 {
				s.Checks = append(s.Checks, diag.Check{
					Name: "File perms", Status: diag.Warn,
					Detail: fmt.Sprintf("%s is world-readable (%04o) — run 'chmod 600 %s'", sv.name, info.Mode().Perm(), sv.name),
				})
			}
		}
	}

	return s
}

// doctorConnectivity tests network connectivity to the ER1 server.
func doctorConnectivity() diag.Section {
	s := diag.Section{Title: "Connectivity"}

	cfg := er1.LoadConfig()
	baseURL := cfg.APIURL
	if idx := strings.LastIndex(baseURL, "/upload"); idx > 0 {
		baseURL = baseURL[:idx]
	}

	// Parse host and port from URL.
	hostPort := baseURL
	hostPort = strings.TrimPrefix(hostPort, "https://")
	hostPort = strings.TrimPrefix(hostPort, "http://")
	if idx := strings.Index(hostPort, "/"); idx > 0 {
		hostPort = hostPort[:idx]
	}
	host := hostPort
	port := "443"
	if idx := strings.Index(hostPort, ":"); idx > 0 {
		host = hostPort[:idx]
		port = hostPort[idx+1:]
	}

	// DNS resolve.
	start := time.Now()
	addrs, err := net.LookupHost(host)
	elapsed := time.Since(start)
	if err != nil {
		s.Checks = append(s.Checks, diag.Check{
			Name: "DNS resolve", Status: diag.Fail, Detail: fmt.Sprintf("%s — %v", host, err),
		})
		return s // no point testing further
	}
	s.Checks = append(s.Checks, diag.Check{
		Name: "DNS resolve", Status: diag.OK,
		Detail: fmt.Sprintf("%s -> %s (%s)", host, addrs[0], elapsed.Round(time.Millisecond)),
	})

	// TLS handshake (if HTTPS).
	if strings.HasPrefix(cfg.APIURL, "https://") {
		tlsAddr := host + ":" + port
		start = time.Now()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", tlsAddr, &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
		})
		elapsed = time.Since(start)
		if err != nil {
			s.Checks = append(s.Checks, diag.Check{
				Name: "TLS handshake", Status: diag.Fail, Detail: fmt.Sprintf("%s — %v", tlsAddr, err),
			})
		} else {
			conn.Close()
			s.Checks = append(s.Checks, diag.Check{
				Name: "TLS handshake", Status: diag.OK,
				Detail: fmt.Sprintf("%s (%s)", tlsAddr, elapsed.Round(time.Millisecond)),
			})
		}
	}

	// ER1 /health endpoint (no auth required).
	client := &http.Client{Timeout: 10 * time.Second}
	if !cfg.VerifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	start = time.Now()
	resp, err := client.Get(baseURL + "/health")
	elapsed = time.Since(start)
	if err != nil {
		s.Checks = append(s.Checks, diag.Check{
			Name: "ER1 /health", Status: diag.Fail, Detail: fmt.Sprintf("unreachable — %v", err),
		})
		return s
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		s.Checks = append(s.Checks, diag.Check{
			Name: "ER1 /health", Status: diag.OK,
			Detail: fmt.Sprintf("HTTP %d (%s)", resp.StatusCode, elapsed.Round(time.Millisecond)),
		})
	} else {
		s.Checks = append(s.Checks, diag.Check{
			Name: "ER1 /health", Status: diag.Fail,
			Detail: fmt.Sprintf("HTTP %d", resp.StatusCode),
		})
	}

	// Authenticated endpoint — tests actual auth.
	if !auth.HasAuth(cfg.APIKey) {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.Skipped, Detail: "no credentials to test",
		})
		return s
	}

	req, err := http.NewRequest("GET", baseURL+"/api/plm/projects", nil)
	if err != nil {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.Fail, Detail: fmt.Sprintf("request error: %v", err),
		})
		return s
	}
	for k, v := range cfg.AuthHeaders() {
		req.Header.Set(k, v)
	}

	start = time.Now()
	resp, err = client.Do(req)
	elapsed = time.Since(start)
	if err != nil {
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.Fail, Detail: fmt.Sprintf("unreachable — %v", err),
		})
		return s
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.OK,
			Detail: fmt.Sprintf("/api/plm/projects HTTP %d (%s) [%s]", resp.StatusCode, elapsed.Round(time.Millisecond), auth.AuthMethod()),
		})
	case http.StatusUnauthorized:
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.Fail,
			Detail: fmt.Sprintf("HTTP 401 — %s is invalid or expired", auth.AuthMethod()),
		})
	case http.StatusForbidden:
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.Fail,
			Detail: fmt.Sprintf("HTTP 403 — %s rejected", auth.AuthMethod()),
		})
	default:
		s.Checks = append(s.Checks, diag.Check{
			Name: "Auth endpoint", Status: diag.Warn,
			Detail: fmt.Sprintf("HTTP %d (unexpected)", resp.StatusCode),
		})
	}

	return s
}

// readEnvFile reads a .env file and returns key-value pairs.
// Returns nil if the file doesn't exist.
func readEnvFile(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	vars := make(map[string]string)
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
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		vars[k] = v
	}
	return vars
}

// envSource holds parsed env vars from a single config file.
type envSource struct {
	name string
	vars map[string]string
}

// findConflicts returns a description of conflicting values across sources, or "".
func findConflicts(sources []envSource, key, effective string) string {
	var conflicts []string
	for _, sv := range sources {
		if v, ok := sv.vars[key]; ok && v != "" && v != effective {
			conflicts = append(conflicts, fmt.Sprintf("%s=%s", sv.name, v))
		}
	}
	if len(conflicts) > 0 {
		return fmt.Sprintf("effective=%s, conflicts: %s", effective, strings.Join(conflicts, ", "))
	}
	return ""
}

// maskID shows first 5 and last 3 characters of an ID.
func maskID(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:5] + "..." + id[len(id)-3:]
}
