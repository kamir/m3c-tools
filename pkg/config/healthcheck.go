package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// healthCheckInsecureWarnOnce ensures the SEC-M7 fail-closed message on the
// TestConnection path fires at most once per process, mirroring the one-time
// WARN emitted by er1.applyTLSVerificationPolicy.
var healthCheckInsecureWarnOnce sync.Once

// isLoopbackHealthURL reports whether the host component of rawURL is a literal
// loopback address (127.0.0.0/8, ::1, or "localhost"). It is a self-contained
// copy of er1.isLoopbackURL — pkg/config cannot import pkg/er1 (that would form
// an import cycle, since er1 imports config), so the SEC-M7 gate is duplicated
// here rather than shared. Pure (no DNS): a hostname that merely *resolves* to
// loopback is NOT treated as loopback.
func isLoopbackHealthURL(rawURL string) bool {
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

// healthCheckSkipVerify resolves the effective InsecureSkipVerify decision for
// the TestConnection health check, applying the SEC-M7 fail-closed rule: a
// request to disable TLS verification (ER1_VERIFY_SSL in {false,0,no}) is only
// honoured for a loopback target. For any non-loopback host the request is
// REFUSED (verification forced back on) with a one-time loud WARN — identical
// policy to er1.applyTLSVerificationPolicy so this third path can no longer
// silently MITM-test a remote profile.
func healthCheckSkipVerify(apiURL, verifySSLStr string) bool {
	requested := false
	switch strings.ToLower(strings.TrimSpace(verifySSLStr)) {
	case "false", "0", "no":
		requested = true
	}
	if !requested {
		return false
	}
	if isLoopbackHealthURL(apiURL) {
		healthCheckInsecureWarnOnce.Do(func() {
			log.Printf("[config] WARNING: TLS verification is DISABLED (ER1_VERIFY_SSL=false) for loopback target %q during Test Connection. This is only safe for local development with self-signed certs.", apiURL)
		})
		return true
	}
	healthCheckInsecureWarnOnce.Do(func() {
		log.Printf("[config] SECURITY: REFUSING to disable TLS verification (ER1_VERIFY_SSL=false) for NON-loopback host %q during Test Connection — testing over a verified channel instead. ER1_VERIFY_SSL=false is only honoured for 127.0.0.1/localhost.", apiURL)
	})
	return false
}

// healthCheckER1 performs a basic HTTP GET to the ER1 server to verify connectivity.
// This is a lightweight version that avoids importing the er1 package.
func healthCheckER1(apiURL, verifySSLStr string) error {
	// Derive base URL from upload URL.
	baseURL := apiURL
	if idx := strings.LastIndex(baseURL, "/upload"); idx > 0 {
		baseURL = baseURL[:idx]
	}

	// SEC-M7 (F33): honour ER1_VERIFY_SSL=false ONLY for loopback targets;
	// refuse (fail-closed) for any remote host so a profile pointed at a
	// remote URL can never be "tested" over an unverified TLS channel.
	skipVerify := healthCheckSkipVerify(apiURL, verifySSLStr)

	client := &http.Client{Timeout: 10 * time.Second}
	if skipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", baseURL+"/health", nil) // BUG-0086: was /api/plm/projects (requires auth)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ER1 server unreachable: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return fmt.Errorf("ER1 health check returned HTTP %d", resp.StatusCode)
}
