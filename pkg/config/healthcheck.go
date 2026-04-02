package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// healthCheckER1 performs a basic HTTP GET to the ER1 server to verify connectivity.
// This is a lightweight version that avoids importing the er1 package.
func healthCheckER1(apiURL, verifySSLStr string) error {
	// Derive base URL from upload URL.
	baseURL := apiURL
	if idx := strings.LastIndex(baseURL, "/upload"); idx > 0 {
		baseURL = baseURL[:idx]
	}

	skipVerify := false
	switch strings.ToLower(verifySSLStr) {
	case "false", "0", "no":
		skipVerify = true
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if skipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", baseURL+"/api/plm/projects", nil)
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
