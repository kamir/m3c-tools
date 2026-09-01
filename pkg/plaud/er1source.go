package plaud

// SPEC-0304 — pull the Plaud token from the ER1 Credential Vault instead of
// harvesting it from a local browser. The token was captured once (any OS) via
// the "Plaud verbinden" page and stored encrypted server-side; here the owner's
// agent fetches it back with the same auth m3c-tools already uses for ER1
// uploads: device token (Bearer) preferred, X-API-KEY fallback.
//
// This is the client side of the SPEC-0304 6.3 owner-retrieval path. The server
// endpoint is FLAG-GATED (CREDENTIAL_ALLOW_CLIENT_REVEAL) and OFF by default;
// the durable design (Ph2) uses the credential server-side only. Kept
// self-contained (no pkg/er1 import) to avoid an import cycle.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ER1RevealPath is the SPEC-0304 owner-retrieval endpoint (relative to the ER1 base).
const ER1RevealPath = "/api/credentials/plaud/reveal"

// FetchTokenFromER1 retrieves the stored Plaud token from the ER1 Credential
// Vault. It resolves the ER1 base URL from the active profile (ER1_API_URL,
// minus the /upload_2 suffix) and authenticates with the device token (Bearer)
// or, failing that, ER1_API_KEY (+ ER1_USER_ID). TLS verification is skipped
// only for loopback targets when ER1_VERIFY_SSL is false (dev self-signed cert).
func FetchTokenFromER1() (token string, exp int64, err error) {
	apiURL := strings.TrimSpace(os.Getenv("ER1_API_URL"))
	if apiURL == "" {
		return "", 0, fmt.Errorf("ER1_API_URL not set — activate a profile with 'm3c-tools config switch <name>'")
	}
	base := apiURL
	if idx := strings.LastIndex(base, "/upload"); idx > 0 {
		base = base[:idx]
	}
	endpoint := strings.TrimRight(base, "/") + ER1RevealPath

	headers := map[string]string{"Accept": "application/json"}
	if dt := strings.TrimSpace(os.Getenv("ER1_DEVICE_TOKEN")); dt != "" {
		headers["Authorization"] = "Bearer " + dt // SPEC-0127 device token (preferred)
	} else if key := strings.TrimSpace(os.Getenv("ER1_API_KEY")); key != "" {
		headers["X-API-KEY"] = key
		if uid := strings.TrimSpace(os.Getenv("ER1_USER_ID")); uid != "" {
			headers["X-User-ID"] = uid // owner id for the X-API-KEY auth path
		}
	} else {
		return "", 0, fmt.Errorf("no ER1 authentication (device token or ER1_API_KEY) — run 'm3c-tools login'")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if verifyDisabled(os.Getenv("ER1_VERIFY_SSL")) && isLoopbackURL(endpoint) {
		// SEC: only for loopback + self-signed dev cert.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("reach ER1 reveal endpoint %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			Token string `json:"token"`
			Exp   int64  `json:"exp"`
		}
		if e := json.Unmarshal(body, &out); e != nil {
			return "", 0, fmt.Errorf("parse ER1 reveal response: %w", e)
		}
		if strings.TrimSpace(out.Token) == "" {
			return "", 0, fmt.Errorf("ER1 returned an empty token")
		}
		return out.Token, out.Exp, nil
	case http.StatusUnauthorized:
		return "", 0, fmt.Errorf("ER1 rejected the credentials (401) — run 'm3c-tools login'")
	case http.StatusForbidden:
		return "", 0, fmt.Errorf("ER1 credential reveal is disabled (403) — the server must set CREDENTIAL_ALLOW_CLIENT_REVEAL=1 (SPEC-0304 R1, spike-only)")
	case http.StatusNotFound:
		return "", 0, fmt.Errorf("no Plaud credential stored in ER1 for this user — capture it first at <ER1>/v2/credentials/plaud")
	default:
		return "", 0, fmt.Errorf("ER1 reveal failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// verifyDisabled reports whether ER1_VERIFY_SSL requests skipping TLS verification.
func verifyDisabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off":
		return true
	}
	return false
}

// isLoopbackURL reports whether the URL host is loopback (the only place we
// honour ER1_VERIFY_SSL=false).
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}
