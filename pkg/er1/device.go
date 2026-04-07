// device.go — Device pairing and heartbeat client for SPEC-0126.
//
// Talks to the aims-core device management endpoints:
//   POST /api/v2/devices/pair       — idempotent device pairing (upsert)
//   POST /api/v2/devices/heartbeat  — update sync state after batch
//   GET  /api/v2/devices            — list paired devices
package er1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
)

// PairRequest is sent to POST /api/v2/devices/pair.
type PairRequest struct {
	DeviceType      string `json:"device_type"`
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	VendorAccountID string `json:"vendor_account_id,omitempty"`
}

// HeartbeatRequest is sent to POST /api/v2/devices/heartbeat.
type HeartbeatRequest struct {
	DeviceType       string `json:"device_type"`
	DeviceID         string `json:"device_id"`
	ItemsSyncedDelta int    `json:"items_synced_delta"`
	LastItemID       string `json:"last_item_id,omitempty"`
	ClientVersion    string `json:"client_version,omitempty"`
}

// PairedDevice is returned by GET /api/v2/devices.
type PairedDevice struct {
	DeviceType   string `json:"device_type"`
	DeviceName   string `json:"device_name"`
	Status       string `json:"status"`
	ItemsSynced  int    `json:"items_synced"`
	LastSyncAt   string `json:"last_sync_at"`
	VendorAppURL string `json:"vendor_app_url,omitempty"`
}

// deviceHTTPClient is the shared HTTP client for device API calls.
var deviceHTTPClient = &http.Client{Timeout: 30 * time.Second}

// PairDevice registers or updates a device pairing. Idempotent — returns nil
// on both 200 (already paired) and 201 (new pairing).
func PairDevice(ctx context.Context, baseURL, apiKey string, req PairRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal pair request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/v2/devices/pair", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create pair request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	auth.ApplyAuth(httpReq, apiKey)
	applyUserIDHeader(httpReq)

	resp, err := deviceHTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("pair device request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	return fmt.Errorf("pair device failed (HTTP %d)", resp.StatusCode)
}

// DeviceHeartbeat updates sync state for a paired device.
func DeviceHeartbeat(ctx context.Context, baseURL, apiKey string, req HeartbeatRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal heartbeat request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/v2/devices/heartbeat", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create heartbeat request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	auth.ApplyAuth(httpReq, apiKey)
	applyUserIDHeader(httpReq)

	resp, err := deviceHTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("heartbeat request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("heartbeat failed (HTTP %d)", resp.StatusCode)
}

// ListDevices returns all paired devices for the authenticated user.
func ListDevices(ctx context.Context, baseURL, apiKey string) ([]PairedDevice, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v2/devices", nil)
	if err != nil {
		return nil, fmt.Errorf("create list devices request: %w", err)
	}
	auth.ApplyAuth(httpReq, apiKey)
	applyUserIDHeader(httpReq)

	resp, err := deviceHTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("list devices request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read list devices response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list devices failed (HTTP %d): %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var devices []PairedDevice
	if err := json.Unmarshal(respBody, &devices); err != nil {
		return nil, fmt.Errorf("parse devices response: %w", err)
	}
	return devices, nil
}

// BaseURLFromConfig derives the API base URL from a Config's APIURL,
// stripping the /upload_2 suffix. Useful for device API calls.
func BaseURLFromConfig(cfg *Config) string {
	base := cfg.APIURL
	if idx := strings.LastIndex(base, "/upload"); idx > 0 {
		base = base[:idx]
	}
	return base
}

// applyUserIDHeader sets the X-User-ID header from the ER1_CONTEXT_ID env var.
// The context ID format is "<user_id>___<suffix>"; we extract the user ID part.
func applyUserIDHeader(req *http.Request) {
	ctxID := os.Getenv("ER1_CONTEXT_ID")
	if ctxID == "" {
		return
	}
	parts := strings.SplitN(ctxID, "___", 2)
	if parts[0] != "" {
		req.Header.Set("X-User-ID", parts[0])
	}
}
