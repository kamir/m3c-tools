package registry

// FR-0045 D5 — the client-side fetch of the signed revocation HEAD.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchRevocationHead GETs the signed revocation HEAD from the registry
// (FR-0045 D2 endpoint: <registry>/revocations/head, where <registry> already
// includes the /api/skills root — mirroring how `revoke` posts to
// <registry>/bundles/<digest>/revoke). Returns the head as a map[string]any for
// AdoptRevocationHead.
//
// PUBLIC feed (CRL semantics): no auth header. Integrity comes from the ed25519
// envelope signature, which the caller verifies against the PINNED registry key —
// this function only transports the already-authoritative record (BDR 2026-07-06).
func FetchRevocationHead(baseURL, tenantScope string, timeout time.Duration) (map[string]any, error) {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		return nil, fmt.Errorf("registry: empty base URL for revocation head")
	}
	u := strings.TrimRight(base, "/") + "/revocations/head"
	if tenantScope != "" {
		u += "?tenant_scope=" + url.QueryEscape(tenantScope)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry: revocation head HTTP %d", resp.StatusCode)
	}
	var head map[string]any
	if err := json.Unmarshal(body, &head); err != nil {
		return nil, fmt.Errorf("registry: revocation head decode: %w", err)
	}
	return head, nil
}
