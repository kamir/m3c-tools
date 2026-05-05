package install

// Audit POST helper for SPEC-0188 --allow-yellow / --ignore-deps overrides.
//
// Both flags lower the install gate from its default (refuse-on-anything-
// less-than-pinned-minimum). SPEC-0188 §11 requires that the override be
// audit-logged BEFORE the install proceeds — not after, because a
// post-hoc audit creates a window where a successful override-install
// happened but the registry never saw it. We refuse the install if the
// audit POST itself fails (see Install in install.go).
//
// The endpoint shape mirrors SPEC-0115's existing /api/skills/audit
// surface. If the production server's signature differs at integration
// time, plug the right URL via Opts.AuditPoster and adjust the wire
// shape in HTTPAuditPoster — the contract we expose to the rest of the
// code (AuditPoster func) stays stable.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuditEntry is the wire shape posted to /api/skills/audit. Field names
// match SPEC-0115's existing audit row schema; new fields specific to
// SPEC-0188 (AllowYellow, IgnoreDeps) are additive.
type AuditEntry struct {
	// Action is the verb that drove the entry, e.g.
	// "install.allow-yellow" / "install.ignore-deps". Multi-word
	// actions can stack (overrideAction concatenates them).
	Action string `json:"action"`

	// Name + Version is the skill being installed (the override is per
	// install, not global).
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`

	// AllowYellow / IgnoreDeps flag the specific override(s) chosen.
	AllowYellow bool `json:"allow_yellow,omitempty"`
	IgnoreDeps  bool `json:"ignore_deps,omitempty"`

	// RecordedAt is the client-side timestamp (RFC3339 UTC). The server
	// SHOULD also stamp its own arrival time; this field is the
	// client's intent at invocation.
	RecordedAt string `json:"recorded_at"`

	// Origin identifies the tool. "skillctl" for this code path; future
	// MCP server overrides would set "mcp:skill_install" or similar.
	Origin string `json:"origin"`

	// RegistryURL is the trust-root the install is targeting, so the
	// audit row scopes to the right tenant.
	RegistryURL string `json:"registry_url"`
}

// HTTPAuditPoster is the production AuditPoster: serializes AuditEntry as
// JSON and POSTs it to <base>/audit. Returns an error if the server
// responds non-2xx (Install translates that into a refuse-to-proceed).
//
// The base URL is the same registry root that the trust-root already
// pinned, so we don't ask for a separate audit URL — keeping the
// configuration surface narrow.
func HTTPAuditPoster(httpClient *http.Client, baseURL string) func(ctx context.Context, entry AuditEntry) error {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/audit"
	return func(ctx context.Context, entry AuditEntry) error {
		body, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("audit: marshal: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("audit: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "skillctl/spec-0188-s8")

		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("audit: POST %s: %w", endpoint, err)
		}
		defer resp.Body.Close()
		// Drain a short prefix so the connection can be reused.
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

		if resp.StatusCode/100 != 2 {
			snippet := strings.TrimSpace(string(respBody))
			if len(snippet) > 256 {
				snippet = snippet[:256] + "..."
			}
			return fmt.Errorf("audit: POST %s returned HTTP %d: %s", endpoint, resp.StatusCode, snippet)
		}
		return nil
	}
}

// overrideAction composes a stable action string for the audit row. We
// concatenate so a single install that uses both flags surfaces both in
// the audit log without the server having to demux.
func overrideAction(opts Opts) string {
	parts := []string{}
	if opts.AllowYellow {
		parts = append(parts, "install.allow-yellow")
	}
	if opts.IgnoreDeps {
		parts = append(parts, "install.ignore-deps")
	}
	if len(parts) == 0 {
		return "install"
	}
	return strings.Join(parts, ",")
}
