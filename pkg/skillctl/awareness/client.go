// HTTP plumbing for the SPEC-0195 admission endpoints.
//
// We intentionally do NOT reuse `pkg/skillctl/registry`'s Client struct:
// that client targets the SPEC-0188 read paths (/by-name, /bundles,
// /identities). The SPEC-0195 admit paths are write-shaped POSTs with a
// different request envelope, and adding a "POST or GET" knob to that
// client would muddy its sole-purpose contract.
//
// What lives here:
//
//	HTTPDoer          — minimal interface for test injection.
//	postSync          — POST /admit-from-scan
//	postAttest        — POST /admit-from-scan/attest
//	getSessionAdmissions — GET /admit-from-scan?session=<tag>
//
// All three share request-construction + status-code handling so a SPEC
// drift on response shape only needs to be fixed once.

package awareness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPDoer is the subset of *http.Client the awareness package uses.
// httptest.Server returns an *http.Client that satisfies it; production
// callers pass a tuned *http.Client with timeout + redirect cap.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// defaultHTTPClient is a 30s-timeout client. Mirrors registry.DefaultTimeout
// so the two clients age in lockstep when the spec-wide timeout is tuned.
const defaultHTTPTimeout = 30 * time.Second

// userAgent is sent on every request so the registry's request log can
// distinguish awareness traffic from the SPEC-0188 install/verify path.
const userAgent = "skillctl-awareness/0.0.0-spec0195"

// admitFromScanPath is the SPEC-0195 §5.1 endpoint suffix. Appended to
// the registry's base URL with a single "/" separator; the base URL is
// expected to be the canonical /api/skills root (no trailing slash).
const admitFromScanPath = "/admit-from-scan"

// admitFromScanAttestPath is the SPEC-0195 §5.4 attestation endpoint.
const admitFromScanAttestPath = "/admit-from-scan/attest"

// maxResponseSize bounds how much JSON the client will read off the
// admission endpoints. The largest legitimate response is the verify
// path: a per-session admission list, capped at a few hundred entries
// of small metadata. 8 MiB is well above that.
const maxResponseSize int64 = 8 << 20 // 8 MiB

// postSync issues POST /admit-from-scan. The envelope is JSON-encoded
// as-is; the response is decoded into SyncResponse.
func postSync(opts Opts, env SyncEnvelope) (*SyncResponse, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("awareness: marshal sync envelope: %w", err)
	}
	u := strings.TrimRight(opts.RegistryURL, "/") + admitFromScanPath

	resp, err := doRequest(opts.Ctx, opts.HTTPClient, http.MethodPost, u, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through
	case resp.StatusCode == http.StatusConflict:
		// SPEC-0195 §5.2: 409 = session_tag already in use by a
		// different client_identity. Surface the body so the operator
		// sees the conflicting identity.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("awareness: registry rejected sync (409 conflict): %s", strings.TrimSpace(string(raw)))
	case resp.StatusCode == http.StatusForbidden:
		// SPEC-0195 §6.1: 403 = dev_seed_forbidden_in_prod (or other
		// auth-time refusal). Surface verbatim.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("awareness: registry rejected sync (403): %s", strings.TrimSpace(string(raw)))
	case resp.StatusCode/100 == 4:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("awareness: registry rejected sync (HTTP %d): %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	case resp.StatusCode/100 == 5:
		return nil, fmt.Errorf("awareness: registry sync failed (HTTP %d)", resp.StatusCode)
	default:
		return nil, fmt.Errorf("awareness: registry sync unexpected HTTP %d", resp.StatusCode)
	}

	var out SyncResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("awareness: decode sync response: %w", err)
	}
	return &out, nil
}

// postAttest issues POST /admit-from-scan/attest. Body shape:
//
//	{ "session_tag": ..., "governance_level": yellow|green,
//	  "rationale": ..., "scope": ... }
func postAttest(opts Opts, sessionTag string) (*AttestResponse, error) {
	env := AttestEnvelope{
		SessionTag:      sessionTag,
		GovernanceLevel: string(opts.DefaultAttest),
		Rationale:       opts.AttestRationale,
		Scope:           opts.AttestScope,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("awareness: marshal attest envelope: %w", err)
	}
	u := strings.TrimRight(opts.RegistryURL, "/") + admitFromScanAttestPath

	resp, err := doRequest(opts.Ctx, opts.HTTPClient, http.MethodPost, u, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("awareness: attest rejected (HTTP %d): %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out AttestResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("awareness: decode attest response: %w", err)
	}
	return &out, nil
}

// getSessionAdmissions issues GET /admit-from-scan?session=<tag>. Used by
// `skillctl awareness verify`.
func getSessionAdmissions(opts VerifyOpts) (*VerifyResponse, error) {
	if opts.HTTPClient == nil {
		opts.HTTPClient = newDefaultHTTPClient()
	}
	q := url.Values{}
	q.Set("session", opts.SessionTag)
	u := strings.TrimRight(opts.RegistryURL, "/") + admitFromScanPath + "?" + q.Encode()

	resp, err := doRequest(opts.Ctx, opts.HTTPClient, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Server says no admissions exist for this session_tag.
		// Return an empty (non-error) response so the CLI can print
		// "0 admitted" rather than failing — this is a normal "verify
		// before any sync" case.
		return &VerifyResponse{SessionTag: opts.SessionTag}, nil
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("awareness verify: registry returned HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out VerifyResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("awareness verify: decode response: %w", err)
	}
	if out.SessionTag == "" {
		out.SessionTag = opts.SessionTag
	}
	return &out, nil
}

// doRequest is the centralised request constructor. It applies the
// canonical headers, a default 30s-timeout client when none was injected,
// and a polite "Accept" so a registry that 406s on bad clients fails
// loud rather than returning HTML.
func doRequest(ctx context.Context, client HTTPDoer, method, u string, body []byte) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = newDefaultHTTPClient()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, fmt.Errorf("awareness: build %s %s: %w", method, u, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("awareness: %s %s: %w", method, u, err)
	}
	return resp, nil
}

// newDefaultHTTPClient builds the production-default *http.Client. A
// 30s overall timeout is plenty for an admit-from-scan envelope of a few
// hundred KiB; a longer timeout would just mask a registry outage.
func newDefaultHTTPClient() HTTPDoer {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
	}
}

// AttestResponse — JSON unmarshal hook so unknown server fields are
// preserved in `Extra` for forward-compat (we don't lose new fields the
// registry might add). The base shape lives in awareness.go.
func (r *AttestResponse) UnmarshalJSON(data []byte) error {
	// Decode into a generic map first so we can pull out the extras.
	raw := map[string]interface{}{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["session_tag"].(string); ok {
		r.SessionTag = v
		delete(raw, "session_tag")
	}
	if v, ok := raw["attested"].(float64); ok {
		r.Attested = int(v)
		delete(raw, "attested")
	}
	if len(raw) > 0 {
		r.Extra = raw
	}
	return nil
}

// recognized error sentinels — exported as predicates so tests / CLI can
// branch without parsing strings.
var (
	// errNoBody is returned when the server returns a 200 with an empty
	// body. Treated as a bug in the registry rather than a successful
	// admission with zero rows; refusing here makes the failure
	// diagnosable.
	errNoBody = errors.New("awareness: registry returned 200 with empty body")
)

// IsRegistryEmpty reports whether err is the empty-200 sentinel.
func IsRegistryEmpty(err error) bool { return errors.Is(err, errNoBody) }
