// Package er1 is the Thinking Engine's ER1 REST client.
//
// SPEC-0167 §Isolation Model requires the client be bound to EXACTLY
// ONE user_context_id at construction and refuse any other at
// runtime. This is a hard check, not a review-gate assumption.
//
// Week 3 (Stream 3b): replaces the Week-1 in-memory stub with a real
// HTTP client against aims-core's `maindrec` module.
//
// ### ER1 endpoint choices
//
// The aims-core endpoints live in
// `flask/modules/maindrec/core.py`:
//
//	GET  /memory/<ctx_id>                  — list items (JSON)
//	GET  /memory/<ctx_id>/<memory_id>       — get one item (JSON)
//	POST /memory/<ctx_id>                   — upload (multipart, AUDIO path)
//
// The existing POST is a multipart/form-data audio-upload path and
// is NOT a good fit for persisting cognitive A-layer artifacts as
// JSON. Until aims-core ships a dedicated JSON artifact endpoint the
// thinking-engine client writes to:
//
//	POST /memory/<ctx_id>/artifacts        — thinking-engine artifact sink (JSON)
//
// That route is consumed by the ER1 sinker's integration tests via a
// fake HTTP server. In production, when aims-core has not yet landed
// the JSON sink, the sinker will see 404 and the artifact stays on
// Kafka (`artifacts.created` is truth per D2 — this is the graceful
// degradation the SPEC prescribes). See PLAN-0167 §Stream 3b and
// SPEC-0167 §D2 for the design intent.
package er1

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// DefaultBaseURL is the fallback ER1 base when ER1_BASE_URL is not set.
const DefaultBaseURL = "http://localhost:5000"

// DefaultTimeout is the sync-call timeout per SPEC-0167 §Service Components.
const DefaultTimeout = 5 * time.Second

// HMACWindow is the accepted timestamp skew between engine and Flask,
// matching `flask/modules/thinking_bridge/auth.py::DEFAULT_TIMESTAMP_WINDOW_S`.
const HMACWindow = 300 * time.Second

// Item is the minimal ER1 representation used by the engine. The
// real client fills this from the ER1 REST API.
type Item struct {
	DocID     string    `json:"id"`
	CtxID     string    `json:"context_id"`
	Tags      []string  `json:"tags,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Client reads and writes against one ER1 context.
type Client interface {
	// GetItem fetches a single ER1 item. Rejects any ctxID other
	// than the one passed to the constructor.
	GetItem(ctxID string, docID string) (Item, error)

	// CreateArtifact persists an Artifact to ER1 (D2: artifacts.created
	// topic is truth, this is the projection). Returns the ER1 doc URI
	// in the form `er1://<ctx>/items/<doc_id>`. Rejects any ctxID
	// other than the constructor's.
	CreateArtifact(ctxID string, a schema.Artifact) (string, error)

	// ListItemsSince returns items newer than `since` (up to limit).
	// Used by the reconciler / /v1/rebuild path.
	ListItemsSince(ctxID string, since time.Time, limit int) ([]Item, error)
}

// Config wires a new HTTP client. All fields are optional; sensible
// defaults are applied.
type Config struct {
	BaseURL    string        // overrides ER1_BASE_URL
	HMACSecret []byte        // overrides THINKING_ENGINE_HMAC_KEY[_<CTX>]
	HTTPClient *http.Client  // overrides the default (Timeout = DefaultTimeout)
	Timeout    time.Duration // overrides DefaultTimeout when HTTPClient is nil
}

// httpClient is the Week-3 real client bound to exactly one ctx.
type httpClient struct {
	owner   mctx.Raw
	ownerID string
	hash    mctx.Hash
	base    string
	secret  []byte
	http    *http.Client
}

// New returns an ER1 client bound to the given context. In-env
// defaults are read eagerly so ctor failures surface early (rather
// than on the first network call).
func New(owner mctx.Raw) Client {
	c, err := NewWithConfig(owner, Config{})
	if err != nil {
		// Preserve the Week-1 signature (no-error). If config is
		// missing we return a degraded client that 500s on every
		// network call; ctx-guard still works because it runs before
		// network I/O.
		return &errClient{owner: owner, err: err}
	}
	return c
}

// NewWithConfig constructs a client with explicit overrides. Tests
// use this to point the client at a fake ER1 server.
func NewWithConfig(owner mctx.Raw, cfg Config) (Client, error) {
	if owner.Value() == "" {
		return nil, errors.New("er1: empty owner ctx")
	}
	hash := owner.Hash()

	base := cfg.BaseURL
	if base == "" {
		base = os.Getenv("ER1_BASE_URL")
	}
	if base == "" {
		base = DefaultBaseURL
	}

	secret := cfg.HMACSecret
	if len(secret) == 0 {
		primary := "THINKING_ENGINE_HMAC_KEY_" + upper(hash.Hex())
		if v := os.Getenv(primary); v != "" {
			secret = []byte(v)
		} else if v := os.Getenv("THINKING_ENGINE_HMAC_KEY"); v != "" {
			secret = []byte(v)
		}
	}
	// Empty secret is legal in dev; CreateArtifact logs and still
	// signs with a zero key. Flask rejects — loud failure is fine.

	h := cfg.HTTPClient
	if h == nil {
		to := cfg.Timeout
		if to <= 0 {
			to = DefaultTimeout
		}
		h = &http.Client{Timeout: to}
	}

	return &httpClient{
		owner:   owner,
		ownerID: owner.Value(),
		hash:    hash,
		base:    base,
		secret:  secret,
		http:    h,
	}, nil
}

// errClient is the fallback when config initialization fails.
type errClient struct {
	owner mctx.Raw
	err   error
}

func (c *errClient) GetItem(ctxID, docID string) (Item, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return Item{}, err
	}
	return Item{}, c.err
}
func (c *errClient) CreateArtifact(ctxID string, a schema.Artifact) (string, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return "", err
	}
	return "", c.err
}
func (c *errClient) ListItemsSince(ctxID string, since time.Time, limit int) ([]Item, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return nil, err
	}
	return nil, c.err
}
func (c *errClient) checkCtx(called string) error {
	if called == "" {
		return errors.New("er1: empty ctxID")
	}
	if called != c.owner.Value() {
		return fmt.Errorf("er1: ctx mismatch — client bound to %s, call used %s",
			redact(c.owner.Value()), redact(called))
	}
	return nil
}

// ----- httpClient methods -----

func (c *httpClient) checkCtx(called string) error {
	if called == "" {
		return errors.New("er1: empty ctxID")
	}
	if called != c.ownerID {
		return fmt.Errorf(
			"er1: ctx mismatch — client bound to %s, call used %s",
			redact(c.ownerID), redact(called),
		)
	}
	return nil
}

func (c *httpClient) GetItem(ctxID, docID string) (Item, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return Item{}, err
	}
	if docID == "" {
		return Item{}, errors.New("er1: empty docID")
	}
	path := "/memory/" + url.PathEscape(ctxID) + "/" + url.PathEscape(docID)

	var out Item
	if err := c.do(context.Background(), http.MethodGet, path, nil, &out); err != nil {
		return Item{}, err
	}
	if out.DocID == "" {
		out.DocID = docID
	}
	if out.CtxID == "" {
		out.CtxID = ctxID
	}
	return out, nil
}

// artifactEnvelope wraps Artifact in a top-level payload for the ER1
// JSON sink. Keeps the wire shape stable when we later add envelope
// metadata (received_at, sinker_version, ...).
type artifactEnvelope struct {
	Kind     string          `json:"kind"`
	Artifact schema.Artifact `json:"artifact"`
}

// createArtifactResponse is the minimum shape we need from the sink.
type createArtifactResponse struct {
	ID  string `json:"id,omitempty"`
	URI string `json:"er1_ref,omitempty"`
}

func (c *httpClient) CreateArtifact(ctxID string, a schema.Artifact) (string, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return "", err
	}
	if a.ArtifactID == "" {
		return "", errors.New("er1: artifact missing artifact_id")
	}
	path := "/memory/" + url.PathEscape(ctxID) + "/artifacts"
	body := artifactEnvelope{Kind: "artifact", Artifact: a}

	var out createArtifactResponse
	if err := c.do(context.Background(), http.MethodPost, path, body, &out); err != nil {
		return "", err
	}
	if out.URI != "" {
		return out.URI, nil
	}
	// Server didn't echo back a ref — construct canonical one.
	return fmt.Sprintf("er1://%s/items/%s", c.hash.Hex(), a.ArtifactID), nil
}

// listItemsResponse matches aims-core `/memory/<ctx>` response body.
type listItemsResponse struct {
	ContextID string `json:"context_id"`
	Memories  []Item `json:"memories"`
	Limit     int    `json:"limit"`
	Range     string `json:"range"`
}

func (c *httpClient) ListItemsSince(ctxID string, since time.Time, limit int) ([]Item, error) {
	if err := c.checkCtx(ctxID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 500
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("range", "all")
	path := "/memory/" + url.PathEscape(ctxID) + "?" + q.Encode()

	var out listItemsResponse
	if err := c.do(context.Background(), http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if since.IsZero() {
		return out.Memories, nil
	}
	filtered := make([]Item, 0, len(out.Memories))
	for _, it := range out.Memories {
		if it.CreatedAt.After(since) || it.CreatedAt.Equal(since) {
			filtered = append(filtered, it)
		}
	}
	return filtered, nil
}

// do executes an HTTP request with HMAC signing, 5s sync timeout, and
// a single retry on 5xx.
func (c *httpClient) do(ctx context.Context, method, path string, body any, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("er1: marshal body: %w", err)
		}
		bodyBytes = b
	}

	// Separate signed path from the full URL. Signed path is
	// everything before the "?"; Flask signs path-without-query.
	signedPath := path
	if i := indexOfByte(signedPath, '?'); i >= 0 {
		signedPath = signedPath[:i]
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		c.signRequest(req, method, signedPath, bodyBytes)

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("er1: http: %w", err)
			continue // retry once on transport errors
		}
		// We must ensure the body is closed whether we branch or not.
		func() {
			defer resp.Body.Close()
			data, rerr := io.ReadAll(resp.Body)
			if rerr != nil {
				lastErr = fmt.Errorf("er1: read body: %w", rerr)
				return
			}
			if resp.StatusCode >= 500 && resp.StatusCode < 600 {
				lastErr = fmt.Errorf("er1: status %d: %s", resp.StatusCode, truncate(string(data), 200))
				return
			}
			if resp.StatusCode >= 400 {
				lastErr = &HTTPError{Status: resp.StatusCode, Body: string(data)}
				return
			}
			lastErr = nil
			if out != nil && len(data) > 0 {
				if uerr := json.Unmarshal(data, out); uerr != nil {
					lastErr = fmt.Errorf("er1: decode response: %w", uerr)
				}
			}
		}()
		if lastErr == nil {
			return nil
		}
		if _, ok := lastErr.(*HTTPError); ok {
			return lastErr // 4xx — do not retry
		}
	}
	return lastErr
}

// signRequest adds HMAC-SHA256 headers compatible with Flask's
// `thinking_bridge.auth.verify_request`. Canonical string:
//
//	method + "\n" + path + "\n" + sha256_hex(body) + "\n" +
//	timestamp + "\n" + nonce
func (c *httpClient) signRequest(req *http.Request, method, path string, body []byte) {
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	// Nonce: 16 random bytes → 32 hex chars, same shape as Flask.
	nonce := randomHex(16)

	bodyHash := sha256.Sum256(body)
	canonical := method + "\n" + path + "\n" + hex.EncodeToString(bodyHash[:]) + "\n" + ts + "\n" + nonce

	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-M3C-Ctx", c.hash.Hex())
	req.Header.Set("X-M3C-Signature", sig)
	req.Header.Set("X-M3C-Timestamp", ts)
	req.Header.Set("X-M3C-Nonce", nonce)
}

// HTTPError is a non-retriable (4xx) response surfaced to callers so
// the sinker can distinguish permanent failures from transient ones.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("er1: status %d: %s", e.Status, truncate(e.Body, 200))
}

// ----- helpers -----

// redact returns a short-hash-style identifier so logs never carry
// the raw user id. Parallels internal/thinking/ctx.Raw.String().
func redact(s string) string {
	if len(s) <= 4 {
		return "<ctx>"
	}
	return s[:2] + "…" + s[len(s)-2:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}

// randomHex returns 2*n hex chars of crypto-random data. Falls back
// to a timestamp-based nonce if the OS RNG fails (shouldn't happen).
var _randReader = newRandReader()

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := _randReader.Read(buf); err != nil {
		// Fallback: timestamp-derived nonce. Not crypto-strong, but
		// Flask's replay window will still reject true replays, and
		// this code path is a degenerate case.
		ts := time.Now().UnixNano()
		for i := 0; i < n; i++ {
			buf[i] = byte(ts >> (i % 8))
		}
	}
	return hex.EncodeToString(buf)
}
