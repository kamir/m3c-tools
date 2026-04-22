// http_registry.go — Flask-hosted prompt registry client (D1).
//
// Protocol (from PLAN-0167 §Contract: Prompt Registry HTTP API):
//
//   GET /api/prompts/<prompt_id>
//     If-None-Match: <etag>   (optional)
//   → 200 + ETag + body          | on fresh/changed
//     304 Not Modified           | when ETag matches
//     404 / 401                  | error paths
//
// Client behaviour:
//   * 5-minute TTL in-memory cache keyed by prompt_id.
//   * SQLite mirror (store.PromptCache*) for cross-restart survival.
//   * Cache-hit fresh (within TTL): serve from cache, no HTTP.
//   * Cache-hit stale (past TTL): issue GET with If-None-Match; on
//     304 refresh timestamp + serve; on 200 replace; on network
//     failure within an extended window, serve stale with a warning
//     log so reflections still run during Flask outages.
//   * Auth: HMAC bearer via internal/thinking/api.SignToken so the
//     engine signs the same way the Flask bridge does.
package prompts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// DefaultTTL is D1's 5-minute cache TTL.
const DefaultTTL = 5 * time.Minute

// OfflineGraceWindow is how long we'll keep serving stale cache
// entries during Flask outages before surfacing the error. Set to
// 2x TTL so a single failed revalidation doesn't break reflections.
const OfflineGraceWindow = 10 * time.Minute

// HTTPConfig configures the Flask-backed registry client.
type HTTPConfig struct {
	// BaseURL is the registry prefix, e.g. "http://localhost:5000/api/prompts/".
	// Trailing slash is required; constructor will add it if missing.
	BaseURL string

	// TTL is the revalidation window. Defaults to DefaultTTL.
	TTL time.Duration

	// TokenProvider returns a valid bearer token for the next request.
	// Called per-GET so short-lived tokens rotate cleanly. If nil, no
	// Authorization header is sent (dev/local only).
	TokenProvider func() string

	// HTTPClient overrides the default client (tests).
	HTTPClient *http.Client

	// Store, when non-nil, is used as the SQLite mirror for
	// cross-restart cache survival.
	Store *store.Store

	// Logger for warnings (stale-cache fallback, etc.). Defaults to
	// log.Default().
	Logger *log.Logger
}

// ----- HTTP Registry -----

// httpRegistry is the D1 Flask-backed prompt Registry.
type httpRegistry struct {
	cfg    HTTPConfig
	client *http.Client
	log    *log.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	Prompt     Prompt
	ETag       string
	FetchedAt  time.Time
	// LastVerifiedAt is the last time we revalidated (either by hitting
	// the server and getting 304, or by a fresh 200).
	LastVerifiedAt time.Time
}

// NewHTTPRegistry returns an ETag-cached HTTP-backed Registry.
// Replaces the Week 1 stub; see prompts/registry.go for the shared
// Registry interface + Prompt type.
func NewHTTPRegistry(cfg HTTPConfig) (Registry, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("prompts/http: BaseURL required")
	}
	if !strings.HasSuffix(cfg.BaseURL, "/") {
		cfg.BaseURL += "/"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	r := &httpRegistry{
		cfg:    cfg,
		client: cfg.HTTPClient,
		log:    cfg.Logger,
		cache:  make(map[string]cacheEntry),
	}
	// Warm the in-memory cache from SQLite mirror if provided.
	if cfg.Store != nil {
		rows, err := cfg.Store.LoadPromptCache()
		if err == nil {
			for _, row := range rows {
				r.cache[row.ID] = cacheEntry{
					Prompt: Prompt{
						ID:      row.ID,
						Version: row.Version,
						Body:    row.Body,
						Model:   row.Model,
					},
					ETag:           row.ETag,
					FetchedAt:      row.FetchedAt,
					LastVerifiedAt: row.FetchedAt,
				}
			}
		}
	}
	return r, nil
}

// Get resolves id, honoring TTL + ETag revalidation.
func (r *httpRegistry) Get(ctx context.Context, id string) (Prompt, error) {
	r.mu.Lock()
	entry, hasCache := r.cache[id]
	r.mu.Unlock()

	now := time.Now()
	if hasCache && now.Sub(entry.LastVerifiedAt) < r.cfg.TTL {
		// Fresh — serve cache.
		return entry.Prompt, nil
	}

	// Need to revalidate. Send If-None-Match when we have one.
	url := r.cfg.BaseURL + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Prompt{}, fmt.Errorf("prompts/http: request: %w", err)
	}
	if hasCache && entry.ETag != "" {
		req.Header.Set("If-None-Match", entry.ETag)
	}
	if r.cfg.TokenProvider != nil {
		if tok := r.cfg.TokenProvider(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		// Network failure. If we have a usable cache entry within the
		// grace window, serve it and log a warning — don't fail
		// reflections on a transient Flask outage.
		if hasCache && now.Sub(entry.LastVerifiedAt) < OfflineGraceWindow {
			r.log.Printf("prompts/http: serving stale cache for %q during Flask outage: %v", id, err)
			return entry.Prompt, nil
		}
		return Prompt{}, fmt.Errorf("prompts/http: fetch %s: %w", id, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if !hasCache {
			return Prompt{}, fmt.Errorf("prompts/http: 304 without cache for %q", id)
		}
		// Refresh verified-at + return cached value.
		r.mu.Lock()
		entry.LastVerifiedAt = now
		r.cache[id] = entry
		r.mu.Unlock()
		if r.cfg.Store != nil {
			_ = r.cfg.Store.UpsertPromptCache(store.PromptCacheRow{
				ID: entry.Prompt.ID, Version: entry.Prompt.Version, Body: entry.Prompt.Body,
				Model: entry.Prompt.Model, ETag: entry.ETag, FetchedAt: entry.FetchedAt,
			})
		}
		return entry.Prompt, nil

	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return Prompt{}, fmt.Errorf("prompts/http: read %s: %w", id, err)
		}
		var dto httpPromptDTO
		if err := json.Unmarshal(body, &dto); err != nil {
			return Prompt{}, fmt.Errorf("prompts/http: decode %s: %w", id, err)
		}
		p := Prompt{
			ID:      dto.PromptID,
			Version: dto.Version,
			Body:    dto.Template,
			Model:   dto.ModelHint,
		}
		if p.ID == "" {
			p.ID = id // allow servers that echo the id only in the URL
		}
		etag := resp.Header.Get("ETag")
		fresh := cacheEntry{
			Prompt:         p,
			ETag:           etag,
			FetchedAt:      now,
			LastVerifiedAt: now,
		}
		r.mu.Lock()
		r.cache[id] = fresh
		r.mu.Unlock()
		if r.cfg.Store != nil {
			_ = r.cfg.Store.UpsertPromptCache(store.PromptCacheRow{
				ID: p.ID, Version: p.Version, Body: p.Body, Model: p.Model,
				ETag: etag, FetchedAt: now,
			})
		}
		return p, nil

	case http.StatusNotFound:
		return Prompt{}, fmt.Errorf("prompts/http: not found: %s", id)

	case http.StatusUnauthorized:
		return Prompt{}, fmt.Errorf("prompts/http: unauthorized fetching %s", id)

	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Prompt{}, fmt.Errorf("prompts/http: %s -> %d: %s",
			id, resp.StatusCode, bytes.TrimSpace(body))
	}
}

// httpPromptDTO mirrors the server's JSON wire format (contract from
// PLAN-0167 §Contract: Prompt Registry HTTP API).
type httpPromptDTO struct {
	PromptID  string   `json:"prompt_id"`
	Version   int      `json:"version"`
	Template  string   `json:"template"`
	Variables []string `json:"variables,omitempty"`
	ModelHint string   `json:"model_hint,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}
