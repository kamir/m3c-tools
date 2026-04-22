package er1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// ----- ctx-guard tests (carry over from Week 1, now against real client) -----

func TestGetItemRejectsForeignCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c, err := NewWithConfig(raw, Config{BaseURL: "http://unused"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetItem("user-B", "doc-1"); err == nil {
		t.Errorf("expected ctx mismatch error")
	}
}

func TestCreateArtifactRejectsForeignCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c, err := NewWithConfig(raw, Config{BaseURL: "http://unused"})
	if err != nil {
		t.Fatal(err)
	}
	art := schema.Artifact{ArtifactID: "a-1", SchemaVer: schema.CurrentSchemaVer}
	if _, err := c.CreateArtifact("user-B", art); err == nil {
		t.Errorf("expected ctx mismatch error")
	}
}

func TestListItemsSinceRejectsForeignCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c, err := NewWithConfig(raw, Config{BaseURL: "http://unused"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListItemsSince("user-B", time.Time{}, 10); err == nil {
		t.Errorf("expected ctx mismatch error")
	}
}

func TestEmptyCtxRejected(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	c, err := NewWithConfig(raw, Config{BaseURL: "http://unused"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetItem("", "doc-1"); err == nil {
		t.Errorf("expected error on empty ctx")
	}
}

// ----- real HTTP round-trip against a fake ER1 server -----

func TestGetItemRoundTrip(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	hash := raw.Hash()
	secret := []byte("test-secret")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/memory/user-A/doc-1" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		// HMAC must verify.
		if err := verifyFakeSig(r, hash.Hex(), secret, nil); err != nil {
			t.Errorf("hmac: %v", err)
			http.Error(w, "bad sig", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"doc-1","context_id":"user-A","tags":["x"],"summary":"hi"}`))
	}))
	defer ts.Close()

	c, err := NewWithConfig(raw, Config{BaseURL: ts.URL, HMACSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	it, err := c.GetItem("user-A", "doc-1")
	if err != nil {
		t.Fatal(err)
	}
	if it.DocID != "doc-1" || it.CtxID != "user-A" || it.Summary != "hi" {
		t.Errorf("bad item: %+v", it)
	}
}

func TestCreateArtifactRoundTrip(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	hash := raw.Hash()
	secret := []byte("test-secret")

	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/memory/user-A/artifacts" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		gotBody, _ = io.ReadAll(r.Body)
		if err := verifyFakeSig(r, hash.Hex(), secret, gotBody); err != nil {
			t.Errorf("hmac: %v", err)
			http.Error(w, "bad sig", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"a-1","er1_ref":"er1://user-A/items/a-1"}`))
	}))
	defer ts.Close()

	c, err := NewWithConfig(raw, Config{BaseURL: ts.URL, HMACSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	art := schema.Artifact{ArtifactID: "a-1", SchemaVer: schema.CurrentSchemaVer, Version: 1, Format: schema.FormatSummary, Audience: schema.AudienceHuman}
	ref, err := c.CreateArtifact("user-A", art)
	if err != nil {
		t.Fatal(err)
	}
	if ref != "er1://user-A/items/a-1" {
		t.Errorf("unexpected ref: %s", ref)
	}

	// Body must contain the artifact envelope.
	var env struct {
		Kind     string          `json:"kind"`
		Artifact schema.Artifact `json:"artifact"`
	}
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if env.Kind != "artifact" || env.Artifact.ArtifactID != "a-1" {
		t.Errorf("unexpected envelope: %+v", env)
	}
}

func TestCreateArtifactSynthesisesRefOnEmptyResponse(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	secret := []byte("test-secret")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204) // no body
	}))
	defer ts.Close()

	c, _ := NewWithConfig(raw, Config{BaseURL: ts.URL, HMACSecret: secret})
	art := schema.Artifact{ArtifactID: "a-1", SchemaVer: schema.CurrentSchemaVer}
	ref, err := c.CreateArtifact("user-A", art)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ref, "/items/a-1") {
		t.Errorf("expected synthesised ref, got %s", ref)
	}
}

func TestListItemsSinceFiltersByTimestamp(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	secret := []byte("test-secret")

	cutoff := time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/memory/user-A") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"context_id":"user-A",
			"limit":500,
			"range":"all",
			"memories":[
				{"id":"old","context_id":"user-A","created_at":"2026-04-10T00:00:00Z"},
				{"id":"fresh","context_id":"user-A","created_at":"2026-04-20T00:00:00Z"}
			]
		}`))
	}))
	defer ts.Close()

	c, _ := NewWithConfig(raw, Config{BaseURL: ts.URL, HMACSecret: secret})
	items, err := c.ListItemsSince("user-A", cutoff, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].DocID != "fresh" {
		t.Errorf("expected only 'fresh' item, got %+v", items)
	}
}

// ----- retry + error behaviour -----

func TestRetriesOn5xxOnce(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	secret := []byte("s")

	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "boom", 503)
			return
		}
		_, _ = w.Write([]byte(`{"id":"doc-1","context_id":"user-A"}`))
	}))
	defer ts.Close()

	c, _ := NewWithConfig(raw, Config{BaseURL: ts.URL, HMACSecret: secret})
	it, err := c.GetItem("user-A", "doc-1")
	if err != nil {
		t.Fatalf("expected success on retry, got %v", err)
	}
	if it.DocID != "doc-1" {
		t.Errorf("unexpected item: %+v", it)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	secret := []byte("s")

	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "not found", 404)
	}))
	defer ts.Close()

	c, _ := NewWithConfig(raw, Config{BaseURL: ts.URL, HMACSecret: secret})
	_, err := c.GetItem("user-A", "doc-1")
	if err == nil {
		t.Fatalf("expected error")
	}
	if _, ok := err.(*HTTPError); !ok {
		t.Errorf("expected *HTTPError, got %T: %v", err, err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (no retry on 4xx), got %d", calls)
	}
}

// ----- HMAC symmetry with Flask (thinking_bridge.auth.verify_request) -----

func TestHMACSymmetryWithFlaskCanonical(t *testing.T) {
	// Replicates the Flask canonical-string construction byte-for-byte
	// and verifies that signRequest produces the same signature.
	raw, _ := mctx.NewRaw("user-A")
	hash := raw.Hash()
	secret := []byte("shared-secret-ffff")

	c, _ := NewWithConfig(raw, Config{BaseURL: "http://x", HMACSecret: secret})
	cc := c.(*httpClient)

	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest("POST", "http://x/memory/user-A/artifacts", nil)
	cc.signRequest(req, "POST", "/memory/user-A/artifacts", body)

	if got := req.Header.Get("X-M3C-Ctx"); got != hash.Hex() {
		t.Errorf("X-M3C-Ctx = %q, want %q", got, hash.Hex())
	}
	sigHeader := req.Header.Get("X-M3C-Signature")
	ts := req.Header.Get("X-M3C-Timestamp")
	nonce := req.Header.Get("X-M3C-Nonce")

	// Compute expected signature the same way Flask does.
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		"POST",
		"/memory/user-A/artifacts",
		hex.EncodeToString(bodyHash[:]),
		ts,
		nonce,
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))
	if sigHeader != want {
		t.Errorf("signature mismatch:\n got  %s\n want %s", sigHeader, want)
	}
}

// verifyFakeSig re-implements Flask's verify_request for the test
// fake server. Any drift between this and signRequest will cause
// every HTTP test to fail, which is the point — it is the symmetry
// check the SPEC requires.
func verifyFakeSig(r *http.Request, wantCtx string, secret, body []byte) error {
	ctx := r.Header.Get("X-M3C-Ctx")
	sig := r.Header.Get("X-M3C-Signature")
	ts := r.Header.Get("X-M3C-Timestamp")
	nonce := r.Header.Get("X-M3C-Nonce")
	if ctx != wantCtx {
		return errMsg("ctx mismatch: got " + ctx)
	}
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		return errMsg("bad timestamp: " + ts)
	}
	if nonce == "" || sig == "" {
		return errMsg("missing nonce/signature")
	}
	bodyHash := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.Path + "\n" + hex.EncodeToString(bodyHash[:]) + "\n" + ts + "\n" + nonce
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))
	if want != sig {
		return errMsg("sig mismatch")
	}
	return nil
}

type errMsg string

func (e errMsg) Error() string { return string(e) }
