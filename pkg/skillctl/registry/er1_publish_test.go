package registry

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// fakeER1 emulates the bits of the ER1 server `publish` exercises:
//   - GET /memory/<ctx>/search → returns canned items (for idempotency tests)
//   - POST /upload_2          → records the multipart and returns a doc_id
type fakeER1 struct {
	t          *testing.T
	srv        *httptest.Server
	mu         sync.Mutex
	uploads    []uploadCapture     // every /upload_2 we received
	searchHits map[string][]map[string]any // path query → canned items
	nextDocID  int
}

type uploadCapture struct {
	Tags        string
	ContentType string
	Body        string
	Filename    string
}

func newFakeER1(t *testing.T) *fakeER1 {
	f := &fakeER1{t: t, searchHits: map[string][]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/upload_2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		cap := uploadCapture{
			Tags:        r.FormValue("tags"),
			ContentType: r.FormValue("content_type"),
		}
		if fh, _, err := r.FormFile("transcript_file_ext"); err == nil {
			b, _ := io.ReadAll(fh)
			cap.Body = string(b)
			cap.Filename = ""
		}
		f.mu.Lock()
		f.uploads = append(f.uploads, cap)
		f.nextDocID++
		docID := "doc-" + strings.Repeat("0", 1) + itoa(f.nextDocID)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"doc_id": docID, "message": "ok"})
	})
	// List: SPEC-0225 P5 path. The client uses `/memory/<ctx>?limit=…&range=year`
	// (maindrec dual-auth) and filters client-side; the legacy /search query
	// param is ignored if present. Return every seeded item as a flat list;
	// items must carry a `tags` field (string or list) so the client's
	// itemMatchesAllTags filter does the work.
	mux.HandleFunc("/memory/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		var all []map[string]any
		for needle, items := range f.searchHits {
			_ = needle
			all = append(all, items...)
		}
		f.mu.Unlock()
		out := map[string]any{"memories": hitsToAny(all)}
		_ = json.NewEncoder(w).Encode(out)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func itoa(i int) string {
	return string(rune('0' + i%10))
}

func hitsToAny(xs []map[string]any) []any {
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

func (f *fakeER1) cfg() *er1.Config {
	return &er1.Config{
		APIURL:        f.srv.URL + "/upload_2",
		APIKey:        "test-key",
		ContextID:     "skills",
		ContentType:   "application/m3c-skill-bundle-event",
		UploadTimeout: 10,
		VerifySSL:     false,
	}
}

func (f *fakeER1) seedSearchHit(path string, items []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searchHits[path] = items
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func newSignedAdmitted(t *testing.T, digest string) (map[string]any, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	ev, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       digest,
		Name:               "fetch-contract",
		Version:            "1.0.0",
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
		Signatures: []SignatureRef{
			{Role: "author", IdentityID: "id:kamir@m3c"},
			{Role: "registry", IdentityID: "id:kamir@m3c"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return ev, pub
}

func TestPublishAdmitted_InlineHappyPath(t *testing.T) {
	f := newFakeER1(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	ev, _ := newSignedAdmitted(t, digest)
	skb := []byte("PRETEND THIS IS A .skb")

	res, err := PublishAdmitted(PublishAdmittedOpts{
		ER1Cfg:    f.cfg(),
		ContextID: "skills",
		Event:     ev,
		Skill: SkillMeta{
			Name:            "fetch-contract",
			Version:         "1.0.0",
			BundleDigest:    digest,
			AuthorIdentity:  "id:kamir@m3c",
			GovernanceLevel: "green",
			PackedOnHost:    "workstation",
		},
		SkbBytes:       skb,
		InlineMaxBytes: 1 << 20,
		Now:            time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("PublishAdmitted: %v", err)
	}
	if res.DocID == "" {
		t.Error("expected non-empty DocID")
	}
	if res.Transport != "er1-inline" {
		t.Errorf("transport = %q, want er1-inline", res.Transport)
	}
	if res.BlobURI != "" {
		t.Errorf("blob_uri should be empty for inline, got %q", res.BlobURI)
	}

	// Inspect the captured upload.
	if got := len(f.uploads); got != 1 {
		t.Fatalf("expected 1 upload, got %d", got)
	}
	up := f.uploads[0]
	for _, want := range []string{
		"m3c-skill-bundle",
		"skb-transport-version:1",
		"skill:fetch-contract",
		"skill-version:fetch-contract@1.0.0",
		"skill-digest:" + digest,
		"skill-registry:self",
		"skill-author:id:kamir@m3c",
		"governance:green",
		"host:workstation",
		"transport:er1-inline",
		"claude-code.skill-registry",
		"skill-event:admitted",
	} {
		if !strings.Contains(up.Tags, want) {
			t.Errorf("tag %q missing from %q", want, up.Tags)
		}
	}
	if !strings.Contains(up.Body, "```json") {
		t.Error("body missing ```json fence")
	}
	if !strings.Contains(up.Body, "```skb-base64") {
		t.Error("body missing ```skb-base64 fence (inline tier)")
	}
	if !strings.Contains(up.Body, "envelope_signature") {
		t.Error("body does not carry envelope_signature in the JSON")
	}
}

func TestPublishAdmitted_IdempotentOnDigest(t *testing.T) {
	f := newFakeER1(t)
	digest := "sha256:" + strings.Repeat("b", 64)
	// Pre-seed an existing admitted item carrying the digest tag set the
	// client's filter expects.
	f.seedSearchHit("any-key", []map[string]any{
		{
			"doc_id": "doc-pre-existing",
			"tags": strings.Join([]string{
				"m3c-skill-bundle",
				"skill-registry:self",
				"skill-event:admitted",
				"skill-digest:" + digest,
			}, ","),
		},
	})
	ev, _ := newSignedAdmitted(t, digest)
	res, err := PublishAdmitted(PublishAdmittedOpts{
		ER1Cfg:    f.cfg(),
		ContextID: "skills",
		Event:     ev,
		Skill: SkillMeta{
			Name:            "fetch-contract",
			Version:         "1.0.0",
			BundleDigest:    digest,
			AuthorIdentity:  "id:kamir@m3c",
			GovernanceLevel: "green",
			PackedOnHost:    "workstation",
		},
		SkbBytes:       []byte("any"),
		InlineMaxBytes: 1 << 20,
	})
	if !errors.Is(err, ErrAlreadyPublished) {
		t.Fatalf("err = %v, want ErrAlreadyPublished", err)
	}
	if res == nil || res.DocID != "doc-pre-existing" {
		t.Errorf("expected DocID=doc-pre-existing, got %+v", res)
	}
	if got := len(f.uploads); got != 0 {
		t.Errorf("expected 0 uploads on idempotent skip, got %d", got)
	}
}

func TestPublishAdmitted_ClaimCheckOverflowRequiresFn(t *testing.T) {
	f := newFakeER1(t)
	digest := "sha256:" + strings.Repeat("c", 64)
	ev, _ := newSignedAdmitted(t, digest)
	skb := make([]byte, 1024) // 1 KiB
	for i := range skb {
		skb[i] = byte(i)
	}
	_, err := PublishAdmitted(PublishAdmittedOpts{
		ER1Cfg:    f.cfg(),
		ContextID: "skills",
		Event:     ev,
		Skill: SkillMeta{
			Name: "x", Version: "1.0.0", BundleDigest: digest,
			AuthorIdentity:  "id:kamir@m3c",
			GovernanceLevel: "green", PackedOnHost: "h",
		},
		SkbBytes:       skb,
		InlineMaxBytes: 64, // forces overflow
		ClaimCheckFn:   nil,
	})
	if !errors.Is(err, ErrClaimCheckNotImplemented) {
		t.Errorf("err = %v, want ErrClaimCheckNotImplemented", err)
	}
}

func TestPublishAdmitted_ClaimCheckCallsFnAndOmitsInlineBlock(t *testing.T) {
	f := newFakeER1(t)
	digest := "sha256:" + strings.Repeat("d", 64)
	ev, _ := newSignedAdmitted(t, digest)
	skb := make([]byte, 1024)
	called := false
	res, err := PublishAdmitted(PublishAdmittedOpts{
		ER1Cfg:    f.cfg(),
		ContextID: "skills",
		Event:     ev,
		Skill: SkillMeta{
			Name: "big", Version: "1.0.0", BundleDigest: digest,
			AuthorIdentity:  "id:kamir@m3c",
			GovernanceLevel: "green", PackedOnHost: "h",
		},
		SkbBytes:       skb,
		InlineMaxBytes: 64,
		ClaimCheckFn: func(b []byte, d string) (string, error) {
			called = true
			if d != digest {
				t.Errorf("claim-check called with digest %q, want %q", d, digest)
			}
			if len(b) != len(skb) {
				t.Errorf("claim-check called with %d bytes, want %d", len(b), len(skb))
			}
			return "minio://m3c-homelab/skill-bundles-self/" + d, nil
		},
	})
	if err != nil {
		t.Fatalf("PublishAdmitted: %v", err)
	}
	if !called {
		t.Error("ClaimCheckFn was not invoked")
	}
	if res.Transport != "er1-claimcheck" {
		t.Errorf("transport = %q, want er1-claimcheck", res.Transport)
	}
	if !strings.HasPrefix(res.BlobURI, "minio://") {
		t.Errorf("blob_uri = %q, want minio:// scheme", res.BlobURI)
	}
	if len(f.uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(f.uploads))
	}
	body := f.uploads[0].Body
	if strings.Contains(body, "```skb-base64") {
		t.Error("claim-check body must NOT carry inline skb-base64 block")
	}
	if !strings.Contains(f.uploads[0].Tags, "transport:er1-claimcheck") {
		t.Errorf("transport:er1-claimcheck tag missing: tags=%q", f.uploads[0].Tags)
	}
	if !strings.Contains(body, "blob_uri") {
		t.Error("claim-check body should mention blob_uri (markdown header + envelope JSON)")
	}
}

func TestPublishAdmitted_RejectsUnsignedEvent(t *testing.T) {
	f := newFakeER1(t)
	digest := "sha256:" + strings.Repeat("e", 64)
	ev, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       digest,
		Name:               "x",
		Version:            "1.0.0",
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:kamir@m3c",
		AdmittedAt:         time.Now(),
		Signatures: []SignatureRef{
			{Role: "author"}, {Role: "registry"},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// NOTE: not signed.
	_, err = PublishAdmitted(PublishAdmittedOpts{
		ER1Cfg:    f.cfg(),
		ContextID: "skills",
		Event:     ev,
		Skill: SkillMeta{
			Name: "x", Version: "1.0.0", BundleDigest: digest,
			AuthorIdentity:  "id:kamir@m3c",
			GovernanceLevel: "green", PackedOnHost: "h",
		},
		SkbBytes:       []byte("x"),
		InlineMaxBytes: 1024,
	})
	if err == nil || !strings.Contains(err.Error(), "envelope_signature") {
		t.Errorf("expected envelope_signature error, got %v", err)
	}
}

func TestBuildInstalledTags(t *testing.T) {
	tags := BuildInstalledTags(SkillMeta{
		Name: "fetch-contract", Version: "1.0.0",
		BundleDigest:   "sha256:" + strings.Repeat("a", 64),
		AuthorIdentity: "id:kamir@m3c",
	}, "macbookpro-intel")
	joined := strings.Join(tags, ",")
	for _, want := range []string{
		"skill-event:installed",
		"host:macbookpro-intel",
		"skill:fetch-contract",
		"skill-registry:self",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("install tag %q missing from %q", want, joined)
		}
	}
}
