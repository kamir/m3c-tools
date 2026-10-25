package httpsafe

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestGETBoundaryContract(t *testing.T) {
	boundary, err := NewGETBoundary("http://127.0.0.1:1234/api/skills", true, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://127.0.0.1:1234/api/skills", "http://127.0.0.1:1234/api/skills/by-name/name", "http://127.0.0.1:1234/api/skills/bundles/sha256:abc?meta=1"} {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil || boundary.Validate(req) != nil {
			t.Fatalf("valid boundary refused: %s %v", raw, err)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:1235/api/skills/x", "https://127.0.0.1:1234/api/skills/x", "http://localhost:1234/api/skills/x", "http://127.0.0.1:1234/api/skills-other/x", "http://127.0.0.1:1234/other", "http://user@127.0.0.1:1234/api/skills/x", "http://127.0.0.1:1234/api/skills/x#fragment", "http://127.0.0.1:1234/api/skills/../skills/x", "http://127.0.0.1:1234/api/skills//x", "http://127.0.0.1:1234/api/skills/%2e%2e/x", "http://127.0.0.1:1234/api/skills/%2fx", "http://127.0.0.1:1234/api/skills/%252fx", "http://127.0.0.1:1234/%61pi/skills/x", "http://127.0.0.1:1234/api/skills/a%5cb"} {
		req, e := http.NewRequest(http.MethodGet, raw, nil)
		if e == nil && boundary.Validate(req) == nil {
			t.Fatalf("escape accepted: %s", raw)
		}
	}
	for _, raw := range []string{"https://example.invalid/api/%61", "https://example.invalid/api/%252f", "https://example.invalid/api//skills", "https://example.invalid/api/../skills"} {
		if _, err := NewGETBoundary(raw, false, 5); err == nil {
			t.Fatalf("ambiguous base accepted: %s", raw)
		}
	}
	for _, base := range []string{"https://example.invalid/caf%C3%A9/skills", "https://EXAMPLE.invalid:0443/api/skills"} {
		b, e := NewGETBoundary(base, false, 5)
		if e != nil {
			t.Fatal(e)
		}
		req, _ := http.NewRequest(http.MethodGet, strings.ReplaceAll(base, ":0443", ":443")+"/item?meta=1", nil)
		if e = b.Validate(req); e != nil {
			t.Fatalf("canonical valid prefix refused: %v", e)
		}
	}
	first, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/skills/first", nil)
	next, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/skills/next", nil)
	next.Response = &http.Response{Header: http.Header{"Location": []string{"next"}}}
	if err := boundary.CheckRedirect(next, []*http.Request{first}); err != nil {
		t.Fatal("relative redirect refused")
	}
	next.Response.Header.Set("Location", "../skills/next")
	if boundary.CheckRedirect(next, []*http.Request{first}) != nil {
		t.Fatal("resolved in-prefix relative redirect refused")
	}
	next.Response.Header.Set("Location", "%2e%2e/skills/next")
	if boundary.CheckRedirect(next, []*http.Request{first}) == nil {
		t.Fatal("encoded dot traversal accepted")
	}
	next.Response = nil
	if boundary.CheckRedirect(next, []*http.Request{first, first, first, first, first}) == nil {
		t.Fatal("chain cap ignored")
	}
	foreign, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1235/api/skills/first", nil)
	if boundary.CheckRedirect(next, []*http.Request{first, foreign}) == nil {
		t.Fatal("intermediate escape ignored")
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		req, _ := http.NewRequest(method, first.URL.String(), strings.NewReader("synthetic-payload"))
		if boundary.Validate(req) == nil {
			t.Fatal("payload route accepted")
		}
	}
	req := first.Clone(first.Context())
	req.Body = io.NopCloser(strings.NewReader("payload"))
	if boundary.Validate(req) == nil {
		t.Fatal("GET payload accepted")
	}
	req = first.Clone(first.Context())
	req.URL = &url.URL{Scheme: "http", Host: "127.0.0.1:1234", Path: "/api/skills/x", RawPath: "/different"}
	if boundary.Validate(req) == nil {
		t.Fatal("inconsistent escaped path accepted")
	}
}
