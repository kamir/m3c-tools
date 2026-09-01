//go:build darwin

package main

import (
	"strings"
	"testing"
)

// TestBuildDeviceHubHTML_EscapesContextID locks the SEC M10 fix: the
// login-callback page interpolates the raw `context_id` query param into HTML,
// so a malicious/MITM'd ER1 redirect could otherwise reflect markup. The value
// must be HTML-escaped before it lands in the page.
func TestBuildDeviceHubHTML_EscapesContextID(t *testing.T) {
	payload := `<script>alert(1)</script>`
	html := buildDeviceHubHTML(payload, "https://er1.example.test")

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("device-hub HTML reflected an unescaped <script> payload (XSS):\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("expected the context_id to appear HTML-escaped (&lt;script&gt;); got:\n%s", html)
	}
}

// TestBuildDeviceHubHTML_EscapesBaseURL guards the defense-in-depth escaping of
// baseURL, which lands in href attributes.
func TestBuildDeviceHubHTML_EscapesBaseURL(t *testing.T) {
	html := buildDeviceHubHTML("user123", `https://er1.test/"><script>x</script>`)
	if strings.Contains(html, `"><script>x</script>`) {
		t.Errorf("baseURL was reflected unescaped into the page:\n%s", html)
	}
}
