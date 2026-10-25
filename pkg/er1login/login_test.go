package er1login

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://h:8081/upload_2":     "https://h:8081",
		"https://h:8081/upload":       "https://h:8081",
		"https://h/api/upload_2":      "https://h/api",
		"https://h:8081/":             "https://h:8081",
		"https://h:8081":              "https://h:8081",
		"  https://h:8081/upload_2  ": "https://h:8081",
	}
	for in, want := range cases {
		if got := BaseURL(in); got != want {
			t.Errorf("BaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeviceLogin_Timeout(t *testing.T) {
	// openBrowser=false → no exec; no one hits the callback → it must time out.
	_, err := DeviceLogin("https://127.0.0.1:65535", false, io.Discard, 80*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}

func TestDeviceLogin_EmptyBase(t *testing.T) {
	if _, err := DeviceLogin("   ", false, io.Discard, time.Second); err == nil {
		t.Fatal("expected error for empty base URL")
	}
}

func TestLoginRejectsUnsafeTargetWithoutProgressOutput(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1", "https://user:synthetic-secret@host.example", "https://host.example/upload_2?synthetic-secret", "https://host.example/#synthetic-secret", "https://host.example/\\bad"} {
		t.Run(raw, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := DeviceLogin(raw, false, &out, time.Millisecond); err == nil || strings.Contains(err.Error(), "synthetic-secret") || out.Len() != 0 {
				t.Fatalf("err=%v output=%q", err, out.String())
			}
			if _, err := LoginBase(raw); err == nil {
				t.Fatal("original URL validation bypassed by suffix removal")
			}
		})
	}
}

func TestLoginBasePreservesHostAndNonterminalPaths(t *testing.T) {
	for raw, want := range map[string]string{
		"https://upload.example":                    "https://upload.example:443",
		"https://a.example/prefix/upload-history":   "https://a.example:443/prefix/upload-history",
		"https://a.example/upload_2/child":          "https://a.example:443/upload_2/child",
		"https://a.example/prefix/upload_2":         "https://a.example:443/prefix",
		"https://a.example/upload/upload_2":         "https://a.example:443/upload",
		"https://a.example/prefix%2Fsegment/upload": "https://a.example:443/prefix%2Fsegment",
	} {
		got, err := LoginBase(raw)
		if err != nil || got != want {
			t.Fatalf("LoginBase(%q)=%q,%v want %q", raw, got, err, want)
		}
	}
}
