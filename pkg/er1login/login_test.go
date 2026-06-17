package er1login

import (
	"io"
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
