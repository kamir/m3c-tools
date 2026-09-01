// Package er1login runs the aims-core browser device-pairing flow and returns
// the issued device token. It is the reusable core behind `m3c-tools login` and
// `skillctl login` (FR-0043): a localhost callback server receives the OAuth
// redirect from <baseURL>/v2/signin?next=<callback>, which carries the
// device_token + context_id as query parameters.
package er1login

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Result is the data delivered by the aims-core login redirect.
type Result struct {
	ContextID   string
	DeviceToken string
	UserID      string
	UserName    string
	UserEmail   string
}

// BaseURL derives the ER1 server root from an ER1 API (upload) URL by stripping
// a trailing /upload* path segment, e.g.
//
//	https://host:8081/upload_2  ->  https://host:8081
func BaseURL(apiURL string) string {
	u := strings.TrimSpace(apiURL)
	if idx := strings.LastIndex(u, "/upload"); idx > 0 {
		u = u[:idx]
	}
	return strings.TrimRight(u, "/")
}

// DeviceLogin runs the browser device-pairing flow: it starts a localhost
// callback server, points the browser at <baseURL>/v2/signin?next=<callback>,
// and blocks until the redirect delivers the device token (or the timeout
// elapses). Progress is written to out. When openBrowser is false the URL is
// only printed (for headless / SSH sessions).
func DeviceLogin(baseURL string, openBrowser bool, out io.Writer, timeout time.Duration) (*Result, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("empty ER1 base URL (set ER1_API_URL or pass --base-url)")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start callback server: %w", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate callback nonce: %w", err)
	}
	path := "/skillctl-login-" + hex.EncodeToString(nonce)
	addr := ln.Addr().String()
	callbackURL := "http://" + addr + path
	resultCh := make(chan Result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ctxID := strings.TrimSpace(q.Get("context_id"))
		if ctxID == "" {
			ctxID = strings.TrimSpace(q.Get("user_id"))
		}
		select {
		case resultCh <- Result{
			ContextID:   ctxID,
			DeviceToken: strings.TrimSpace(q.Get("device_token")),
			UserID:      strings.TrimSpace(q.Get("user_id")),
			UserName:    strings.TrimSpace(q.Get("user_name")),
			UserEmail:   strings.TrimSpace(q.Get("user_email")),
		}:
		default:
		}
		// SEC: lock the throwaway page down — no scripts, no remote fetches.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = io.WriteString(w, successHTML)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	loginURL := fmt.Sprintf("%s/v2/signin?next=%s", baseURL, neturl.QueryEscape(callbackURL))
	fmt.Fprintf(out, "Opening browser for login…\nIf it does not open, visit:\n  %s\n\n", loginURL)
	if openBrowser {
		if err := openURL(loginURL); err != nil {
			fmt.Fprintf(out, "(could not open a browser automatically: %v — open the URL above)\n", err)
		}
	}
	fmt.Fprintf(out, "Waiting for login to complete (timeout %s)…\n", timeout)

	select {
	case res := <-resultCh:
		if res.DeviceToken == "" && res.ContextID == "" {
			return nil, fmt.Errorf("login callback carried neither a device token nor a context id")
		}
		return &res, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("login timed out after %s waiting for the browser callback", timeout)
	}
}

const successHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<title>skillctl — logged in</title>` +
	`<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;` +
	`background:#0b0d11;color:#e8eaed;display:grid;place-items:center;height:100vh;margin:0}` +
	`.c{text-align:center}.c h1{color:#16c79a;margin:0 0 8px}.c p{color:#9aa3b2}</style></head>` +
	`<body><div class="c"><h1>✓ Logged in</h1><p>You can close this tab and return to the terminal.</p></div></body></html>`

// openURL best-effort launches the platform browser. Failure is non-fatal —
// the caller has already printed the URL for manual navigation.
func openURL(u string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{u}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", u}
	default:
		name, args = "xdg-open", []string{u}
	}
	return exec.Command(name, args...).Start()
}
