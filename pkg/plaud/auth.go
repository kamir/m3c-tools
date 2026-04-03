package plaud

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultMaxTokenAge is the default maximum age before a token triggers a warning.
// FIX-14: Tokens older than this prompt re-authentication.
const DefaultMaxTokenAge = 7 * 24 * time.Hour

// TokenSession holds the Plaud API authentication token.
type TokenSession struct {
	Token   string    `json:"token"`
	SavedAt time.Time `json:"saved_at"`
}

// IsExpired returns true if the token is older than maxAge.
func (s *TokenSession) IsExpired(maxAge time.Duration) bool {
	if s.SavedAt.IsZero() {
		return true // No saved timestamp — treat as expired
	}
	return time.Since(s.SavedAt) > maxAge
}

// LoadToken reads a token session from a JSON file.
// FIX-14: Warns if token is older than DefaultMaxTokenAge.
func LoadToken(path string) (*TokenSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plaud: load token: %w", err)
	}
	var s TokenSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("plaud: parse token: %w", err)
	}
	if s.Token == "" {
		return nil, fmt.Errorf("plaud: token file is empty")
	}
	if s.IsExpired(DefaultMaxTokenAge) {
		age := time.Since(s.SavedAt).Round(time.Hour)
		// FIX C-H02: Refuse expired tokens instead of just warning.
		return nil, fmt.Errorf("plaud: token expired (%s old, saved %s) — run 'plaud auth login' to re-authenticate", age, s.SavedAt.Format(time.RFC3339))
	}
	return &s, nil
}

// SaveToken writes a token session to a JSON file with 0600 permissions.
func SaveToken(path string, session *TokenSession) error {
	if session.SavedAt.IsZero() {
		session.SavedAt = time.Now()
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("plaud: marshal token: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("plaud: create token dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("plaud: write token: %w", err)
	}
	return nil
}

// ExtractTokenFromChrome extracts the Plaud auth token from a running Chrome
// browser. On macOS, uses osascript/JXA. On all platforms, falls back to
// reading Chrome's remote debugging protocol (CDP) on localhost:9222.
//
// If CDP is not available (Chrome not started with debug port), the function
// will automatically launch Chrome with the debug port, open plaud.ai, and
// prompt the user to log in before retrying.
func ExtractTokenFromChrome() (string, error) {
	// On macOS, try osascript/JXA first (no special Chrome launch flags needed).
	if runtime.GOOS == "darwin" {
		token, err := extractTokenOsascript()
		if err == nil {
			return token, nil
		}
		// Fall through to CDP if osascript fails.
	}

	// Try CDP first — Chrome may already be running with debug port.
	token, err := extractTokenCDP()
	if err == nil {
		return token, nil
	}

	// CDP failed — try to launch Chrome automatically.
	fmt.Printf("  Chrome debug port not available: %v\n", err)
	return extractTokenWithAutoLaunch()
}

// extractTokenWithAutoLaunch launches Chrome with the debug port, opens
// plaud.ai, waits for the user to log in, then extracts the token via CDP.
func extractTokenWithAutoLaunch() (string, error) {
	chromePath := findChrome()
	if chromePath == "" {
		return "", fmt.Errorf("chrome not found\n" +
			"Please install Google Chrome, or start it manually with:\n" +
			"  chrome --remote-debugging-port=9222\n" +
			"Then run this command again")
	}

	fmt.Printf("Chrome found: %s\n", chromePath)
	fmt.Println("Launching Chrome with remote debugging enabled...")

	// Launch Chrome with debug port. Use a separate user-data-dir to avoid
	// conflicts with an already-running Chrome instance.
	// FIX-13: Use unpredictable temp dir to prevent symlink attacks on shared systems
	debugDir, err := os.MkdirTemp("", "m3c-chrome-debug-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(debugDir) // Clean up debug profile after use (contains cookies, localStorage)
	cmd := exec.Command(chromePath,
		"--remote-debugging-port=9222",
		"--user-data-dir="+debugDir,
		"https://app.plaud.ai",
	)
	if err := cmd.Start(); err != nil {
		hint := "Try starting Chrome manually with --remote-debugging-port=9222"
		if runtime.GOOS == "windows" {
			hint = fmt.Sprintf("Try running in PowerShell:\n  & \"%s\" --remote-debugging-port=9222", chromePath)
		}
		return "", fmt.Errorf("failed to launch Chrome: %w\n%s", err, hint)
	}

	// Give Chrome a moment to start.
	fmt.Println()
	fmt.Println("  A Chrome window should open with app.plaud.ai.")
	fmt.Println("  Please log in to your Plaud account.")
	fmt.Println()

	// Wait for CDP to become available (up to 30 seconds).
	// Use 127.0.0.1 explicitly to avoid IPv6 resolution issues on Windows
	// where Chrome binds to IPv4 but Go's HTTP client tries IPv6 ([::1]) first.
	cdpReady := false
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		if i > 0 && i%5 == 0 {
			fmt.Printf("  Waiting for Chrome to start... (%ds)\n", i)
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:9222/json")
		if err == nil {
			resp.Body.Close()
			cdpReady = true
			break
		}
	}
	if !cdpReady {
		hint := "Check your firewall settings and try again."
		if runtime.GOOS == "windows" {
			hint = "On Windows, check that Windows Firewall / Defender is not blocking port 9222.\n" +
				"You can also try starting Chrome manually in PowerShell:\n" +
				fmt.Sprintf("  & \"%s\" --remote-debugging-port=9222", chromePath)
		}
		return "", fmt.Errorf("chrome started but CDP port 9222 is not responding\n%s", hint)
	}

	// Prompt the user to confirm they've logged in.
	fmt.Print("  Press Enter after you have logged in to Plaud... ")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
	fmt.Println()

	// Retry CDP extraction with a few attempts (page may still be loading).
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		token, err := extractTokenCDP()
		if err == nil {
			return token, nil
		}
		lastErr = err
		if attempt < 4 {
			fmt.Printf("  Waiting for token... (attempt %d/5)\n", attempt+2)
			time.Sleep(2 * time.Second)
		}
	}

	return "", fmt.Errorf("could not extract token after login: %w — "+
		"make sure you are fully logged in to app.plaud.ai and the page has loaded", lastErr)
}

// ProgressFunc is a callback for reporting progress to callers (e.g. tray tooltip).
type ProgressFunc func(msg string)

// LaunchChromeForPlaud launches Chrome with the remote debugging port and
// opens plaud.ai. It returns a cleanup function that removes the temp profile
// directory. The caller is responsible for calling cleanup when done.
// This is separated from token extraction so tray apps can launch Chrome
// and then poll for the token independently.
func LaunchChromeForPlaud() (cleanup func(), err error) {
	chromePath := findChrome()
	if chromePath == "" {
		return nil, fmt.Errorf("chrome not found — please install Google Chrome")
	}

	debugDir, err := os.MkdirTemp("", "m3c-chrome-debug-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	cmd := exec.Command(chromePath,
		"--remote-debugging-port=9222",
		"--user-data-dir="+debugDir,
		"https://app.plaud.ai",
	)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(debugDir)
		return nil, fmt.Errorf("failed to launch Chrome: %w", err)
	}

	cleanup = func() {
		// Kill Chrome process if still running.
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		os.RemoveAll(debugDir)
	}
	return cleanup, nil
}

// WaitForCDPReady polls the CDP endpoint until Chrome is ready or timeout.
// Returns true if CDP is available, false on timeout.
func WaitForCDPReady(timeout time.Duration, progress ProgressFunc) bool {
	deadline := time.Now().Add(timeout)
	attempt := 0
	for time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		attempt++
		if attempt%5 == 0 && progress != nil {
			remaining := time.Until(deadline).Round(time.Second)
			progress(fmt.Sprintf("Waiting for Chrome to start... (%s remaining)", remaining))
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:9222/json")
		if err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
}

// PollForPlaudToken polls CDP every pollInterval for up to timeout, trying to
// extract the Plaud token. Calls progress (if non-nil) with status updates.
// This is the tray-friendly alternative to extractTokenWithAutoLaunch which
// blocks on stdin — here we just poll until the user logs in.
func PollForPlaudToken(timeout, pollInterval time.Duration, progress ProgressFunc) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		token, err := extractTokenCDP()
		if err == nil {
			return token, nil
		}
		lastErr = err

		remaining := time.Until(deadline).Round(time.Second)
		if progress != nil {
			progress(fmt.Sprintf("Waiting for Plaud login in Chrome... (%s remaining)", remaining))
		}
		time.Sleep(pollInterval)
	}

	return "", fmt.Errorf("timed out waiting for Plaud token: %w", lastErr)
}

// FindChrome locates the Chrome executable on the current platform.
func FindChrome() string {
	return findChrome()
}

func findChrome() string {
	switch runtime.GOOS {
	case "windows":
		candidates := []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
			// Edge as fallback — supports CDP with the same flags.
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		}
		for _, p := range candidates {
			if p == "" {
				continue // env var was empty
			}
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	case "darwin":
		candidates := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			filepath.Join(os.Getenv("HOME"), "Applications", "Google Chrome.app", "Contents", "MacOS", "Google Chrome"),
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	case "linux":
		candidates := []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium-browser",
			"/usr/bin/chromium",
			"/snap/bin/chromium",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	// Last resort: check PATH.
	for _, name := range []string{
		"chrome", "google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser",
		"msedge", // Edge supports CDP with the same flags
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// extractTokenOsascript uses macOS osascript/JXA to read localStorage from Chrome.
func extractTokenOsascript() (string, error) {
	script := `
function run() {
	try {
		var chrome = Application("Google Chrome");
		if (!chrome.running()) return "__ERR__:Chrome not running";
		var wins = chrome.windows();
		for (var i = 0; i < wins.length; i++) {
			var tabs = wins[i].tabs();
			for (var j = 0; j < tabs.length; j++) {
				var u = tabs[j].url();
				if (u && u.indexOf("plaud.ai") !== -1) {
					var token = chrome.execute(tabs[j], {javascript: 'localStorage.getItem("tokenstr")'});
					if (token && token !== "null" && token.length > 10) {
						return token;
					}
				}
			}
		}
		return "__ERR__:no plaud.ai tab with token found";
	} catch(e) {
		return "__ERR__:" + e.message;
	}
}
`
	out, err := exec.Command("osascript", "-l", "JavaScript", "-e", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("osascript failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	result := strings.TrimSpace(string(out))
	if strings.HasPrefix(result, "__ERR__:") {
		return "", fmt.Errorf("%s", strings.TrimPrefix(result, "__ERR__:"))
	}
	if result == "" || result == "null" {
		return "", fmt.Errorf("no token found in Chrome localStorage")
	}
	return result, nil
}

// ExtractTokenCDP connects to Chrome's DevTools Protocol on localhost:9222
// and extracts the Plaud token from any open plaud.ai tab.
// Chrome must be started with --remote-debugging-port=9222 for this to work.
// Exported so tray apps can call it directly for non-interactive polling.
func ExtractTokenCDP() (string, error) {
	return extractTokenCDP()
}

// extractTokenCDP is the internal implementation of ExtractTokenCDP.
func extractTokenCDP() (string, error) {
	// 1. Discover available tabs via /json endpoint.
	// Use 127.0.0.1 explicitly — on Windows, "localhost" may resolve to IPv6 [::1]
	// while Chrome's debug port binds to IPv4 only, causing "connection refused".
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", fmt.Errorf("cannot connect to Chrome DevTools on 127.0.0.1:9222: %w", err)
	}
	defer resp.Body.Close()

	var targets []struct {
		ID          string `json:"id"`
		URL         string `json:"url"`
		WebSocketURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", fmt.Errorf("parse Chrome targets: %w", err)
	}

	// 2. Find a plaud.ai tab.
	for _, t := range targets {
		if strings.Contains(t.URL, "plaud.ai") && t.WebSocketURL != "" {
			token, err := cdpEvaluate(t.WebSocketURL, `localStorage.getItem("tokenstr")`)
			if err != nil {
				continue
			}
			token = strings.Trim(token, "\"")
			if token != "" && token != "null" && len(token) > 10 {
				return token, nil
			}
		}
	}

	return "", fmt.Errorf("no plaud.ai tab with token found in Chrome (checked %d tabs)", len(targets))
}

// cdpEvaluate sends a Runtime.evaluate command over a WebSocket to Chrome.
// This is a minimal CDP client — no external dependencies needed.
func cdpEvaluate(wsURL, expression string) (string, error) {
	// Establish WebSocket connection to Chrome tab.
	conn, err := cdpDial(wsURL)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Send Runtime.evaluate command.
	reqJSON := fmt.Sprintf(`{"id":1,"method":"Runtime.evaluate","params":{"expression":%q,"returnByValue":true}}`, expression)
	if _, err := conn.Write([]byte(cdpFrame(reqJSON))); err != nil {
		return "", fmt.Errorf("send CDP command: %w", err)
	}

	// Read response (simplified: read up to 64KB).
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read CDP response: %w", err)
	}

	// Extract the result value from the JSON response.
	payload := cdpUnframe(buf[:n])
	var result struct {
		Result struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		return "", fmt.Errorf("parse CDP response: %w", err)
	}

	return result.Result.Result.Value, nil
}

// cdpDial performs a minimal WebSocket handshake to a Chrome DevTools URL.
func cdpDial(wsURL string) (net.Conn, error) {
	// Parse ws:// URL into host and path.
	u := strings.TrimPrefix(wsURL, "ws://")
	parts := strings.SplitN(u, "/", 2)
	host := parts[0]
	path := "/"
	if len(parts) > 1 {
		path = "/" + parts[1]
	}

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", host, err)
	}

	// Minimal WebSocket upgrade handshake (RFC 6455).
	key := "dGhlIHNhbXBsZSBub25jZQ==" // static key, fine for local debugging
	handshake := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, key)
	if _, err := conn.Write([]byte(handshake)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Read upgrade response.
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	if !strings.Contains(string(buf[:n]), "101") {
		_ = conn.Close()
		return nil, fmt.Errorf("WebSocket upgrade failed: %s", string(buf[:n]))
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return conn, nil
}

// cdpFrame wraps a text payload in a WebSocket text frame (masked, per RFC 6455).
func cdpFrame(payload string) []byte {
	data := []byte(payload)
	frame := []byte{0x81} // FIN + text opcode
	l := len(data)
	if l < 126 {
		frame = append(frame, byte(l)|0x80) // masked
	} else {
		frame = append(frame, 126|0x80, byte(l>>8), byte(l))
	}
	mask := []byte{0x37, 0xfa, 0x21, 0x3d} // arbitrary mask
	frame = append(frame, mask...)
	masked := make([]byte, l)
	for i := range data {
		masked[i] = data[i] ^ mask[i%4]
	}
	frame = append(frame, masked...)
	return frame
}

// cdpUnframe extracts the payload from a WebSocket frame.
func cdpUnframe(frame []byte) string {
	if len(frame) < 2 {
		return ""
	}
	payloadLen := int(frame[1] & 0x7F)
	offset := 2
	if payloadLen == 126 {
		if len(frame) < 4 {
			return ""
		}
		payloadLen = int(frame[2])<<8 | int(frame[3])
		offset = 4
	}
	if offset+payloadLen > len(frame) {
		payloadLen = len(frame) - offset
	}
	return string(frame[offset : offset+payloadLen])
}

// OpenPlaudLogin opens web.plaud.ai/login in the default browser.
func OpenPlaudLogin() error {
	return OpenBrowser("https://web.plaud.ai/login")
}

// OpenBrowser opens a URL in the platform's default browser.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", "", url).Start() // empty title prevents injection via & in URL
	case "linux":
		return exec.Command("xdg-open", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// CDPEvaluateOnFirstTab connects to Chrome CDP on localhost:9222 and
// evaluates a JS expression on the first available tab.
func CDPEvaluateOnFirstTab(expression string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", fmt.Errorf("cannot connect to Chrome DevTools: %w", err)
	}
	defer resp.Body.Close()

	var targets []struct {
		WebSocketURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", fmt.Errorf("parse targets: %w", err)
	}

	for _, t := range targets {
		if t.WebSocketURL == "" {
			continue
		}
		val, err := cdpEvaluate(t.WebSocketURL, expression)
		if err == nil && val != "" && val != "null" {
			return val, nil
		}
	}
	return "", fmt.Errorf("no result from CDP evaluation")
}
