package plaud

import (
	"encoding/json"
	"net"
	"net/http"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// TokenSession holds the Plaud API authentication token.
type TokenSession struct {
	Token   string    `json:"token"`
	SavedAt time.Time `json:"saved_at"`
}

// LoadToken reads a token session from a JSON file.
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
func ExtractTokenFromChrome() (string, error) {
	// On macOS, try osascript/JXA first (no special Chrome launch flags needed).
	if runtime.GOOS == "darwin" {
		token, err := extractTokenOsascript()
		if err == nil {
			return token, nil
		}
		// Fall through to CDP if osascript fails.
	}

	// Cross-platform fallback: Chrome DevTools Protocol.
	return extractTokenCDP()
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

// extractTokenCDP connects to Chrome's DevTools Protocol on localhost:9222
// and extracts the Plaud token from any open plaud.ai tab.
// Chrome must be started with --remote-debugging-port=9222 for this to work.
func extractTokenCDP() (string, error) {
	// 1. Discover available tabs via /json endpoint.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:9222/json")
	if err != nil {
		return "", fmt.Errorf("cannot connect to Chrome DevTools on localhost:9222: %w\n"+
			"Hint: start Chrome with --remote-debugging-port=9222, or use 'plaud auth <token>' to set the token manually", err)
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
	url := "https://web.plaud.ai/login"
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
