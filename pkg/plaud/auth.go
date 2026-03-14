package plaud

import (
	"encoding/json"
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

// ExtractTokenFromChrome uses osascript to read localStorage("tokenstr")
// from any open Chrome tab on web.plaud.ai. Returns the token or an error.
// Only works on macOS with Google Chrome.
func ExtractTokenFromChrome() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("browser token extraction only supported on macOS")
	}

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

// OpenPlaudLogin opens web.plaud.ai/login in the default browser.
func OpenPlaudLogin() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("browser open only supported on macOS")
	}
	return exec.Command("open", "https://web.plaud.ai/login").Start()
}
