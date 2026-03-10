//go:build darwin

package menubar

import (
	"log"
	"net/url"
	"os/exec"
	"path"
	"strings"
)

// SuggestedYouTubeVideoID scans Google Chrome for open YouTube tabs
// and returns the first detected video ID (or empty string if none found).
func SuggestedYouTubeVideoID() string {
	const app = "Google Chrome"
	urls := youTubeURLsFromChrome()
	if len(urls) == 0 {
		log.Printf("[tabs] no open YouTube tabs found in %s", app)
		return ""
	}
	for _, u := range urls {
		log.Printf("[tabs] browser=%s youtube_url=%s", app, u)
	}
	id := CleanVideoID(urls[0])
	if id != "" {
		log.Printf("[tabs] selected video_id=%s from browser=%s", id, app)
		return id
	}
	for _, u := range urls[1:] {
		id = CleanVideoID(u)
		if id != "" {
			log.Printf("[tabs] selected video_id=%s from browser=%s", id, app)
			return id
		}
	}
	log.Printf("[tabs] no valid YouTube video id found in %s tabs", app)
	return ""
}

func youTubeURLsFromChrome() []string {
	urls := chromeTabURLs()
	if len(urls) == 0 {
		return nil
	}
	var matches []string
	for _, u := range urls {
		if strings.Contains(u, "youtube.com/watch") || strings.Contains(u, "youtu.be/") {
			matches = append(matches, u)
		}
	}
	if len(matches) == 0 {
		log.Printf("[tabs] browser=Google Chrome no youtube tabs")
		return nil
	}
	return matches
}

// SuggestedServiceContextID inspects open Chrome tabs for URLs on the same
// ER1 host and extracts the first context ID from /memory/<context>/... URLs.
func SuggestedServiceContextID(serviceBase string) string {
	baseHost := hostForURL(serviceBase)
	if baseHost == "" {
		log.Printf("[auth] could not parse ER1 service host from %q", serviceBase)
		return ""
	}
	urls := chromeTabURLs()
	if len(urls) == 0 {
		log.Printf("[auth] no Chrome tabs available for ER1 context detection")
		return ""
	}
	log.Printf("[auth] inspecting %d Chrome tab URLs for ER1 host=%s", len(urls), baseHost)
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		if !sameHost(baseHost, u.Host) {
			continue
		}
		log.Printf("[auth] matched ER1 host URL: %s", raw)
		if ctx := contextIDFromServiceURL(u); ctx != "" {
			log.Printf("[auth] selected context_id=%s from URL=%s", ctx, raw)
			return ctx
		}
	}
	log.Printf("[auth] no context_id found in Chrome tabs for ER1 host=%s", baseHost)
	return ""
}

func chromeTabURLs() []string {
	script := `
function run() {
	try {
		var chrome = Application("Google Chrome");
		if (!chrome.running()) {
			return "";
		}
		var matches = [];
		var wins = chrome.windows();
		for (var i = 0; i < wins.length; i++) {
			var tabs = wins[i].tabs();
			for (var j = 0; j < tabs.length; j++) {
				var u = tabs[j].url();
				if (!u) {
					continue;
				}
				matches.push(u);
			}
		}
		return matches.join("\n");
	} catch (e) {
		return "__ERR__:" + e.toString();
	}
}
	`

	const appName = "Google Chrome"
	out, err := exec.Command("osascript", "-l", "JavaScript", "-e", script).CombinedOutput()
	if err != nil {
		log.Printf("[tabs] browser=%s inspect failed: %v output=%q", appName, err, strings.TrimSpace(string(out)))
		return nil
	}
	raw := strings.TrimSpace(string(out))
	if strings.HasPrefix(raw, "__ERR__:") {
		log.Printf("[tabs] browser=%s inspect returned script error detail=%q", appName, strings.TrimPrefix(raw, "__ERR__:"))
		return nil
	}
	if raw == "" {
		log.Printf("[tabs] browser=%s no tabs", appName)
		return nil
	}
	lines := strings.Split(raw, "\n")
	var urls []string
	for _, line := range lines {
		u := strings.TrimSpace(line)
		if u == "" {
			continue
		}
		urls = append(urls, u)
	}
	if len(urls) == 0 {
		log.Printf("[tabs] browser=%s no tabs", appName)
	}
	return urls
}

func hostForURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func contextIDFromServiceURL(u *url.URL) string {
	if q := strings.TrimSpace(u.Query().Get("context_id")); q != "" {
		return q
	}
	p := path.Clean(u.Path)
	parts := strings.Split(p, "/")
	// Expect /memory/<context>/<doc_id>
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "memory" {
			ctx := strings.TrimSpace(parts[i+1])
			if ctx != "" {
				return ctx
			}
		}
	}
	return ""
}
