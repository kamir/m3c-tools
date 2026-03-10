//go:build darwin

package menubar

import (
	"log"
	"os/exec"
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
				if (u.indexOf("youtube.com/watch") !== -1 || u.indexOf("youtu.be/") !== -1) {
					matches.push(u);
				}
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
		log.Printf("[tabs] browser=%s no youtube tabs", appName)
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
		log.Printf("[tabs] browser=%s no youtube tabs", appName)
	}
	return urls
}
