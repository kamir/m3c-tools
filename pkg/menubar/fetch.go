//go:build darwin

// fetch.go — Transcript fetch integration for the menu bar app.
//
// TranscriptFetcher bridges pkg/transcript with the menu bar, providing
// a high-level FetchAndDisplay method that fetches a YouTube transcript,
// formats it as text, copies it to the clipboard, updates the app status
// and history, and reports results back to the user.
//
// Rate-limit mitigations:
//   - Local cache: ~/.m3c-tools/cache/transcripts/<videoID>.json (7-day TTL)
//   - Proxy support: set YT_PROXY_URL (+ YT_PROXY_AUTH) in .env
//   - Graceful degradation: on 429, proceeds without transcript text
package menubar

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

// TranscriptFetcher fetches YouTube transcripts and integrates results
// with the menu bar App state (status, history, clipboard).
type TranscriptFetcher struct {
	api       *transcript.API
	formatter transcript.Formatter
	languages []string // preferred language codes, e.g. ["en", "de"]
	cache     *transcriptCache
}

// FetchResult holds the outcome of a transcript fetch operation.
type FetchResult struct {
	VideoID      string `json:"video_id"`
	Language     string `json:"language"`
	LanguageCode string `json:"language_code"`
	SnippetCount int    `json:"snippet_count"`
	CharCount    int    `json:"char_count"`
	Text         string `json:"text"`
	Flag         string `json:"flag"`
	RateLimited  bool   `json:"rate_limited,omitempty"`
	FromCache    bool   `json:"from_cache,omitempty"`
}

// NewTranscriptFetcher creates a fetcher with default settings.
// If YT_PROXY_URL is set in the environment, proxy support is enabled.
func NewTranscriptFetcher() *TranscriptFetcher {
	return &TranscriptFetcher{
		api:       buildAPI(),
		formatter: transcript.TextFormatter{},
		languages: []string{"en", "de", "fr", "es"},
		cache:     newTranscriptCache(),
	}
}

// NewTranscriptFetcherWithLanguages creates a fetcher with custom language preferences.
func NewTranscriptFetcherWithLanguages(languages []string) *TranscriptFetcher {
	return &TranscriptFetcher{
		api:       buildAPI(),
		formatter: transcript.TextFormatter{},
		languages: languages,
		cache:     newTranscriptCache(),
	}
}

// buildAPI creates a transcript.API, using a proxy if YT_PROXY_URL is set.
func buildAPI() *transcript.API {
	proxyURL := os.Getenv("YT_PROXY_URL")
	if proxyURL != "" {
		proxy := &transcript.GenericProxyConfig{
			ProxyURL:  proxyURL,
			ProxyAuth: os.Getenv("YT_PROXY_AUTH"),
		}
		api, err := transcript.NewWithProxy(proxy)
		if err != nil {
			log.Printf("[fetch] proxy setup failed (falling back to direct): %v", err)
			return transcript.New()
		}
		redacted := proxyURL
		if u, pErr := url.Parse(proxyURL); pErr == nil && u.User != nil {
			u.User = nil
			redacted = u.String()
		}
		log.Printf("[fetch] using proxy: %s", redacted)
		return api
	}
	return transcript.New()
}

// SetFormatter sets the output formatter (text, srt, json, webvtt, etc.).
func (tf *TranscriptFetcher) SetFormatter(f transcript.Formatter) {
	tf.formatter = f
}

// SetLanguages sets the preferred language codes for transcript selection.
func (tf *TranscriptFetcher) SetLanguages(langs []string) {
	tf.languages = langs
}

// Fetch fetches a transcript for the given video ID and returns the result.
// It checks the local cache first, then falls back to the YouTube API.
// On rate limit (429), returns a partial result with RateLimited=true
// instead of an error (graceful degradation).
func (tf *TranscriptFetcher) Fetch(videoID string) (*FetchResult, error) {
	videoID = CleanVideoID(videoID)
	if videoID == "" {
		return nil, fmt.Errorf("empty video ID")
	}

	// Check cache first.
	if cached := tf.cache.Get(videoID); cached != nil {
		cached.FromCache = true
		return cached, nil
	}

	log.Printf("[menubar] transcript fetch START video=%s languages=%v", videoID, tf.languages)
	start := time.Now()

	fetched, err := tf.api.Fetch(videoID, tf.languages, false)
	if err != nil {
		log.Printf("[menubar] transcript fetch FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))

		// Graceful degradation: on rate limit, return partial result.
		var rateLimitErr *transcript.TooManyRequestsError
		if errors.As(err, &rateLimitErr) {
			log.Printf("[menubar] rate limited — proceeding without transcript for video=%s", videoID)
			return &FetchResult{
				VideoID:     videoID,
				RateLimited: true,
				Flag:        "⚠️",
			}, nil
		}

		return nil, fmt.Errorf("fetch transcript: %w", err)
	}

	text := tf.formatter.FormatTranscript(fetched)
	charCount := len(strings.TrimSpace(text))

	flag := transcript.FlagForLanguage(fetched.LanguageCode)

	log.Printf("[menubar] transcript fetch DONE video=%s snippets=%d chars=%d language=%s generated=%v elapsed=%s",
		videoID, len(fetched.Snippets), charCount, fetched.LanguageCode, fetched.IsGenerated, time.Since(start))

	result := &FetchResult{
		VideoID:      videoID,
		Language:     fetched.Language,
		LanguageCode: fetched.LanguageCode,
		SnippetCount: len(fetched.Snippets),
		CharCount:    charCount,
		Text:         text,
		Flag:         flag,
	}

	// Store in cache for future use.
	tf.cache.Put(videoID, result)

	return result, nil
}

// FetchAndDisplay fetches a transcript, fetches the video thumbnail, opens
// the Observation Window with the thumbnail and pre-filled tags (video ID +
// youtube), copies the transcript to the clipboard, updates the App status
// and history, and sends notifications.
// This is the main entry point called from the menu bar action handler.
func (tf *TranscriptFetcher) FetchAndDisplay(app *App, videoID string) {
	app.SetStatus(StatusFetching)
	app.notify("Fetching...", fmt.Sprintf("Fetching transcript for %s", videoID))

	result, err := tf.Fetch(videoID)
	if err != nil {
		app.SetStatus(StatusError)
		app.notify("Error", fmt.Sprintf("Failed to fetch transcript: %s", err))
		return
	}

	// Handle rate-limited result (graceful degradation).
	if result.RateLimited {
		app.notify("Rate Limited", fmt.Sprintf("YouTube rate limit for %s — proceeding without transcript", videoID))
	}

	// Copy transcript text to clipboard (skip if rate-limited/empty).
	if result.Text != "" {
		if err := CopyToClipboard(result.Text); err != nil {
			app.SetStatus(StatusError)
			app.notify("Error", fmt.Sprintf("Failed to copy to clipboard: %s", err))
			return
		}
	}

	// Add to history
	app.AddHistory(NewHistoryEntry(result.VideoID, result.Flag))

	// Fetch thumbnail and open Observation Window
	thumbnailPath := tf.FetchAndSaveThumbnail(result.VideoID)

	meta := &ReviewMetadata{
		Source:       "YouTube",
		Language:     result.Language,
		SnippetCount: result.SnippetCount,
		CharCount:    result.CharCount,
		Date:         time.Now().Format("2006-01-02 15:04:05"),
	}

	transcriptText := result.Text
	if result.RateLimited {
		transcriptText = "[Transcript unavailable — YouTube rate limit (429). Try again later or configure YT_PROXY_URL in .env]"
	}

	if result.FromCache {
		meta.Source = "YouTube (cached)"
	}

	log.Printf("[menubar] opening observation window video=%s thumbnail=%s cached=%v rate_limited=%v",
		result.VideoID, thumbnailPath, result.FromCache, result.RateLimited)
	ShowObservationWindowForYouTube(thumbnailPath, result.VideoID, meta, transcriptText)

	// Update status
	app.SetStatus(StatusIdle)

	// Notify user
	if result.RateLimited {
		app.notify("Observation Ready",
			fmt.Sprintf("⚠️ %s — rate limited, no transcript", result.VideoID))
	} else {
		source := ""
		if result.FromCache {
			source = " (cached)"
		}
		app.notify("Transcript Ready",
			fmt.Sprintf("%s %s%s — %d snippets, %d chars copied to clipboard",
				result.Flag, result.VideoID, source, result.SnippetCount, result.CharCount))
	}
}

// FetchAndSaveThumbnail downloads the YouTube video thumbnail and saves it
// to a temporary file. Returns the file path, or empty string if the
// thumbnail could not be fetched (non-fatal — the window opens without image).
func (tf *TranscriptFetcher) FetchAndSaveThumbnail(videoID string) string {
	log.Printf("[menubar] fetching thumbnail for video=%s", videoID)
	data, err := tf.api.FetchThumbnail(videoID)
	if err != nil {
		log.Printf("[menubar] thumbnail fetch failed video=%s error=%v (non-fatal)", videoID, err)
		return ""
	}

	// Save to temp file
	tmpDir := os.TempDir()
	thumbPath := filepath.Join(tmpDir, fmt.Sprintf("m3c-thumb-%s.jpg", videoID))
	if err := os.WriteFile(thumbPath, data, 0644); err != nil {
		log.Printf("[menubar] thumbnail save failed path=%s error=%v (non-fatal)", thumbPath, err)
		return ""
	}

	log.Printf("[menubar] thumbnail saved path=%s size=%d bytes", thumbPath, len(data))
	return thumbPath
}

// WireToApp returns a Handlers.OnAction callback that dispatches
// ActionFetchTranscript events to this fetcher. Other actions are
// passed through to the optional fallback handler.
func (tf *TranscriptFetcher) WireToApp(fallback ActionCallback) ActionCallback {
	return func(action ActionType, data string) {
		if action == ActionFetchTranscript {
			// Run in background to avoid blocking the menu bar
			go tf.FetchAndDisplay(nil, data)
			return
		}
		if fallback != nil {
			fallback(action, data)
		}
	}
}

// WireToAppInstance returns a Handlers.OnAction callback that dispatches
// ActionFetchTranscript events to this fetcher using the provided App
// for status and history updates. Other actions pass through to fallback.
func (tf *TranscriptFetcher) WireToAppInstance(app *App, fallback ActionCallback) ActionCallback {
	return func(action ActionType, data string) {
		if action == ActionFetchTranscript {
			go tf.FetchAndDisplay(app, data)
			return
		}
		if fallback != nil {
			fallback(action, data)
		}
	}
}
