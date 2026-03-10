// fetch.go — Transcript fetch integration for the menu bar app.
//
// TranscriptFetcher bridges pkg/transcript with the menu bar, providing
// a high-level FetchAndDisplay method that fetches a YouTube transcript,
// formats it as text, copies it to the clipboard, updates the app status
// and history, and reports results back to the user.
package menubar

import (
	"fmt"
	"log"
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
}

// FetchResult holds the outcome of a transcript fetch operation.
type FetchResult struct {
	VideoID      string
	Language     string
	LanguageCode string
	SnippetCount int
	CharCount    int
	Text         string // formatted transcript text
	Flag         string // language flag emoji
}

// NewTranscriptFetcher creates a fetcher with default settings (no proxy,
// text formatter, English preferred).
func NewTranscriptFetcher() *TranscriptFetcher {
	return &TranscriptFetcher{
		api:       transcript.New(),
		formatter: transcript.TextFormatter{},
		languages: []string{"en", "de", "fr", "es"},
	}
}

// NewTranscriptFetcherWithLanguages creates a fetcher with custom language preferences.
func NewTranscriptFetcherWithLanguages(languages []string) *TranscriptFetcher {
	return &TranscriptFetcher{
		api:       transcript.New(),
		formatter: transcript.TextFormatter{},
		languages: languages,
	}
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
// This is the core fetch operation without any UI side effects.
func (tf *TranscriptFetcher) Fetch(videoID string) (*FetchResult, error) {
	videoID = CleanVideoID(videoID)
	if videoID == "" {
		return nil, fmt.Errorf("empty video ID")
	}

	log.Printf("[menubar] transcript fetch START video=%s languages=%v", videoID, tf.languages)
	start := time.Now()

	fetched, err := tf.api.Fetch(videoID, tf.languages, false)
	if err != nil {
		log.Printf("[menubar] transcript fetch FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, fmt.Errorf("fetch transcript: %w", err)
	}

	text := tf.formatter.FormatTranscript(fetched)
	charCount := len(strings.TrimSpace(text))

	flag := transcript.FlagForLanguage(fetched.LanguageCode)

	log.Printf("[menubar] transcript fetch DONE video=%s snippets=%d chars=%d language=%s generated=%v elapsed=%s",
		videoID, len(fetched.Snippets), charCount, fetched.LanguageCode, fetched.IsGenerated, time.Since(start))

	return &FetchResult{
		VideoID:      videoID,
		Language:     fetched.Language,
		LanguageCode: fetched.LanguageCode,
		SnippetCount: len(fetched.Snippets),
		CharCount:    charCount,
		Text:         text,
		Flag:         flag,
	}, nil
}

// FetchAndDisplay fetches a transcript, copies it to the clipboard,
// updates the App status and history, and sends notifications.
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

	// Copy transcript text to clipboard
	if err := CopyToClipboard(result.Text); err != nil {
		app.SetStatus(StatusError)
		app.notify("Error", fmt.Sprintf("Failed to copy to clipboard: %s", err))
		return
	}

	// Add to history
	app.AddHistory(NewHistoryEntry(result.VideoID, result.Flag))

	// Update status
	app.SetStatus(StatusIdle)

	// Notify user
	app.notify("Transcript Ready",
		fmt.Sprintf("%s %s — %d snippets, %d chars copied to clipboard",
			result.Flag, result.VideoID, result.SnippetCount, result.CharCount))
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
