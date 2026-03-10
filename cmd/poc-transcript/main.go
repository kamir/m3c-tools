// POC 4: YouTube Transcript Fetching (core library port)
//
// Validates:
//   - HTTP fetch of YouTube video page
//   - InnerTube API key extraction
//   - InnerTube API call for captions
//   - Caption XML parsing
//   - Proxy support via http.Transport
//
// Run: go run ./cmd/poc-transcript <video_id>
package main

import (
	"fmt"
	"os"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <video_id> [language]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s dQw4w9WgXcQ en\n", os.Args[0])
		os.Exit(1)
	}

	videoID := os.Args[1]
	lang := "en"
	if len(os.Args) > 2 {
		lang = os.Args[2]
	}

	fmt.Printf("Fetching transcript for video: %s (language: %s)\n\n", videoID, lang)

	api := transcript.New()

	// List available transcripts
	fmt.Println("=== Available Transcripts ===")
	transcriptList, err := api.List(videoID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing transcripts: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(transcriptList)

	// Fetch the transcript
	fmt.Printf("\n=== Fetching '%s' transcript ===\n", lang)
	fetched, err := api.Fetch(videoID, []string{lang}, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching transcript: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Language: %s (%s), Generated: %v, Snippets: %d\n\n",
		fetched.Language, fetched.LanguageCode, fetched.IsGenerated, len(fetched.Snippets))

	// Print first 10 snippets
	limit := 10
	if len(fetched.Snippets) < limit {
		limit = len(fetched.Snippets)
	}
	for i := 0; i < limit; i++ {
		s := fetched.Snippets[i]
		fmt.Printf("[%6.1fs] %s\n", s.Start, s.Text)
	}
	if len(fetched.Snippets) > limit {
		fmt.Printf("... and %d more snippets\n", len(fetched.Snippets)-limit)
	}

	// Test formatters
	fmt.Println("\n=== Text Format ===")
	textFmt := transcript.TextFormatter{}
	text := textFmt.FormatTranscript(fetched)
	lines := 0
	for _, c := range text {
		if c == '\n' {
			lines++
		}
	}
	fmt.Printf("(%d lines, %d chars)\n", lines+1, len(text))

	fmt.Println("\n=== SRT Format (first 3 entries) ===")
	srtFmt := transcript.SRTFormatter{}
	srt := srtFmt.FormatTranscript(fetched)
	// Print first ~300 chars
	if len(srt) > 300 {
		fmt.Println(srt[:300] + "...")
	} else {
		fmt.Println(srt)
	}

	fmt.Println("\nPOC transcript fetch: SUCCESS")
}
