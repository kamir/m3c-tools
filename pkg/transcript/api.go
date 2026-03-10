package transcript

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

var videoIDRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{11}$`)

// API is the main entry point for fetching YouTube transcripts.
type API struct {
	fetcher *Fetcher
}

// New creates a new transcript API with no proxy.
func New() *API {
	f, _ := NewFetcher(nil) // no proxy, no error possible
	return &API{fetcher: f}
}

// NewWithProxy creates a new transcript API with proxy support.
func NewWithProxy(proxy ProxyConfig) (*API, error) {
	f, err := NewFetcher(proxy)
	if err != nil {
		return nil, err
	}
	return &API{fetcher: f}, nil
}

// List returns all available transcripts for a video.
func (a *API) List(videoID string) (*TranscriptList, error) {
	if !videoIDRE.MatchString(videoID) {
		return nil, NewInvalidVideoIDError(videoID)
	}

	// Step 1: Fetch video page to get the InnerTube API key
	html, err := a.fetcher.FetchVideoPage(videoID)
	if err != nil {
		return nil, err
	}

	// Step 2: Extract API key
	apiKey, err := ExtractAPIKey(html)
	if err != nil {
		return nil, NewTranscriptsDisabledError(videoID)
	}

	// Step 3: Call InnerTube API (matches Python library approach)
	innertubeResp, err := a.fetcher.FetchTranscriptViaInnerTube(videoID, apiKey)
	if err != nil {
		return nil, err
	}

	// Step 4: Check playability from InnerTube response
	if err := checkPlayabilityFromJSON(innertubeResp, videoID); err != nil {
		return nil, err
	}

	// Step 5: Extract captions from InnerTube response
	captionsJSON, ok := innertubeResp["captions"].(map[string]any)
	if !ok || captionsJSON == nil {
		return nil, NewTranscriptsDisabledError(videoID)
	}

	infos, err := ParseCaptionsFromJSON(captionsJSON, videoID)
	if err != nil {
		return nil, err
	}

	return &TranscriptList{
		VideoID:     videoID,
		Transcripts: infos,
	}, nil
}

// checkPlayabilityFromJSON checks the playabilityStatus in the InnerTube response.
func checkPlayabilityFromJSON(resp map[string]any, videoID string) error {
	ps, ok := resp["playabilityStatus"].(map[string]any)
	if !ok {
		return NewVideoUnavailableError(videoID)
	}
	status, _ := ps["status"].(string)
	switch status {
	case "OK":
		return nil
	case "LOGIN_REQUIRED":
		return NewAgeRestrictedError(videoID)
	case "UNPLAYABLE", "ERROR":
		return NewVideoUnavailableError(videoID)
	default:
		return NewVideoUnavailableError(videoID)
	}
}

// Fetch fetches a transcript for a video in one of the preferred languages.
// If preserveFormatting is true, HTML formatting tags are kept in the text.
func (a *API) Fetch(videoID string, languages []string, preserveFormatting bool) (*FetchedTranscript, error) {
	log.Printf("[transcript] START video=%s languages=%v", videoID, languages)
	start := time.Now()

	list, err := a.List(videoID)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, err
	}

	info, err := list.FindTranscript(languages)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, err
	}

	result, err := a.fetchFromInfo(videoID, info)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s language=%s error=%v elapsed=%s",
			videoID, info.LanguageCode, err, time.Since(start))
		return nil, err
	}

	charCount := 0
	for _, s := range result.Snippets {
		charCount += len(s.Text)
	}
	log.Printf("[transcript] DONE video=%s snippets=%d chars=%d language=%s generated=%v elapsed=%s",
		result.VideoID, len(result.Snippets), charCount, result.LanguageCode, result.IsGenerated, time.Since(start))

	return result, nil
}

// FetchTranslated fetches a transcript and translates it to the target language.
func (a *API) FetchTranslated(videoID string, sourceLanguages []string, targetLanguage string) (*FetchedTranscript, error) {
	log.Printf("[transcript] START video=%s languages=%v target=%s", videoID, sourceLanguages, targetLanguage)
	start := time.Now()

	list, err := a.List(videoID)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, err
	}

	info, err := list.FindTranscript(sourceLanguages)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, err
	}

	if !info.IsTranslatable {
		err := fmt.Errorf("[%s] transcript in %s is not translatable", videoID, info.LanguageCode)
		log.Printf("[transcript] FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, err
	}

	// Add translation language parameter to the URL
	translatedURL := info.BaseURL + "&tlang=" + targetLanguage

	xmlData, err := a.fetcher.FetchCaptionXML(translatedURL, videoID)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s language=%s error=%v elapsed=%s",
			videoID, targetLanguage, err, time.Since(start))
		return nil, err
	}

	snippets, err := ParseCaptionXML(xmlData)
	if err != nil {
		log.Printf("[transcript] FAIL video=%s error=%v elapsed=%s", videoID, err, time.Since(start))
		return nil, err
	}

	charCount := 0
	for _, s := range snippets {
		charCount += len(s.Text)
	}
	log.Printf("[transcript] DONE video=%s snippets=%d chars=%d language=%s generated=%v elapsed=%s",
		videoID, len(snippets), charCount, targetLanguage, info.IsGenerated, time.Since(start))

	return &FetchedTranscript{
		VideoID:      videoID,
		Language:     targetLanguage,
		LanguageCode: targetLanguage,
		IsGenerated:  info.IsGenerated,
		Snippets:     snippets,
	}, nil
}

// fetchFromInfo fetches the actual caption content from a TranscriptInfo.
func (a *API) fetchFromInfo(videoID string, info *TranscriptInfo) (*FetchedTranscript, error) {
	// Check for PoToken requirement (YouTube anti-bot measure)
	if strings.Contains(info.BaseURL, "&exp=xpe") {
		return nil, fmt.Errorf("[%s] PoToken required: YouTube requires proof-of-origin for this video", videoID)
	}

	xmlData, err := a.fetcher.FetchCaptionXML(info.BaseURL, videoID)
	if err != nil {
		return nil, err
	}

	snippets, err := ParseCaptionXML(xmlData)
	if err != nil {
		return nil, err
	}

	return &FetchedTranscript{
		VideoID:      videoID,
		Language:     info.Language,
		LanguageCode: info.LanguageCode,
		IsGenerated:  info.IsGenerated,
		Snippets:     snippets,
	}, nil
}
