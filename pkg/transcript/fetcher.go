package transcript

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

var (
	apiKeyRE = regexp.MustCompile(`"INNERTUBE_API_KEY"\s*:\s*"([^"]+)"`)
)

// Fetcher handles HTTP communication with YouTube to retrieve transcripts.
type Fetcher struct {
	client *http.Client
}

// NewFetcher creates a fetcher with an optional proxy config.
func NewFetcher(proxy ProxyConfig) (*Fetcher, error) {
	jar, _ := cookiejar.New(nil)

	// Pre-set the consent cookie so it's sent on all requests
	ytURL, _ := url.Parse("https://www.youtube.com")
	jar.SetCookies(ytURL, []*http.Cookie{
		{Name: "CONSENT", Value: "YES+cb", Path: "/", Domain: ".youtube.com"},
	})

	client := &http.Client{Jar: jar}
	if proxy != nil {
		transport, err := proxy.GetTransport()
		if err != nil {
			return nil, fmt.Errorf("proxy setup: %w", err)
		}
		client.Transport = transport
	}
	return &Fetcher{client: client}, nil
}

// FetchVideoPage fetches the YouTube watch page HTML.
func (f *Fetcher) FetchVideoPage(videoID string) (string, error) {
	url := fmt.Sprintf(watchURL, videoID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch video page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return "", NewTooManyRequestsError(videoID)
	}
	if resp.StatusCode != 200 {
		return "", NewRequestFailedError(videoID, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read video page: %w", err)
	}
	return string(body), nil
}

// ExtractAPIKey extracts the InnerTube API key from the video page HTML.
func ExtractAPIKey(html string) (string, error) {
	matches := apiKeyRE.FindStringSubmatch(html)
	if matches == nil {
		return "", fmt.Errorf("could not find INNERTUBE_API_KEY in page")
	}
	return matches[1], nil
}

// FetchCaptionXML fetches the raw caption XML from a caption track URL.
func (f *Fetcher) FetchCaptionXML(captionURL string, videoID string) (string, error) {
	req, err := http.NewRequest("GET", captionURL, nil)
	if err != nil {
		return "", fmt.Errorf("create caption request: %w", err)
	}
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch caption XML: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return "", NewTooManyRequestsError(videoID)
	}
	if resp.StatusCode != 200 {
		return "", NewRequestFailedError(videoID, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read caption XML: %w", err)
	}
	return string(body), nil
}

// FetchTranscriptViaInnerTube uses the InnerTube API to get captions for a video.
// This is the fallback path when captions aren't in the initial page load.
func (f *Fetcher) FetchTranscriptViaInnerTube(videoID string, apiKey string) (map[string]any, error) {
	url := fmt.Sprintf(innertubeAPIURL, apiKey)

	payload := map[string]any{
		"context":     innertubeContext,
		"videoId":     videoID,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal innertube payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("innertube API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, NewTooManyRequestsError(videoID)
	}
	if resp.StatusCode != 200 {
		return nil, NewRequestFailedError(videoID, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read innertube response: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse innertube response: %w", err)
	}
	return result, nil
}
