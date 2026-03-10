package transcript

import (
	"encoding/xml"
	"fmt"
	"html"
	"strconv"
	"strings"
)

// xmlTranscript represents the root <transcript> element.
type xmlTranscript struct {
	Texts []xmlText `xml:"text"`
}

// xmlText represents a single <text start="..." dur="...">content</text> element.
type xmlText struct {
	Start    string `xml:"start,attr"`
	Duration string `xml:"dur,attr"`
	Content  string `xml:",chardata"`
}

// ParseCaptionXML parses YouTube's caption XML format into Snippets.
func ParseCaptionXML(xmlData string) ([]Snippet, error) {
	var transcript xmlTranscript
	if err := xml.Unmarshal([]byte(xmlData), &transcript); err != nil {
		return nil, fmt.Errorf("parse caption XML: %w", err)
	}

	snippets := make([]Snippet, 0, len(transcript.Texts))
	for _, t := range transcript.Texts {
		start, err := strconv.ParseFloat(t.Start, 64)
		if err != nil {
			start = 0
		}
		dur, err := strconv.ParseFloat(t.Duration, 64)
		if err != nil {
			dur = 0
		}
		// Unescape HTML entities (YouTube encodes &amp; &#39; etc.)
		text := html.UnescapeString(t.Content)
		// Strip any remaining HTML tags
		text = stripTags(text)
		text = strings.TrimSpace(text)

		snippets = append(snippets, Snippet{
			Text:     text,
			Start:    start,
			Duration: dur,
		})
	}
	return snippets, nil
}

// stripTags removes HTML tags from a string.
func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseCaptionsFromJSON extracts TranscriptInfo entries from the captions JSON structure.
// This handles the nested JSON from YouTube's playerCaptionsTracklistRenderer.
func ParseCaptionsFromJSON(captionsJSON map[string]any, videoID string) ([]TranscriptInfo, error) {
	renderer, ok := captionsJSON["playerCaptionsTracklistRenderer"].(map[string]any)
	if !ok {
		return nil, NewTranscriptsDisabledError(videoID)
	}

	captionTracks, ok := renderer["captionTracks"].([]any)
	if !ok {
		return nil, NewTranscriptNotAvailableError(videoID)
	}

	// Extract translation languages if available
	var translationLangs []TranslationLanguage
	if tlRaw, ok := renderer["translationLanguages"].([]any); ok {
		for _, tl := range tlRaw {
			if tlMap, ok := tl.(map[string]any); ok {
				lang := TranslationLanguage{
					LanguageCode: getStringField(tlMap, "languageCode"),
				}
				if nameMap, ok := tlMap["languageName"].(map[string]any); ok {
					if runs, ok := nameMap["runs"].([]any); ok && len(runs) > 0 {
						if runMap, ok := runs[0].(map[string]any); ok {
							lang.Language = getStringField(runMap, "text")
						}
					} else {
						lang.Language = getStringField(nameMap, "simpleText")
					}
				}
				translationLangs = append(translationLangs, lang)
			}
		}
	}

	infos := make([]TranscriptInfo, 0, len(captionTracks))
	for _, ct := range captionTracks {
		trackMap, ok := ct.(map[string]any)
		if !ok {
			continue
		}

		kind := getStringField(trackMap, "kind")
		isGenerated := kind == "asr"

		langCode := getStringField(trackMap, "languageCode")
		lang := getStringField(trackMap, "name")
		if nameMap, ok := trackMap["name"].(map[string]any); ok {
			if runs, ok := nameMap["runs"].([]any); ok && len(runs) > 0 {
				if runMap, ok := runs[0].(map[string]any); ok {
					lang = getStringField(runMap, "text")
				}
			} else {
				lang = getStringField(nameMap, "simpleText")
			}
		}

		isTranslatable := false
		if _, ok := trackMap["isTranslatable"]; ok {
			isTranslatable = true
		}

		// Strip &fmt=srv3 to get classic XML format (matching Python library)
		baseURL := strings.Replace(getStringField(trackMap, "baseUrl"), "&fmt=srv3", "", 1)

		info := TranscriptInfo{
			Language:             lang,
			LanguageCode:         langCode,
			IsGenerated:          isGenerated,
			IsTranslatable:       isTranslatable,
			BaseURL:              baseURL,
			TranslationLanguages: translationLangs,
		}
		infos = append(infos, info)
	}

	if len(infos) == 0 {
		return nil, NewTranscriptNotAvailableError(videoID)
	}
	return infos, nil
}

func getStringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
