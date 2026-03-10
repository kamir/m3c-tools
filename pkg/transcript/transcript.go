package transcript

// Snippet is a single captioned text segment with timing information.
type Snippet struct {
	Text     string  `json:"text"`
	Start    float64 `json:"start"`
	Duration float64 `json:"duration"`
}

// TranscriptInfo holds metadata about a transcript without the actual content.
type TranscriptInfo struct {
	Language     string
	LanguageCode string
	IsGenerated  bool
	IsTranslatable bool
	BaseURL      string // caption track URL
	TranslationLanguages []TranslationLanguage
}

// TranslationLanguage represents a language a transcript can be translated to.
type TranslationLanguage struct {
	Language     string
	LanguageCode string
}

// FetchedTranscript holds a fetched transcript with its content and metadata.
type FetchedTranscript struct {
	VideoID      string
	Language     string
	LanguageCode string
	IsGenerated  bool
	Snippets     []Snippet
}

// TranscriptList holds all available transcripts for a video.
type TranscriptList struct {
	VideoID     string
	Transcripts []TranscriptInfo
}

// FindTranscript finds the first transcript matching one of the given language codes.
func (tl *TranscriptList) FindTranscript(languages []string) (*TranscriptInfo, error) {
	for _, lang := range languages {
		for i := range tl.Transcripts {
			if tl.Transcripts[i].LanguageCode == lang {
				return &tl.Transcripts[i], nil
			}
		}
	}
	return nil, NewNoTranscriptFoundError(tl.VideoID, languages, tl.Transcripts)
}

// FindGeneratedTranscript finds the first auto-generated transcript matching the languages.
func (tl *TranscriptList) FindGeneratedTranscript(languages []string) (*TranscriptInfo, error) {
	for _, lang := range languages {
		for i := range tl.Transcripts {
			if tl.Transcripts[i].LanguageCode == lang && tl.Transcripts[i].IsGenerated {
				return &tl.Transcripts[i], nil
			}
		}
	}
	return nil, NewNoTranscriptFoundError(tl.VideoID, languages, tl.Transcripts)
}

// FindManualTranscript finds the first manually created transcript matching the languages.
func (tl *TranscriptList) FindManualTranscript(languages []string) (*TranscriptInfo, error) {
	for _, lang := range languages {
		for i := range tl.Transcripts {
			if tl.Transcripts[i].LanguageCode == lang && !tl.Transcripts[i].IsGenerated {
				return &tl.Transcripts[i], nil
			}
		}
	}
	return nil, NewNoTranscriptFoundError(tl.VideoID, languages, tl.Transcripts)
}

// FilterExcludeGenerated returns a new TranscriptList with auto-generated transcripts removed.
func (tl *TranscriptList) FilterExcludeGenerated() *TranscriptList {
	var filtered []TranscriptInfo
	for _, t := range tl.Transcripts {
		if !t.IsGenerated {
			filtered = append(filtered, t)
		}
	}
	return &TranscriptList{VideoID: tl.VideoID, Transcripts: filtered}
}

// FilterExcludeManuallyCreated returns a new TranscriptList with manually created transcripts removed.
func (tl *TranscriptList) FilterExcludeManuallyCreated() *TranscriptList {
	var filtered []TranscriptInfo
	for _, t := range tl.Transcripts {
		if t.IsGenerated {
			filtered = append(filtered, t)
		}
	}
	return &TranscriptList{VideoID: tl.VideoID, Transcripts: filtered}
}

// String returns a human-readable representation of the transcript list.
func (tl *TranscriptList) String() string {
	s := ""
	for _, t := range tl.Transcripts {
		kind := "manual"
		if t.IsGenerated {
			kind = "generated"
		}
		translatable := ""
		if t.IsTranslatable {
			translatable = " [translatable]"
		}
		s += t.Language + " (" + t.LanguageCode + ") " + kind + translatable + "\n"
	}
	return s
}
