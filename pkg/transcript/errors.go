package transcript

import (
	"fmt"
	"strings"
)

// TranscriptError is the base error type for all transcript-related errors.
type TranscriptError struct {
	VideoID string
	Msg     string
	Cause   error
}

func (e *TranscriptError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.VideoID, e.Msg, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.VideoID, e.Msg)
}

func (e *TranscriptError) Unwrap() error { return e.Cause }

// TranscriptsDisabledError indicates transcripts are disabled for the video.
type TranscriptsDisabledError struct {
	TranscriptError
}

func NewTranscriptsDisabledError(videoID string) *TranscriptsDisabledError {
	return &TranscriptsDisabledError{
		TranscriptError{VideoID: videoID, Msg: "subtitles are disabled for this video"},
	}
}

// NoTranscriptFoundError indicates no transcript was found for the requested languages.
type NoTranscriptFoundError struct {
	TranscriptError
	RequestedLanguages []string
	Available          []TranscriptInfo
}

func NewNoTranscriptFoundError(videoID string, languages []string, available []TranscriptInfo) *NoTranscriptFoundError {
	avail := make([]string, len(available))
	for i, t := range available {
		avail[i] = fmt.Sprintf("%s (%s)", t.Language, t.LanguageCode)
	}
	msg := fmt.Sprintf(
		"no transcripts found for languages [%s]. Available: [%s]",
		strings.Join(languages, ", "),
		strings.Join(avail, ", "),
	)
	return &NoTranscriptFoundError{
		TranscriptError:    TranscriptError{VideoID: videoID, Msg: msg},
		RequestedLanguages: languages,
		Available:          available,
	}
}

// TranscriptNotAvailableError indicates the video has no transcripts at all.
type TranscriptNotAvailableError struct {
	TranscriptError
}

func NewTranscriptNotAvailableError(videoID string) *TranscriptNotAvailableError {
	return &TranscriptNotAvailableError{
		TranscriptError{VideoID: videoID, Msg: "no transcripts are available for this video"},
	}
}

// VideoUnavailableError indicates the video is unavailable (private, deleted, etc.).
type VideoUnavailableError struct {
	TranscriptError
}

func NewVideoUnavailableError(videoID string) *VideoUnavailableError {
	return &VideoUnavailableError{
		TranscriptError{VideoID: videoID, Msg: "video is unavailable"},
	}
}

// TooManyRequestsError indicates YouTube returned 429 Too Many Requests.
type TooManyRequestsError struct {
	TranscriptError
}

func NewTooManyRequestsError(videoID string) *TooManyRequestsError {
	return &TooManyRequestsError{
		TranscriptError{VideoID: videoID, Msg: "YouTube rate limit (429). Use a proxy or wait."},
	}
}

// InvalidVideoIDError indicates the video ID format is invalid.
type InvalidVideoIDError struct {
	TranscriptError
}

func NewInvalidVideoIDError(videoID string) *InvalidVideoIDError {
	return &InvalidVideoIDError{
		TranscriptError{VideoID: videoID, Msg: "invalid video ID format"},
	}
}

// AgeRestrictedError indicates the video is age-restricted.
type AgeRestrictedError struct {
	TranscriptError
}

func NewAgeRestrictedError(videoID string) *AgeRestrictedError {
	return &AgeRestrictedError{
		TranscriptError{VideoID: videoID, Msg: "video is age-restricted"},
	}
}

// RequestFailedError wraps an HTTP request failure.
type RequestFailedError struct {
	TranscriptError
	StatusCode int
}

func NewRequestFailedError(videoID string, statusCode int) *RequestFailedError {
	return &RequestFailedError{
		TranscriptError: TranscriptError{
			VideoID: videoID,
			Msg:     fmt.Sprintf("request failed with status %d", statusCode),
		},
		StatusCode: statusCode,
	}
}

// FailedToCreateConsentCookieError indicates consent cookie creation failed.
type FailedToCreateConsentCookieError struct {
	TranscriptError
}

func NewFailedToCreateConsentCookieError(videoID string) *FailedToCreateConsentCookieError {
	return &FailedToCreateConsentCookieError{
		TranscriptError{VideoID: videoID, Msg: "failed to create consent cookie"},
	}
}
