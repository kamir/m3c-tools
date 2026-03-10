package impression

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// FilenamePattern defines a date/time pattern to search for in filenames.
// Layout uses Go's reference time (2006-01-02 15:04:05).
type FilenamePattern struct {
	// Regex matches the date/time portion of the filename.
	Regex *regexp.Regexp
	// Layout is the Go time layout for parsing the matched string.
	Layout string
}

// DefaultPatterns are the built-in filename date/time patterns, tried in order.
// More specific (datetime) patterns are listed before less specific (date-only).
var DefaultPatterns = []FilenamePattern{
	// ISO-ish datetime with T separator: 2026-03-09T14-30-00 or 2026-03-09T143000
	{regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})`), "2006-01-02T15-04-05"},
	{regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{6})`), "2006-01-02T150405"},
	// Compact datetime: 20260309-143000 or 20260309_143000
	{regexp.MustCompile(`(\d{8}[-_]\d{6})`), ""},
	// ISO date: 2026-03-09
	{regexp.MustCompile(`(\d{4}-\d{2}-\d{2})`), "2006-01-02"},
	// Compact date: 20260309
	{regexp.MustCompile(`(\d{8})`), "20060102"},
}

// FilenameInfo holds the parsed result from a filename.
type FilenameInfo struct {
	// Tags extracted from the filename (lowercased, non-date parts).
	Tags []string
	// Timestamp parsed from the filename, zero value if none found.
	Timestamp time.Time
	// Extension is the file extension (e.g. ".wav").
	Extension string
	// BaseName is the original filename without directory or extension.
	BaseName string
}

// ParseFilename extracts tags and an optional timestamp from a filename.
// It uses DefaultPatterns to locate date/time strings, then splits the
// remaining text on common separators (underscore, hyphen, space) to
// produce tag tokens. Tokens that are empty or purely numeric are dropped.
func ParseFilename(filename string) FilenameInfo {
	return ParseFilenameWith(filename, DefaultPatterns)
}

// ParseFilenameWith extracts tags and timestamp using custom patterns.
func ParseFilenameWith(filename string, patterns []FilenamePattern) FilenameInfo {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	info := FilenameInfo{
		Extension: ext,
		BaseName:  name,
	}

	// Try each pattern to extract a timestamp.
	remaining := name
	for _, p := range patterns {
		loc := p.Regex.FindStringIndex(remaining)
		if loc == nil {
			continue
		}
		matched := remaining[loc[0]:loc[1]]
		layout := p.Layout
		if layout == "" {
			layout = compactDatetimeLayout(matched)
		}
		if layout == "" {
			continue
		}
		t, err := time.Parse(layout, matched)
		if err != nil {
			continue
		}
		// Validate parsed date is reasonable (year 2000-2099).
		if t.Year() < 2000 || t.Year() > 2099 {
			continue
		}
		info.Timestamp = t
		// Remove the matched portion from the name for tag extraction.
		remaining = remaining[:loc[0]] + " " + remaining[loc[1]:]
		break
	}

	// Extract tags from remaining text.
	info.Tags = extractTags(remaining)
	return info
}

// compactDatetimeLayout returns the Go layout for compact datetime strings
// like "20260309-143000" or "20260309_143000".
func compactDatetimeLayout(s string) string {
	if len(s) != 15 {
		return ""
	}
	sep := string(s[8])
	if sep == "-" || sep == "_" {
		return "20060102" + sep + "150405"
	}
	return ""
}

// extractTags splits text on common separators and returns cleaned tag tokens.
func extractTags(text string) []string {
	// Replace common separators with spaces.
	r := strings.NewReplacer("_", " ", "-", " ", ".", " ")
	normalized := r.Replace(text)

	var tags []string
	for _, word := range strings.Fields(normalized) {
		word = strings.ToLower(strings.TrimSpace(word))
		if word == "" {
			continue
		}
		// Skip purely numeric tokens (leftover date fragments).
		if isNumeric(word) {
			continue
		}
		tags = append(tags, word)
	}
	return tags
}

// isNumeric returns true if every rune in s is a digit.
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
