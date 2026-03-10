package transcript

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Formatter formats a FetchedTranscript into a string representation.
type Formatter interface {
	FormatTranscript(t *FetchedTranscript) string
}

// TextFormatter outputs plain text, one line per snippet.
type TextFormatter struct{}

func (f TextFormatter) FormatTranscript(t *FetchedTranscript) string {
	var b strings.Builder
	for _, s := range t.Snippets {
		b.WriteString(s.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

// JSONFormatter outputs the transcript as a JSON array.
type JSONFormatter struct {
	Pretty bool
}

func (f JSONFormatter) FormatTranscript(t *FetchedTranscript) string {
	var data []byte
	var err error
	if f.Pretty {
		data, err = json.MarshalIndent(t.Snippets, "", "  ")
	} else {
		data, err = json.Marshal(t.Snippets)
	}
	if err != nil {
		return "[]"
	}
	return string(data)
}

// SRTFormatter outputs the transcript in SubRip (.srt) subtitle format.
type SRTFormatter struct{}

func (f SRTFormatter) FormatTranscript(t *FetchedTranscript) string {
	var b strings.Builder
	for i, s := range t.Snippets {
		startTime := formatSRTTime(s.Start)
		endTime := formatSRTTime(s.Start + s.Duration)
		fmt.Fprintf(&b, "%d\n%s --> %s\n%s\n\n", i+1, startTime, endTime, s.Text)
	}
	return b.String()
}

// WebVTTFormatter outputs the transcript in WebVTT (.vtt) subtitle format.
type WebVTTFormatter struct{}

func (f WebVTTFormatter) FormatTranscript(t *FetchedTranscript) string {
	var b strings.Builder
	b.WriteString("WEBVTT\n\n")
	for i, s := range t.Snippets {
		startTime := formatVTTTime(s.Start)
		endTime := formatVTTTime(s.Start + s.Duration)
		fmt.Fprintf(&b, "%d\n%s --> %s\n%s\n\n", i+1, startTime, endTime, s.Text)
	}
	return b.String()
}

// formatSRTTime converts seconds to HH:MM:SS,mmm format.
func formatSRTTime(seconds float64) string {
	h := int(seconds) / 3600
	m := (int(seconds) % 3600) / 60
	s := int(seconds) % 60
	ms := int((seconds - float64(int(seconds))) * 1000)
	return fmt.Sprintf("%02d:%02d:%02d,%03d", h, m, s, ms)
}

// formatVTTTime converts seconds to HH:MM:SS.mmm format.
func formatVTTTime(seconds float64) string {
	h := int(seconds) / 3600
	m := (int(seconds) % 3600) / 60
	s := int(seconds) % 60
	ms := int((seconds - float64(int(seconds))) * 1000)
	return fmt.Sprintf("%02d:%02d:%02d.%03d", h, m, s, ms)
}

// PrettyPrintFormatter outputs transcripts and CLI data types in a
// structured, human-readable format with headers, metadata, box-drawing
// characters, and aligned snippet output suitable for terminal display.
type PrettyPrintFormatter struct {
	// ShowTimestamps includes start→end timestamps per snippet (default true).
	ShowTimestamps bool
	// ShowHeader includes a metadata header block (default true).
	ShowHeader bool
	// MaxWidth limits snippet text width; 0 means no limit.
	MaxWidth int
}

// NewPrettyPrintFormatter creates a PrettyPrintFormatter with sensible defaults.
func NewPrettyPrintFormatter() *PrettyPrintFormatter {
	return &PrettyPrintFormatter{
		ShowTimestamps: true,
		ShowHeader:     true,
		MaxWidth:       0,
	}
}

// FormatTranscript formats a FetchedTranscript with structured pretty output.
// Implements the Formatter interface.
func (f PrettyPrintFormatter) FormatTranscript(t *FetchedTranscript) string {
	var b strings.Builder

	if f.ShowHeader {
		f.writeHeader(&b, t)
	}

	for i, s := range t.Snippets {
		if f.ShowTimestamps {
			start := formatPrettyTime(s.Start)
			end := formatPrettyTime(s.Start + s.Duration)
			fmt.Fprintf(&b, "  %3d │ %s → %s │ ", i+1, start, end)
		} else {
			fmt.Fprintf(&b, "  %3d │ ", i+1)
		}
		text := s.Text
		if f.MaxWidth > 0 {
			text = truncateText(text, f.MaxWidth)
		}
		b.WriteString(text)
		b.WriteByte('\n')
	}

	if f.ShowHeader && len(t.Snippets) > 0 {
		b.WriteString(repeatChar('─', 60))
		b.WriteByte('\n')
		totalDur := totalDuration(t.Snippets)
		fmt.Fprintf(&b, "  Total: %d snippets, %s\n", len(t.Snippets), formatPrettyTime(totalDur))
	}

	return b.String()
}

// FormatTranscriptList formats a TranscriptList with structured output
// showing available transcripts with flags, language names, and types.
func (f PrettyPrintFormatter) FormatTranscriptList(tl *TranscriptList) string {
	var b strings.Builder

	fmt.Fprintf(&b, "╭─ Available Transcripts ─ %s\n", tl.VideoID)
	b.WriteString("│\n")

	for i, t := range tl.Transcripts {
		kind := "manual"
		if t.IsGenerated {
			kind = "auto"
		}
		flag := FlagForLanguage(t.LanguageCode)
		translatable := ""
		if t.IsTranslatable {
			translatable = " [translatable]"
		}
		fmt.Fprintf(&b, "│  %2d. %s %-20s %-6s %-8s%s\n",
			i+1, flag, t.Language, "("+t.LanguageCode+")", kind, translatable)
	}

	b.WriteString("│\n")
	fmt.Fprintf(&b, "╰─ %d transcript(s) found\n", len(tl.Transcripts))

	return b.String()
}

// FormatTranscriptInfo formats a single TranscriptInfo as a summary line.
func (f PrettyPrintFormatter) FormatTranscriptInfo(t *TranscriptInfo) string {
	var b strings.Builder

	kind := "Manual"
	if t.IsGenerated {
		kind = "Auto-generated"
	}
	flag := FlagForLanguage(t.LanguageCode)

	fmt.Fprintf(&b, "%s %s (%s) — %s\n", flag, t.Language, t.LanguageCode, kind)
	if t.IsTranslatable && len(t.TranslationLanguages) > 0 {
		fmt.Fprintf(&b, "  Translations available: %d languages\n", len(t.TranslationLanguages))
	}

	return b.String()
}

// FormatSnippet formats a single Snippet as a one-line entry.
func (f PrettyPrintFormatter) FormatSnippet(index int, s *Snippet) string {
	if f.ShowTimestamps {
		start := formatPrettyTime(s.Start)
		end := formatPrettyTime(s.Start + s.Duration)
		return fmt.Sprintf("  %3d │ %s → %s │ %s", index, start, end, s.Text)
	}
	return fmt.Sprintf("  %3d │ %s", index, s.Text)
}

// FormatKeyValue formats a key-value pair with aligned padding.
// Useful for CLI output of config, status, and metadata.
func FormatKeyValue(key, value string, padTo int) string {
	if padTo <= 0 {
		padTo = 16
	}
	format := fmt.Sprintf("  %%-%ds  %%s\n", padTo)
	return fmt.Sprintf(format, key+":", value)
}

// FormatTable formats rows of data as an aligned table with a header row.
// columns defines the column headers; each row must have the same number
// of elements as columns.
func FormatTable(columns []string, rows [][]string) string {
	if len(columns) == 0 {
		return ""
	}

	// Calculate column widths.
	widths := make([]int, len(columns))
	for i, col := range columns {
		widths[i] = len(col)
	}
	for _, row := range rows {
		for i := 0; i < len(row) && i < len(widths); i++ {
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}

	var b strings.Builder

	// Header row.
	b.WriteString("  ")
	for i, col := range columns {
		if i > 0 {
			b.WriteString(" │ ")
		}
		fmt.Fprintf(&b, "%-*s", widths[i], col)
	}
	b.WriteByte('\n')

	// Separator.
	b.WriteString("  ")
	for i, w := range widths {
		if i > 0 {
			b.WriteString("─┼─")
		}
		b.WriteString(repeatChar('─', w))
	}
	b.WriteByte('\n')

	// Data rows.
	for _, row := range rows {
		b.WriteString("  ")
		for i := 0; i < len(columns); i++ {
			if i > 0 {
				b.WriteString(" │ ")
			}
			val := ""
			if i < len(row) {
				val = row[i]
			}
			fmt.Fprintf(&b, "%-*s", widths[i], val)
		}
		b.WriteByte('\n')
	}

	return b.String()
}

// FormatSection wraps content in a titled section box using box-drawing chars.
func FormatSection(title, content string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "┌─ %s\n", title)
	for _, line := range strings.Split(content, "\n") {
		if line == "" {
			b.WriteString("│\n")
		} else {
			fmt.Fprintf(&b, "│ %s\n", line)
		}
	}
	b.WriteString("└─\n")
	return b.String()
}

// FormatStatusLine formats a status indicator line for CLI output.
// status should be one of: "ok", "warn", "error", "info".
func FormatStatusLine(status, message string) string {
	var indicator string
	switch status {
	case "ok":
		indicator = "[OK]"
	case "warn":
		indicator = "[!!]"
	case "error":
		indicator = "[ERR]"
	case "info":
		indicator = "[--]"
	default:
		indicator = "[??]"
	}
	return fmt.Sprintf("  %s %s\n", indicator, message)
}

// --- internal helpers ---

func (f PrettyPrintFormatter) writeHeader(b *strings.Builder, t *FetchedTranscript) {
	flag := FlagForLanguage(t.LanguageCode)
	kind := "manual"
	if t.IsGenerated {
		kind = "auto-generated"
	}

	b.WriteString(repeatChar('─', 60))
	b.WriteByte('\n')
	fmt.Fprintf(b, "  Video:    %s\n", t.VideoID)
	fmt.Fprintf(b, "  Language: %s %s (%s, %s)\n", flag, t.Language, t.LanguageCode, kind)
	fmt.Fprintf(b, "  Snippets: %d\n", len(t.Snippets))
	b.WriteString(repeatChar('─', 60))
	b.WriteByte('\n')
}

// formatPrettyTime converts seconds to a compact MM:SS or H:MM:SS format.
func formatPrettyTime(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	total := int(seconds)
	h := total / 3600
	m := (total % 3600) / 60
	s := total % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// totalDuration returns the end time of the last snippet.
func totalDuration(snippets []Snippet) float64 {
	if len(snippets) == 0 {
		return 0
	}
	last := snippets[len(snippets)-1]
	return last.Start + last.Duration
}

// truncateText truncates text to maxLen characters, appending "…" if truncated.
func truncateText(text string, maxLen int) string {
	if maxLen <= 0 || len(text) <= maxLen {
		return text
	}
	if maxLen <= 1 {
		return "…"
	}
	return text[:maxLen-1] + "…"
}

// repeatChar creates a string of n repetitions of the character c.
func repeatChar(c rune, n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(string(c), n)
}

// FormatterLoader is a factory that registers and resolves Formatter
// implementations by name. Use NewFormatterLoader() to get a loader
// pre-populated with all built-in formatters.
type FormatterLoader struct {
	formatters map[string]Formatter
}

// NewFormatterLoader creates a FormatterLoader with all built-in formatters
// registered: "text", "json", "json-pretty", "srt", "webvtt", "pretty".
// The default formatter (returned by Get("") or Get with unknown name) is
// PrettyPrintFormatter.
func NewFormatterLoader() *FormatterLoader {
	fl := &FormatterLoader{
		formatters: make(map[string]Formatter),
	}
	fl.Register("text", TextFormatter{})
	fl.Register("json", JSONFormatter{Pretty: false})
	fl.Register("json-pretty", JSONFormatter{Pretty: true})
	fl.Register("srt", SRTFormatter{})
	fl.Register("webvtt", WebVTTFormatter{})
	fl.Register("pretty", *NewPrettyPrintFormatter())
	return fl
}

// Register adds or replaces a formatter under the given name.
func (fl *FormatterLoader) Register(name string, f Formatter) {
	fl.formatters[name] = f
}

// Get returns the formatter registered under name.
// If name is empty, PrettyPrintFormatter is returned as the default.
// Returns an error if the name is not registered.
func (fl *FormatterLoader) Get(name string) (Formatter, error) {
	if name == "" {
		return *NewPrettyPrintFormatter(), nil
	}
	f, ok := fl.formatters[name]
	if !ok {
		return nil, fmt.Errorf("unknown formatter %q", name)
	}
	return f, nil
}

// Names returns a sorted list of all registered formatter names.
func (fl *FormatterLoader) Names() []string {
	names := make([]string, 0, len(fl.formatters))
	for n := range fl.formatters {
		names = append(names, n)
	}
	// sort for deterministic output
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}
