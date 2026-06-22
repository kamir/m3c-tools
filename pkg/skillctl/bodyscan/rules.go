package bodyscan

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Rule is a table-driven detector. A rule contributes findings either via a
// compiled regexp Pattern (each match becomes a Span) or via a custom Match
// function for rules that need the AllowedTools / Intent context or multi-line
// adjacency logic. Exactly one of Pattern / Match is used; if both are set,
// Match wins (it may consult Pattern itself).
type Rule struct {
	ID       string
	Category Category
	Verdict  Verdict
	// Pattern, when non-nil and Match is nil, is applied to Input.Body and each
	// match index pair becomes a Span.
	Pattern *regexp.Regexp
	Message string
	// Match, when non-nil, fully computes the spans for this rule. It receives
	// the whole Input so it can cross-check AllowedTools / Intent.
	Match func(in Input) []Span
}

// spans returns the byte spans this rule trips on for the given input.
func (r Rule) spans(in Input) []Span {
	if r.Match != nil {
		return r.Match(in)
	}
	if r.Pattern == nil {
		return nil
	}
	return patternSpans(r.Pattern, in.Body)
}

// registry is the global ordered rule table. Each rules_*.go file appends its
// rules in an init(). Because Scan sorts findings by (Span.Start, RuleID), the
// append order does not affect output determinism.
var registry []Rule

// register adds rules to the global table. Called from init() in each
// category file.
func register(rules ...Rule) {
	registry = append(registry, rules...)
}

// patternSpans returns a Span for every non-overlapping match of re in body.
func patternSpans(re *regexp.Regexp, body string) []Span {
	locs := re.FindAllStringIndex(body, -1)
	if locs == nil {
		return nil
	}
	out := make([]Span, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Span{Start: loc[0], End: loc[1]})
	}
	return out
}

// decodeRune decodes the first rune of s, returning the rune and its byte
// width. On an empty string it returns (utf8.RuneError, 0); on an invalid
// encoding it returns (utf8.RuneError, 1) so callers always advance.
func decodeRune(s string) (rune, int) {
	return utf8.DecodeRuneInString(s)
}

// byteRange is a [Start,End) byte interval into the body.
type byteRange struct{ Start, End int }

// fencedCodeRanges returns the byte ranges covered by triple-backtick (```) or
// triple-tilde (~~~) fenced code blocks. A fence opens at a line that begins
// (after optional spaces) with the fence marker and closes at the next such
// line; an unclosed fence runs to end-of-body. Used to treat injection prose
// quoted inside code fences as documentation, not instructions.
func fencedCodeRanges(body string) []byteRange {
	var ranges []byteRange
	var openAt int
	var openMarker byte
	open := false

	lineStart := 0
	for i := 0; i <= len(body); i++ {
		atEnd := i == len(body)
		if !atEnd && body[i] != '\n' {
			continue
		}
		line := body[lineStart:i]
		trimmed := line
		for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
			trimmed = trimmed[1:]
		}
		isFence := strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
		if isFence {
			marker := trimmed[0]
			if !open {
				open = true
				openMarker = marker
				openAt = lineStart
			} else if marker == openMarker {
				open = false
				ranges = append(ranges, byteRange{Start: openAt, End: i})
			}
		}
		lineStart = i + 1
	}
	if open {
		ranges = append(ranges, byteRange{Start: openAt, End: len(body)})
	}
	return ranges
}

// suppressInjectionInFences drops injection findings whose span lies entirely
// within a fenced code block.
func suppressInjectionInFences(body string, findings []Finding) []Finding {
	ranges := fencedCodeRanges(body)
	if len(ranges) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if f.Category == CategoryInjection && spanInAnyRange(f.Span, ranges) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func spanInAnyRange(sp Span, ranges []byteRange) bool {
	for _, r := range ranges {
		if sp.Start >= r.Start && sp.End <= r.End {
			return true
		}
	}
	return false
}
