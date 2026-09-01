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
//
// Pattern-based rules run against the NORMALIZED body (Unicode-folded,
// zero-width-stripped — see normalize.go) and their match spans are mapped back
// to ORIGINAL byte offsets before becoming Findings, so an injection hidden
// behind fullwidth Latin or soft hyphens is caught yet the reported span still
// points at the bytes the user can see. Custom Match functions receive the full
// scanCtx and choose which text to operate on.
type Rule struct {
	ID       string
	Category Category
	Verdict  Verdict
	// Pattern, when non-nil and Match is nil, is applied to the normalized body
	// and each match index pair becomes a Span (mapped back to original bytes).
	Pattern *regexp.Regexp
	Message string
	// Match, when non-nil, fully computes the spans for this rule. It receives
	// the scan context so it can cross-check AllowedTools / Intent and use the
	// normalized text + offset map.
	Match func(c scanCtx) []Span
}

// scanCtx carries the per-scan state shared by every rule: the original Input
// and the normalized body with its offset map. It is constructed once per Scan.
type scanCtx struct {
	In   Input
	Norm *normalized
}

// origSpan maps a [normStart,normEnd) span in the normalized text back to a Span
// in original-body byte offsets.
func (c scanCtx) origSpan(normStart, normEnd int) Span {
	return Span{
		Start: c.Norm.origStart(normStart),
		End:   c.Norm.origEnd(normEnd),
	}
}

// spans returns the byte spans this rule trips on for the given context. The
// returned spans are always in ORIGINAL body offsets.
func (r Rule) spans(c scanCtx) []Span {
	if r.Match != nil {
		return r.Match(c)
	}
	if r.Pattern == nil {
		return nil
	}
	return patternSpans(r.Pattern, c)
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

// patternSpans returns a Span (in original offsets) for every non-overlapping
// match of re in the normalized body.
func patternSpans(re *regexp.Regexp, c scanCtx) []Span {
	locs := re.FindAllStringIndex(c.Norm.Text, -1)
	if locs == nil {
		return nil
	}
	out := make([]Span, 0, len(locs))
	for _, loc := range locs {
		out = append(out, c.origSpan(loc[0], loc[1]))
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

// fencedCodeRanges returns the byte ranges covered by CLOSED triple-backtick
// (```) or triple-tilde (~~~) fenced code blocks. A fence opens at a line that
// begins (after optional spaces) with the fence marker and closes at the next
// such line.
//
// SECURITY (SPEC-0246 §4, evasion #2): an UNCLOSED fence is NOT treated as a
// fence — otherwise a single trailing "```" would suppress all content to EOF.
// Only properly closed fences produce a range, so trailing injection prose after
// a dangling fence is still scanned.
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
	// An unclosed fence is deliberately NOT added: do not suppress trailing
	// content (evasion #2a).
	return ranges
}

// downgradeInjectionInFences DOWNGRADES (does not drop) injection findings whose
// span lies entirely within a CLOSED fenced code block to YELLOW, attaching a
// flag-for-review rationale.
//
// SECURITY (SPEC-0246 §4, evasion #2b): the previous behaviour dropped such
// findings to green, which let an attacker hide a live injection inside a fence.
// Downgrading instead means: a security-prose skill that *quotes* attacks
// (benign) scores yellow (a "needs rationale" outcome, not an install-blocking
// red), while a real injection smuggled in a fence still surfaces for a human.
// Exfiltration / tool / policy / obfuscation findings are NOT touched — code
// that *does* the dangerous thing is dangerous regardless of fencing.
func downgradeInjectionInFences(body string, findings []Finding) []Finding {
	ranges := fencedCodeRanges(body)
	if len(ranges) == 0 {
		return findings
	}
	for i := range findings {
		if findings[i].Category != CategoryInjection {
			continue
		}
		if !spanInAnyRange(findings[i].Span, ranges) {
			continue
		}
		if findings[i].Verdict == VerdictRed {
			findings[i].Verdict = VerdictYellow
			findings[i].Message = findings[i].Message +
				" [downgraded: quoted inside a fenced code block — flag for review, not a live instruction]"
		}
	}
	return findings
}

func spanInAnyRange(sp Span, ranges []byteRange) bool {
	for _, r := range ranges {
		if sp.Start >= r.Start && sp.End <= r.End {
			return true
		}
	}
	return false
}
