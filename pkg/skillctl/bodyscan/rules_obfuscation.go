package bodyscan

import (
	"regexp"
	"unicode"
)

// Obfuscation rules (SPEC-0246 §4.2) — YELLOW on their own, escalated to RED
// when adjacent to an exfiltration finding (see escalateObfuscationNearExfil).
// These detect encodings/tricks used to hide payloads from a human reviewer.
var (
	// base64 run >= 40 chars (with optional trailing padding). Anchored on a
	// non-base64 boundary so we measure the whole run, not a window of it.
	reObfBase64 = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})`)

	// \xNN escape runs (>= 4 in a row) — classic hex-encoded payload.
	reObfHexRun = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){4,}`)

	// literal atob( — JS base64 decode, a smuggling primitive.
	reObfAtob = regexp.MustCompile(`\batob\s*\(`)

	// zero-width / BOM characters used to hide text
	// (U+200B..U+200D zero-width space/non-joiner/joiner, U+FEFF BOM).
	reObfZeroWidth = regexp.MustCompile(`[\x{200B}-\x{200D}\x{FEFF}]`)

	// HTML comments — checked for embedded injection prose.
	reHTMLComment = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// matchObfBase64 returns spans for base64 runs, anchored on the base64 text
// itself (capture group 1), not the leading boundary char. Runs against the
// original body (base64 alphabet is ASCII; folding cannot change it).
func matchObfBase64(c scanCtx) []Span {
	locs := reObfBase64.FindAllStringSubmatchIndex(c.In.Body, -1)
	if locs == nil {
		return nil
	}
	var out []Span
	for _, loc := range locs {
		// loc[2]:loc[3] is capture group 1 (the base64 run).
		out = append(out, Span{Start: loc[2], End: loc[3]})
	}
	return out
}

// matchObfHomoglyph flags ASCII-looking words that contain a Cyrillic or Greek
// letter (a homoglyph smuggle, e.g. "ѕystem" with a Cyrillic 'ѕ'). A word is a
// run of letters; it is suspicious if it mixes ASCII letters with letters from
// the Cyrillic/Greek scripts.
func matchObfHomoglyph(c scanCtx) []Span {
	// Runs against the ORIGINAL body: the homoglyph (a Cyrillic/Greek letter)
	// is exactly what normalization would otherwise leave in place, but we want
	// the original offsets and the raw rune.
	b := c.In.Body
	var out []Span
	i := 0
	for i < len(b) {
		r, size := decodeRune(b[i:])
		if !unicode.IsLetter(r) {
			i += size
			continue
		}
		// Start of a word.
		start := i
		hasASCII := false
		hasConfusable := false
		for i < len(b) {
			rr, sz := decodeRune(b[i:])
			if !unicode.IsLetter(rr) {
				break
			}
			if rr < 128 {
				hasASCII = true
			} else if unicode.In(rr, unicode.Cyrillic, unicode.Greek) {
				hasConfusable = true
			}
			i += sz
		}
		if hasASCII && hasConfusable {
			out = append(out, Span{Start: start, End: i})
		}
	}
	return out
}

// matchObfHexRun flags runs of \xNN hex escapes. It MUST run against the
// ORIGINAL body: normalization decodes those escapes, so a rule on the folded
// text would no longer see the literal \xNN smell (the decoded payload is
// caught separately by the injection rules).
func matchObfHexRun(c scanCtx) []Span {
	locs := reObfHexRun.FindAllStringIndex(c.In.Body, -1)
	if locs == nil {
		return nil
	}
	out := make([]Span, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Span{Start: loc[0], End: loc[1]})
	}
	return out
}

// matchObfZeroWidth flags zero-width / BOM characters. It MUST run against the
// ORIGINAL body: normalization strips exactly these characters, so a rule that
// ran against the folded text would never see them. (The fold itself is also
// flagged via OBF-007, but OBF-004 keeps the specific zero-width signal and its
// precise span.)
func matchObfZeroWidth(c scanCtx) []Span {
	locs := reObfZeroWidth.FindAllStringIndex(c.In.Body, -1)
	if locs == nil {
		return nil
	}
	out := make([]Span, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Span{Start: loc[0], End: loc[1]})
	}
	return out
}

// matchInjectionInHTMLComment flags injection-style prose hidden inside an HTML
// comment (which renders invisibly but is still read by the agent).
func matchInjectionInHTMLComment(c scanCtx) []Span {
	// Run against the normalized text so a folded injection inside the comment
	// is still recognised; map the comment span back to original bytes.
	text := c.Norm.Text
	comments := reHTMLComment.FindAllStringIndex(text, -1)
	if comments == nil {
		return nil
	}
	var out []Span
	for _, cm := range comments {
		seg := text[cm[0]:cm[1]]
		if reInjIgnore.MatchString(seg) ||
			reInjDisregard.MatchString(seg) ||
			reInjForget.MatchString(seg) ||
			reInjYouAreNow.MatchString(seg) ||
			reInjRoleOverride.MatchString(seg) ||
			reInjTermMarker.MatchString(seg) {
			out = append(out, c.origSpan(cm[0], cm[1]))
		}
	}
	return out
}

func init() {
	register(
		Rule{
			ID:       "OBF-001",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Match:    matchObfBase64,
			Message:  "obfuscation: base64 run >= 40 chars (possible hidden payload)",
		},
		Rule{
			ID:       "OBF-002",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Match:    matchObfHexRun,
			Message:  "obfuscation: run of \\xNN hex escapes (possible hidden payload)",
		},
		Rule{
			ID:       "OBF-003",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Pattern:  reObfAtob,
			Message:  "obfuscation: literal atob( — base64 decode primitive",
		},
		Rule{
			ID:       "OBF-004",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Match:    matchObfZeroWidth,
			Message:  "obfuscation: zero-width / BOM character used to hide text",
		},
		Rule{
			ID:       "OBF-005",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Match:    matchObfHomoglyph,
			Message:  "obfuscation: homoglyph — ASCII word contains a Cyrillic/Greek look-alike letter",
		},
		Rule{
			ID:       "OBF-006",
			Category: CategoryObfuscation,
			Verdict:  VerdictRed,
			Match:    matchInjectionInHTMLComment,
			Message:  "obfuscation: injection prose hidden inside an HTML comment",
		},
	)
}

// escalateObfuscationNearExfil raises a YELLOW obfuscation finding to RED when
// an exfiltration finding occurs on a nearby line (SPEC-0246 §4.2: obfuscation
// "-> red when adjacent to exfil"). It mutates and returns the findings slice.
func escalateObfuscationNearExfil(findings []Finding) []Finding {
	const adjacency = exfilAdjacencyLines

	// Collect exfiltration finding lines.
	var exfilLines []int
	for _, f := range findings {
		if f.Category == CategoryExfiltration {
			exfilLines = append(exfilLines, f.Span.Line)
		}
	}
	if len(exfilLines) == 0 {
		return findings
	}
	for i := range findings {
		if findings[i].Category != CategoryObfuscation || findings[i].Verdict == VerdictRed {
			continue
		}
		for _, el := range exfilLines {
			d := findings[i].Span.Line - el
			if d < 0 {
				d = -d
			}
			if d <= adjacency {
				findings[i].Verdict = VerdictRed
				findings[i].Message = findings[i].Message + " [escalated: adjacent to exfiltration]"
				break
			}
		}
	}
	return findings
}
