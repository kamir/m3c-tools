package bodyscan

import (
	"fmt"
	"regexp"
)

// gapClass returns a lazy, bounded "filler" sub-pattern for the gap between
// tokens in an exfiltration chain. It permits any character (so a soft
// line-wrap does not break a verb→noun→"to"→URL chain) but is tightly bounded
// (n is the max length) so it cannot stitch together unrelated, far-apart text.
// RE2 has no lookahead, so a blank-line guard is applied separately by the
// caller's overall window size — a real exfil instruction lives in one short
// span, which is what n captures.
func gapClass(n int) string {
	return fmt.Sprintf(`(?s:.{0,%d}?)`, n)
}

// Exfiltration rules (SPEC-0246 §4.2) — all RED. These detect prose that moves
// sensitive material (context, secrets, env, credentials, repo, history,
// conversation) off the machine to a network endpoint.
var (
	// Verb ... sensitive-noun ... "to" ... http(s) URL. The verb and the URL
	// must co-occur with a sensitive noun in between, within a bounded window
	// so unrelated sentences do not chain together. The window may span a soft
	// line-wrap (a single newline) but NOT a blank-line paragraph break
	// (\n\n) — see gapClass.
	reExfilVerbToURL = regexp.MustCompile(`(?i)\b(?:send|post|upload|transmit|exfiltrate|leak|forward|email|curl|wget|fetch)\b` + gapClass(80) + `\b(?:context|secrets?|env(?:ironment)?|\.env|credentials?|api[\s_-]?keys?|tokens?|passwords?|repo(?:sitory)?|git\s+history|history|conversation|chat\s+log|messages?|private[\s_-]?key)\b` + gapClass(80) + `\bto\b` + gapClass(40) + `https?://`)

	// Same, but the sensitive noun precedes the verb: "the .env ... send ... to http://".
	reExfilNounToURL = regexp.MustCompile(`(?i)\b(?:secrets?|env(?:ironment)?|\.env|credentials?|api[\s_-]?keys?|tokens?|passwords?|conversation|chat\s+log|context)\b` + gapClass(60) + `\b(?:send|post|upload|transmit|exfiltrate|leak|forward|email|curl|wget|fetch)\b` + gapClass(60) + `https?://`)

	// "summarize ... and (send|transmit|post|upload)" — covert exfil framed as a
	// helpful summary.
	reExfilSummarizeSend = regexp.MustCompile(`(?i)\bsummari[sz]e\b` + gapClass(90) + `\band\b` + gapClass(50) + `\b(?:send|transmit|post|upload|email|forward|exfiltrate|leak)\b`)

	// A URL/curl/fetch reference, for the base64-adjacency rule.
	reNetworkRef = regexp.MustCompile(`(?i)(?:https?://|\bcurl\b|\bwget\b|\bfetch\b|\bxhr\b|\bXMLHttpRequest\b)`)
)

// base64-run-within-N-lines-of-a-URL/curl/fetch adjacency. A long base64 blob
// next to a network call is the classic "encode then exfil" pattern.
const exfilAdjacencyLines = 3

func matchBase64NearNetwork(in Input) []Span {
	b := in.Body
	b64locs := reObfBase64.FindAllStringIndex(b, -1)
	if b64locs == nil {
		return nil
	}
	netLocs := reNetworkRef.FindAllStringIndex(b, -1)
	if netLocs == nil {
		return nil
	}

	li := newLineIndex(b)
	netLines := make([]int, 0, len(netLocs))
	for _, nl := range netLocs {
		netLines = append(netLines, li.lineOf(nl[0]))
	}

	var out []Span
	for _, bl := range b64locs {
		bLine := li.lineOf(bl[0])
		for _, nLine := range netLines {
			d := nLine - bLine
			if d < 0 {
				d = -d
			}
			if d <= exfilAdjacencyLines {
				out = append(out, Span{Start: bl[0], End: bl[1]})
				break
			}
		}
	}
	return out
}

func init() {
	register(
		Rule{
			ID:       "EXF-001",
			Category: CategoryExfiltration,
			Verdict:  VerdictRed,
			Pattern:  reExfilVerbToURL,
			Message:  "exfiltration: instructs sending sensitive data (secrets/env/repo/history) to a remote URL",
		},
		Rule{
			ID:       "EXF-002",
			Category: CategoryExfiltration,
			Verdict:  VerdictRed,
			Pattern:  reExfilNounToURL,
			Message:  "exfiltration: routes secrets/credentials/conversation to a remote URL",
		},
		Rule{
			ID:       "EXF-003",
			Category: CategoryExfiltration,
			Verdict:  VerdictRed,
			Pattern:  reExfilSummarizeSend,
			Message:  "exfiltration: \"summarize and send/transmit\" — covert summary-then-exfil sequence",
		},
		Rule{
			ID:       "EXF-004",
			Category: CategoryExfiltration,
			Verdict:  VerdictRed,
			Match:    matchBase64NearNetwork,
			Message:  "exfiltration: a long base64 blob sits next to a network call (encode-then-exfil)",
		},
	)
}
