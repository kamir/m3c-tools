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

	// "summarize ... and (send|transmit|post|upload) ... <network sink OR
	// sensitive noun>" — covert exfil framed as a helpful summary.
	//
	// FALSE-POSITIVE FIX (SPEC-0246 §4, evasion #5): the bare "summarize and
	// send" form matched benign skills like "summarize and email the report".
	// We now require, like EXF-001/002, that the send be aimed at a NETWORK SINK
	// (a URL / curl / wget / webhook / endpoint) OR concern a SENSITIVE NOUN
	// (secrets/env/credentials/conversation/...). "email the report to the team"
	// has neither and stays green.
	// The trailing gap to the sink/noun is SENTENCE-BOUNDED ([^.\n]) so the rule
	// cannot chain "...email the report. It never touches secrets" across a
	// sentence/line boundary into an unrelated reassurance (that was a
	// false-positive source on benign "summarize and email the report" skills).
	reExfilSummarizeSend = regexp.MustCompile(`(?i)\bsummari[sz]e\b` + gapClass(90) + `\band\b` + gapClass(50) +
		`\b(?:send|transmit|post|upload|email|forward|exfiltrate|leak)\b[^.\n]{0,40}?` +
		`(?:https?://|\bcurl\b|\bwget\b|\bwebhook\b|\bendpoint\b|\b(?:secrets?|env(?:ironment)?|\.env|credentials?|api[\s_-]?keys?|tokens?|passwords?|conversation|chat\s+log|private[\s_-]?key)\b)`)

	// A URL/curl/fetch reference, for the base64-adjacency rule.
	reNetworkRef = regexp.MustCompile(`(?i)(?:https?://|\bcurl\b|\bwget\b|\bfetch\b|\bxhr\b|\bXMLHttpRequest\b)`)
)

// base64-run-within-N-lines-of-a-URL/curl/fetch adjacency. A base64 blob next
// to a network call is the classic "encode then exfil" pattern.
const exfilAdjacencyLines = 3

// exfilB64MinChars is the lowered contiguous-base64 threshold used ONLY in the
// network-adjacency rule (SPEC-0246 §4, evasion #6). Standalone base64 still
// needs reObfBase64's higher bar (40) to avoid false positives on ASCII art; a
// >=24-char contiguous run sitting next to a network sink is suspicious. No
// English word has 24 contiguous base64-alphabet characters, so this does not
// fire on prose.
const exfilB64MinChars = 24

// exfilB64JoinedMinChars is the threshold for the SPLIT form. Because the split
// rule tolerates separators, it must reconstruct to at least the STANDALONE
// blob size (40) to count — otherwise an attacker who simply wrote 24 normal
// chars would not have needed to split at all. This keeps the split rule from
// firing on incidental backtick-separated identifiers.
const exfilB64JoinedMinChars = 40

// reB64Chunk matches one run of >=4 base64-alphabet characters — a "chunk" of a
// split blob. Adversaries break a long base64 payload into adjacent
// `chunk1` `chunk2` fragments (separated ONLY by backticks/quotes/newlines, not
// by spaces — prose uses spaces) to dodge the contiguous-run threshold.
var reB64Chunk = regexp.MustCompile("[A-Za-z0-9+/]{4,}")

// reB64Separator is the set of separators that may join split base64 chunks:
// backticks, single/double quotes, and a single newline (with optional
// surrounding spaces). General inline spaces are deliberately EXCLUDED so the
// rule never stitches ordinary space-separated prose into a fake blob.
var reB64Separator = regexp.MustCompile("^[`'\"]+$|^[ \t]*\n[ \t]*$|^[`'\"][ \t]*\n[ \t]*[`'\"]?$|^[`'\"]+[ \t]*\n?[ \t]*[`'\"]*$")

// itoa is a tiny helper for use in package-level regexp literals (avoids an
// init() just for fmt.Sprint).
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func matchBase64NearNetwork(c scanCtx) []Span {
	// Scan the NORMALIZED body, not the raw one. Normalization has already
	// EOL-folded CRLF/CR to LF (normalize.go), so the single-newline separator
	// in reB64Separator matches identically regardless of the file's line
	// endings — a split-base64 blob authored with Windows CRLF can no longer
	// evade the chunk-merge by inserting a stray "\r" between chunks. Spans are
	// mapped back to ORIGINAL byte offsets via c.origSpan so the reported
	// excerpt / line number still points into the user's on-disk bytes.
	b := c.Norm.Text
	netLocs := reNetworkRef.FindAllStringIndex(b, -1)
	if netLocs == nil {
		return nil
	}

	li := newLineIndex(b)
	netLines := make([]int, 0, len(netLocs))
	for _, nl := range netLocs {
		netLines = append(netLines, li.lineOf(nl[0]))
	}

	nearNet := func(start int) bool {
		bLine := li.lineOf(start)
		for _, nLine := range netLines {
			d := nLine - bLine
			if d < 0 {
				d = -d
			}
			if d <= exfilAdjacencyLines {
				return true
			}
		}
		return false
	}

	var out []Span
	seen := map[int]bool{}

	// (a) Contiguous base64 runs >= exfilB64MinChars adjacent to a network sink.
	for _, bl := range reExfilB64Run.FindAllStringSubmatchIndex(b, -1) {
		start, end := bl[2], bl[3] // capture group 1 = the run
		if nearNet(start) && !seen[start] {
			seen[start] = true
			out = append(out, c.origSpan(start, end))
		}
	}

	// (b) Base64 split across backticks/quotes/newlines. Merge consecutive
	// base64 chunks that are joined by ONLY backtick/quote/newline separators
	// (no inline spaces — those mean prose), and flag the merged run when its
	// reconstructed base64 length reaches the standalone-blob threshold AND it
	// sits next to a network sink.
	for _, m := range mergeSplitB64(b) {
		if m.b64len < exfilB64JoinedMinChars {
			continue
		}
		if nearNet(m.start) && !seen[m.start] {
			seen[m.start] = true
			out = append(out, c.origSpan(m.start, m.end))
		}
	}
	return out
}

// reExfilB64Run is the lowered-threshold contiguous base64 run for the
// adjacency rule (capture group 1 is the run, anchored on a non-base64 left
// boundary so the whole run is measured).
var reExfilB64Run = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{` +
	itoa(exfilB64MinChars) + `,}={0,2})`)

// mergedB64 is a span [start,end) of original bytes covering one or more base64
// chunks joined by backtick/quote/newline separators, with the total base64
// alphabet length (excluding separators) in b64len.
type mergedB64 struct {
	start, end, b64len int
}

// mergeSplitB64 finds base64 chunks (>=4 chars each) and merges any consecutive
// chunks whose intervening text is purely a backtick/quote/newline separator.
// A chunk separated from the next by anything else (a space, a word, a long
// gap) starts a fresh group, so ordinary prose never accumulates.
func mergeSplitB64(b string) []mergedB64 {
	chunks := reB64Chunk.FindAllStringIndex(b, -1)
	if len(chunks) == 0 {
		return nil
	}
	var out []mergedB64
	i := 0
	for i < len(chunks) {
		start := chunks[i][0]
		end := chunks[i][1]
		total := chunks[i][1] - chunks[i][0]
		j := i + 1
		for j < len(chunks) {
			sep := b[end:chunks[j][0]]
			if sep == "" || !reB64Separator.MatchString(sep) {
				break
			}
			end = chunks[j][1]
			total += chunks[j][1] - chunks[j][0]
			j++
		}
		// Only the joined groups (j > i+1) are interesting for the split rule;
		// single contiguous chunks are already handled by reExfilB64Run.
		if j > i+1 {
			out = append(out, mergedB64{start: start, end: end, b64len: total})
		}
		i = j
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
			Message:  "exfiltration: a base64 blob sits next to a network call (encode-then-exfil)",
		},
	)
}
