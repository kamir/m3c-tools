package bodyscan

import (
	"regexp"
	"strings"
)

// Tool-permission escalation (SPEC-0246 §4.2). The body instructs the agent to
// use a capability that is NOT declared in allowed-tools (RED), or the declared
// intent contradicts the allowed-tools / body (YELLOW). These findings carry
// CategoryToolEscalation and are surfaced in BodyScanReport.FrontmatterConsistency.

// toolRef pairs a canonical tool name with the regexp that recognises a prose
// reference to it. Recognition is conservative: it matches the tool used as an
// imperative / capability, e.g. "run Bash", "use WebFetch", a `curl …` command,
// fenced ```bash blocks, or backticked `Edit` — not the bare English word.
type toolRef struct {
	Tool    string
	Pattern *regexp.Regexp
	// negationGuarded marks soft "capability synonym" patterns (prose like
	// "shell out", "over the network") that legitimately appear in NEGATED,
	// reassuring sentences ("we do NOT shell out", "never reaches the network").
	// For these, a match preceded by a negation within a short window is
	// ignored. Literal command forms (curl, python -c) are not guarded.
	negationGuarded bool
}

var toolRefs = []toolRef{
	// Claude Code capability tools — referenced by name (often capitalised or
	// backticked) as an instruction to invoke them. A fenced ```bash block is
	// deliberately NOT matched: it is example code, not an instruction to use
	// the Bash tool. The signal is the capitalised tool name or `bash -c`.
	{Tool: "Bash", Pattern: regexp.MustCompile(`\bBash\b\s+(?:tool|to\s+run|command)|\buse\s+(?:the\s+)?Bash\b|\brun\s+(?:the\s+)?Bash\b|\bbash\s+-c\b`)},
	{Tool: "Read", Pattern: regexp.MustCompile(`\bRead\b\s+(?:the\s+)?(?:file|tool)|\buse\s+(?:the\s+)?Read\b|\bRead\(`)},
	{Tool: "Write", Pattern: regexp.MustCompile(`\bWrite\b\s+(?:the\s+)?(?:file|tool)|\buse\s+(?:the\s+)?Write\b|\bWrite\(`)},
	{Tool: "Edit", Pattern: regexp.MustCompile(`\bEdit\b\s+(?:the\s+)?(?:file|tool)|\buse\s+(?:the\s+)?Edit\b|\bEdit\(`)},
	{Tool: "WebFetch", Pattern: regexp.MustCompile(`\bWebFetch\b`)},
	{Tool: "WebSearch", Pattern: regexp.MustCompile(`\bWebSearch\b`)},
	// Shell network/file tools — referenced as commands. Case-INSENSITIVE
	// (SPEC-0246 §4, evasion #4): "CURL"/"Wget" were slipping past.
	{Tool: "curl", Pattern: regexp.MustCompile(`(?i)(?:^|[^A-Za-z])curl\s+[-\w]`)},
	{Tool: "wget", Pattern: regexp.MustCompile(`(?i)(?:^|[^A-Za-z])wget\s+[-\w]`)},
	// Capability synonyms / indirection (SPEC-0246 §4, evasion #4): a body that
	// reaches the shell or the network WITHOUT naming the tool. These map to the
	// "Bash" capability — flagged unless Bash (a shell) is declared. Prose
	// synonyms are negation-guarded so a reassuring "we do NOT shell out" does
	// not score.
	{Tool: "Bash", negationGuarded: true, Pattern: regexp.MustCompile(`(?i)\bsub-?process(?:es)?\b|\bshell\s+out\b|\bspawn\s+a\s+shell\b|\bopen\s+a\s+terminal\b|\bover\s+the\s+network\b`)},
	// Interpreter -exec forms (python -c, sh -c, node -e, bash -c, perl -e,
	// ruby -e) execute arbitrary code and are shell-equivalent — a literal
	// command, not guarded.
	{Tool: "Bash", Pattern: regexp.MustCompile(`(?i)\b(?:python[0-9.]*|sh|bash|zsh|node|perl|ruby|deno|php)\s+-(?:c|e)\b`)},
}

// reNegationBefore detects a negation cue ("not", "n't", "never", "no", "don't",
// "without", "cannot") within a short window immediately preceding a soft
// synonym match — the sign of a reassuring sentence rather than an instruction.
var reNegationBefore = regexp.MustCompile(`(?i)\b(?:not|never|no|don'?t|does\s*n'?t|do\s*n'?t|cannot|can'?t|without|n'?t)\b[^.\n]{0,30}$`)

// toolImpliesNetwork lists tools whose use means the skill reaches the network.
var toolImpliesNetwork = map[string]bool{
	"WebFetch":  true,
	"WebSearch": true,
	"curl":      true,
	"wget":      true,
}

// toolCoveredBy reports whether a prose tool reference is satisfied by the
// declared allowed-tools. Shell network commands (curl/wget) are covered when
// the skill already has a shell (Bash) OR a declared network capability
// (WebFetch/WebSearch) — a skill that legitimately fetches over the network and
// merely *documents* the equivalent curl command is not escalating. The named
// Claude tools must be present by name.
func toolCoveredBy(tool string, allowed map[string]bool) bool {
	if allowed[tool] {
		return true
	}
	switch tool {
	case "curl", "wget":
		return allowed["Bash"] || allowed["WebFetch"] || allowed["WebSearch"]
	}
	return false
}

func normalizeTool(s string) string { return strings.TrimSpace(s) }

// reIntentNetworkFalse detects an intent block that declares no network reach.
var reIntentNetworkFalse = regexp.MustCompile(`(?i)network\s*[:=]\s*(?:false|no|none|off|0)\b|\bno[\s_-]?network\b|\boffline[\s_-]?only\b|\bnetwork[\s_-]?(?:false|disabled)\b`)

// reIntentNetworkTrue detects an intent block that explicitly declares network.
var reIntentNetworkTrue = regexp.MustCompile(`(?i)network\s*[:=]\s*(?:true|yes|on|1|egress|outbound)\b`)

func matchToolEscalation(c scanCtx) []Span {
	in := c.In
	allowed := map[string]bool{}
	for _, t := range in.AllowedTools {
		allowed[normalizeTool(t)] = true
	}

	// Run against the normalized body so fullwidth/zero-width "ｃｕｒｌ" tricks are
	// still recognised; map the span back to the original bytes.
	text := c.Norm.Text

	var out []Span
	seen := map[string]bool{} // first (real) occurrence per tool keeps output small + stable
	for _, tr := range toolRefs {
		if toolCoveredBy(tr.Tool, allowed) {
			continue
		}
		if seen[tr.Tool] {
			continue
		}
		// Find the first match that is not negation-guarded away. A guarded
		// synonym preceded by a negation cue ("we do NOT shell out") is skipped.
		for _, loc := range tr.Pattern.FindAllStringIndex(text, -1) {
			if tr.negationGuarded && reNegationBefore.MatchString(text[:loc[0]]) {
				continue
			}
			seen[tr.Tool] = true
			out = append(out, c.origSpan(loc[0], loc[1]))
			break
		}
	}
	return out
}

// matchIntentNetworkMismatch flags the SPEC-0196 cross-check: the declared
// intent says no network, but the body calls a URL or a network-capable tool is
// in allowed-tools. YELLOW (a consistency warning, not an attack).
func matchIntentNetworkMismatch(c scanCtx) []Span {
	in := c.In
	if !reIntentNetworkFalse.MatchString(in.Intent) || reIntentNetworkTrue.MatchString(in.Intent) {
		return nil
	}

	// Network-capable tool declared in allowed-tools?
	for _, t := range in.AllowedTools {
		if toolImpliesNetwork[normalizeTool(t)] {
			// Anchor the finding at the start of the body (the inconsistency is
			// a property of the declaration vs. the allow-list, not a body
			// location). Use the first URL if present for a better excerpt.
			if loc := reNetworkRef.FindStringIndex(in.Body); loc != nil {
				return []Span{{Start: loc[0], End: loc[1]}}
			}
			return []Span{{Start: 0, End: min(1, len(in.Body))}}
		}
	}

	// Body calls a URL despite intent:network:false.
	if loc := regexpURL.FindStringIndex(in.Body); loc != nil {
		return []Span{{Start: loc[0], End: loc[1]}}
	}
	return nil
}

var regexpURL = regexp.MustCompile(`https?://[^\s)"'<>]+`)

func init() {
	register(
		Rule{
			ID:       "TOOL-001",
			Category: CategoryToolEscalation,
			Verdict:  VerdictRed,
			Match:    matchToolEscalation,
			Message:  "tool-escalation: body uses a tool not declared in allowed-tools",
		},
		Rule{
			ID:       "TOOL-002",
			Category: CategoryToolEscalation,
			Verdict:  VerdictYellow,
			Match:    matchIntentNetworkMismatch,
			Message:  "frontmatter-consistency: intent declares no network but a URL/network tool is present",
		},
	)
}
