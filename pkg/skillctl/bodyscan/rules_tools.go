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
	// Shell network/file tools — referenced as commands.
	{Tool: "curl", Pattern: regexp.MustCompile(`(?:^|[^A-Za-z])curl\s+[-\w]`)},
	{Tool: "wget", Pattern: regexp.MustCompile(`(?:^|[^A-Za-z])wget\s+[-\w]`)},
}

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

func matchToolEscalation(in Input) []Span {
	allowed := map[string]bool{}
	for _, t := range in.AllowedTools {
		allowed[normalizeTool(t)] = true
	}

	var out []Span
	seen := map[string]bool{} // first occurrence per tool keeps output small + stable
	for _, tr := range toolRefs {
		if toolCoveredBy(tr.Tool, allowed) {
			continue
		}
		loc := tr.Pattern.FindStringIndex(in.Body)
		if loc == nil {
			continue
		}
		if seen[tr.Tool] {
			continue
		}
		seen[tr.Tool] = true
		out = append(out, Span{Start: loc[0], End: loc[1]})
	}
	return out
}

// matchIntentNetworkMismatch flags the SPEC-0196 cross-check: the declared
// intent says no network, but the body calls a URL or a network-capable tool is
// in allowed-tools. YELLOW (a consistency warning, not an attack).
func matchIntentNetworkMismatch(in Input) []Span {
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
