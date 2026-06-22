// Package bodyscan implements the SPEC-0246 §4 semantic danger-prose detector
// for skill bodies. Where pkg/skillctl/scanner is a structural inventory walker
// and pkg/skillctl/propose checks frontmatter hygiene, bodyscan reads the
// rendered SKILL.md *body* and flags behavioural manipulation: prompt
// injection, exfiltration, tool-permission escalation, policy subversion and
// obfuscation.
//
// Design constraints (SPEC-0246 R4.3 / R4.4):
//
//   - Core logic is stdlib-only (regexp/strings/unicode/encoding/base64).
//   - Base mode is deterministic and OFFLINE — no network, no LLM.
//   - The same Input produces a byte-identical JSON BodyScanReport.
//
// Detection is table-driven: each Rule carries a Category, a Verdict
// contribution, and either a compiled regexp or a custom Match function that
// returns the byte spans it tripped on. Rules live in one file per category
// (rules_injection.go, rules_exfiltration.go, rules_tools.go, rules_policy.go,
// rules_obfuscation.go) and register themselves in init().
//
// The aggregate report Verdict is the worst-of all findings
// (green < yellow < red). Findings are sorted by (Span.Start, RuleID) so the
// JSON encoding is stable for any given Input.
package bodyscan

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is the SPEC-0130 Ampel contribution of a finding or the aggregate of
// a report.
type Verdict string

// Verdict values, ordered green < yellow < red.
const (
	VerdictGreen  Verdict = "green"
	VerdictYellow Verdict = "yellow"
	VerdictRed    Verdict = "red"
)

// rank maps a Verdict to a total order for worst-of aggregation.
func rank(v Verdict) int {
	switch v {
	case VerdictRed:
		return 2
	case VerdictYellow:
		return 1
	default:
		return 0
	}
}

// worst returns the more severe of a and b.
func worst(a, b Verdict) Verdict {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Category classifies the kind of behavioural manipulation a finding detects.
type Category string

// Category values (SPEC-0246 §4.2).
const (
	CategoryInjection      Category = "injection"
	CategoryExfiltration   Category = "exfiltration"
	CategoryToolEscalation Category = "tool-escalation"
	CategoryPolicySubvert  Category = "policy-subversion"
	CategoryObfuscation    Category = "obfuscation"
)

// Span is a byte range within the scanned body plus the 1-based line number of
// its start. Start is inclusive, End exclusive.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
	Line  int `json:"line"`
}

// Finding is a single rule hit.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Category Category `json:"category"`
	Verdict  Verdict  `json:"verdict"`
	Span     Span     `json:"span"`
	Excerpt  string   `json:"excerpt"`
	Message  string   `json:"message"`
}

// BodyScanReport is the deterministic, JSON-serialisable scan result.
type BodyScanReport struct {
	// Verdict is the worst-of all Findings (green when there are none).
	Verdict Verdict `json:"verdict"`
	// Findings are sorted by (Span.Start, RuleID).
	Findings []Finding `json:"findings"`
	// FrontmatterConsistency holds tool-escalation / intent-mismatch findings
	// that arise from cross-checking the body against the declared
	// allowed-tools and intent (SPEC-0246 §4.2 tool-permission escalation).
	// These are ALSO included in Findings so the aggregate Verdict accounts
	// for them; this field is the focused projection for the inspect/audit UI.
	FrontmatterConsistency []Finding `json:"frontmatter_consistency"`
	// Deep is true when the report was produced with the optional --deep
	// classifier (SPEC-0246 R4.4). Base mode always reports false.
	Deep bool `json:"deep"`
}

// Input is the bodyscan request: the post-frontmatter body, the declared
// allowed-tools, and the declared intent block (SPEC-0246 R4.1).
type Input struct {
	Body         string   `json:"body"`
	AllowedTools []string `json:"allowed_tools"`
	Intent       string   `json:"intent"`
}

// maxBodyBytes is the input-size cap (SPEC-0246 §4, DoS hardening). Bodies
// larger than this are NOT scanned — a regex sweep over a multi-megabyte body is
// both slow (~1.2s/MB measured) and can produce hundreds of thousands of
// findings. Instead a single yellow "oversized body" finding is returned.
const maxBodyBytes = 1 << 20 // 1 MiB

// maxFindingsPerRule caps how many spans a single rule may contribute, and
// maxFindingsTotal caps the aggregate, BEFORE the escalation/sort passes. This
// bounds work and report size on a pathological body that slips under the size
// cap but still has many matches.
const (
	maxFindingsPerRule = 200
	maxFindingsTotal   = 1000
)

// Scan runs the base (offline, deterministic) ruleset over in and returns a
// BodyScanReport. The aggregate Verdict is the worst-of all findings; findings
// are sorted by (Span.Start, RuleID) so the JSON is byte-identical for equal
// Input.
func Scan(in Input) BodyScanReport {
	// DoS guard: do not scan oversized bodies (SPEC-0246 §4). Return a single
	// yellow finding instead so the caller still sees a non-green signal.
	if len(in.Body) > maxBodyBytes {
		f := Finding{
			RuleID:   "SIZE-001",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Span:     Span{Start: 0, End: 0, Line: 1},
			Excerpt:  "",
			Message:  fmt.Sprintf("oversized body (%d bytes) not scanned", len(in.Body)),
		}
		return BodyScanReport{
			Verdict:                VerdictYellow,
			Findings:               []Finding{f},
			FrontmatterConsistency: []Finding{},
			Deep:                   false,
		}
	}

	var findings []Finding
	var fmConsistency []Finding

	lineIdx := newLineIndex(in.Body)
	ctx := scanCtx{In: in, Norm: normalizeBody(in.Body)}

	for _, r := range registry {
		spans := r.spans(ctx)
		if len(spans) > maxFindingsPerRule {
			spans = spans[:maxFindingsPerRule]
		}
		for _, sp := range spans {
			sp.Line = lineIdx.lineOf(sp.Start)
			f := Finding{
				RuleID:   r.ID,
				Category: r.Category,
				Verdict:  r.Verdict,
				Span:     sp,
				Excerpt:  excerpt(in.Body, sp),
				Message:  r.Message,
			}
			findings = append(findings, f)
			if r.Category == CategoryToolEscalation {
				fmConsistency = append(fmConsistency, f)
			}
		}
	}

	// Normalization changed the text (a zero-width strip or a fullwidth fold) —
	// that is itself an obfuscation signal (SPEC-0246 §4). Emit one yellow
	// finding so a soft-hyphen / fullwidth evasion surfaces even if the folded
	// injection regex were ever to miss, and so the verdict carries a rationale.
	if ctx.Norm.Changed {
		findings = append(findings, Finding{
			RuleID:   "OBF-007",
			Category: CategoryObfuscation,
			Verdict:  VerdictYellow,
			Span:     Span{Start: 0, End: 0},
			Message:  "obfuscation: text contained zero-width / soft-hyphen / fullwidth characters that were normalized before matching",
		})
	}

	// Aggregate cap BEFORE escalation/sort passes (DoS hardening).
	if len(findings) > maxFindingsTotal {
		findings = findings[:maxFindingsTotal]
	}

	// Injection phrases quoted inside a CLOSED fenced code block are
	// documentation examples (e.g. a security skill demonstrating an attack),
	// not necessarily live instructions. DOWNGRADE such injection findings to
	// yellow (flag-for-review) — do NOT drop them — so a live injection hidden
	// in a fence still surfaces while benign security prose is yellow-not-red.
	// Exfiltration/tool/policy/obfuscation findings are NOT touched.
	findings = downgradeInjectionInFences(in.Body, findings)

	// Obfuscation contributes yellow on its own but escalates to red when it
	// is adjacent to an exfiltration finding (SPEC-0246 §4.2). Apply this
	// cross-finding pass centrally so a single rule needs no global knowledge.
	findings = escalateObfuscationNearExfil(findings)
	// Re-sync the projection after escalation may have changed verdicts.
	for i := range fmConsistency {
		for j := range findings {
			if findings[j].RuleID == fmConsistency[i].RuleID &&
				findings[j].Span == fmConsistency[i].Span {
				fmConsistency[i].Verdict = findings[j].Verdict
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Span.Start != findings[j].Span.Start {
			return findings[i].Span.Start < findings[j].Span.Start
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	sort.SliceStable(fmConsistency, func(i, j int) bool {
		if fmConsistency[i].Span.Start != fmConsistency[j].Span.Start {
			return fmConsistency[i].Span.Start < fmConsistency[j].Span.Start
		}
		return fmConsistency[i].RuleID < fmConsistency[j].RuleID
	})

	verdict := VerdictGreen
	for _, f := range findings {
		verdict = worst(verdict, f.Verdict)
	}

	if findings == nil {
		findings = []Finding{}
	}
	if fmConsistency == nil {
		fmConsistency = []Finding{}
	}

	return BodyScanReport{
		Verdict:                verdict,
		Findings:               findings,
		FrontmatterConsistency: fmConsistency,
		Deep:                   false,
	}
}

// excerpt returns a trimmed, single-line snippet of body for the span, capped
// to keep reports readable and deterministic.
func excerpt(body string, sp Span) string {
	const maxLen = 120
	if sp.Start < 0 || sp.End > len(body) || sp.Start >= sp.End {
		return ""
	}
	s := body[sp.Start:sp.End]
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}

// lineIndex maps a byte offset to a 1-based line number.
type lineIndex struct {
	// starts[i] is the byte offset of the first character of line i+1.
	starts []int
}

func newLineIndex(body string) *lineIndex {
	starts := []int{0}
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) lineOf(offset int) int {
	if offset <= 0 {
		return 1
	}
	// Binary search for the greatest start <= offset.
	lo, hi := 0, len(li.starts)-1
	ans := 0
	for lo <= hi {
		mid := (lo + hi) / 2
		if li.starts[mid] <= offset {
			ans = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return ans + 1
}
