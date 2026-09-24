package trustfreeze

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrCompletenessMismatch: a capture declares a completeness that does not
// follow from its own probe list (SPEC-0466 TF01-AC6).
var ErrCompletenessMismatch = errors.New("trustfreeze: declared completeness differs from the recomputed value")

// Summarize projects probe results onto the capture.json probes list, sorted
// by probe id.
func Summarize(results []ProbeResult) []ProbeSummary {
	out := make([]ProbeSummary, 0, len(results))
	for _, r := range results {
		out = append(out, ProbeSummary{ProbeID: r.ProbeID, Status: r.Status, Reason: r.Reason})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ProbeID < out[j].ProbeID })
	return out
}

// ComputeCompleteness decides completeness from the required probe ids and the
// probe results (SPEC-0466 R6). It returns complete only when every required
// probe has exactly one result and that result is captured, or not_applicable
// with a non-empty reason. partial, permission_denied, timeout, failed,
// unsupported and unavailable never count (SPEC-0466 R6). With no required
// probe the capture is complete.
func ComputeCompleteness(required []string, results []ProbeResult) Completeness {
	return ComputeCompletenessFromSummaries(required, Summarize(results))
}

// ComputeCompletenessFromSummaries is ComputeCompleteness over the probes list
// of capture.json. Readers use it to recompute instead of trusting the file.
func ComputeCompletenessFromSummaries(required []string, probes []ProbeSummary) Completeness {
	req := make([]string, 0, len(required))
	seen := make(map[string]bool, len(required))
	for _, r := range required {
		if !seen[r] {
			seen[r] = true
			req = append(req, r)
		}
	}
	sort.Strings(req)

	byID := make(map[string][]ProbeSummary, len(probes))
	for _, p := range probes {
		byID[p.ProbeID] = append(byID[p.ProbeID], p)
	}

	gaps := []CompletenessGap{}
	for _, id := range req {
		rs := byID[id]
		switch {
		case len(rs) == 0:
			gaps = append(gaps, CompletenessGap{ProbeID: id, Reason: GapNoResult})
			continue
		case len(rs) > 1:
			gaps = append(gaps, CompletenessGap{ProbeID: id, Reason: GapDuplicateResult})
			continue
		}
		p := rs[0]
		switch {
		case !p.Status.Valid():
			gaps = append(gaps, CompletenessGap{ProbeID: id, Reason: GapInvalidStatus})
		case p.Status == StatusCaptured:
		case p.Status == StatusNotApplicable:
			if strings.TrimSpace(p.Reason) == "" {
				gaps = append(gaps, CompletenessGap{ProbeID: id, Status: p.Status, Reason: GapNotApplicableNoReason})
			}
		default:
			gaps = append(gaps, CompletenessGap{ProbeID: id, Status: p.Status, Reason: GapNotCaptured})
		}
	}
	status := CompletenessComplete
	if len(gaps) > 0 {
		status = CompletenessIncomplete
	}
	return Completeness{Status: status, Required: req, Gaps: gaps}
}

// CheckCompleteness recomputes the completeness of doc from its required list
// and its probes list and returns an error wrapping ErrCompletenessMismatch
// when the declared value differs in any byte of its canonical form.
func CheckCompleteness(doc CaptureDoc) error {
	want := ComputeCompletenessFromSummaries(doc.Completeness.Required, doc.Probes)
	a, err := MarshalCanonical(doc.Completeness)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCompletenessMismatch, err)
	}
	b, err := MarshalCanonical(want)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCompletenessMismatch, err)
	}
	if !bytes.Equal(a, b) {
		return fmt.Errorf("%w: declared %s, recomputed %s", ErrCompletenessMismatch, a, b)
	}
	return nil
}
