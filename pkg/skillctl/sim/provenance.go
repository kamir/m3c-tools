package sim

// provenance.go identifies what produced a report.

import (
	"fmt"
	"io"
	"strings"
)

// Provenance renders the identification block. An empty field prints as "unknown"
// rather than being omitted: a missing field that merely looks absent is how a
// report stops being reproducible without anybody noticing.
func (rep Report) Provenance() [][2]string {
	orUnknown := func(s string) string {
		if strings.TrimSpace(s) == "" {
			return "unknown"
		}
		return s
	}
	var corpus []Scenario
	for _, r := range rep.Results {
		corpus = append(corpus, r.Scenario)
	}
	return [][2]string{
		{"commit", orUnknown(rep.Commit)},
		{"binary under test", orUnknown(rep.BinaryPath)},
		{"binary hash", orUnknown(rep.BinaryID)},
		{"model hash", ModelHash()},
		{"corpus hash", CorpusHash(corpus)},
		{"platform", orUnknown(rep.Platform)},
		{"started", orUnknown(rep.StartedAt)},
		{"configuration", orUnknown(rep.Config)},
	}
}

// WriteProvenance prints the identification block.
func (rep Report) WriteProvenance(w io.Writer) {
	fmt.Fprintf(w, "\nprovenance: what produced these numbers\n")
	for _, kv := range rep.Provenance() {
		fmt.Fprintf(w, "  %-18s %s\n", kv[0], kv[1])
	}
	fmt.Fprintf(w, "  A number whose commit is unknown cannot be compared with a later one.\n")
}
