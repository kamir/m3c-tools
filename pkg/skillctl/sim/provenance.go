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
		// The first two rows used to be one row called "commit", and it named the
		// HARNESS. An IEEE 1012 reviewer read it as the version of the thing under
		// test, which is how anyone would read the first row of a table called
		// provenance, and pointed out that the binary under test had no source
		// identity at all. It still may not have one; what changed is that the
		// report now says so in the row where a reader looks for it.
		{"harness commit", orUnknown(rep.Commit)},
		{"SUT self-reported version", orUnknown(rep.SUTVersion)},
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
	fmt.Fprintf(w, "  The harness commit identifies the MODEL and this program, not the binary\n")
	fmt.Fprintf(w, "  under test. Where the SUT version reads \"dev\" or unknown, the run has no\n")
	fmt.Fprintf(w, "  source identity for what it measured, and no result here is citable against\n")
	fmt.Fprintf(w, "  a released artifact.\n")
	fmt.Fprintf(w, "  Hashes are SHA-256 truncated to 16 hex characters. They identify a run for\n")
	fmt.Fprintf(w, "  comparison; they are not integrity anchors.\n")
}
