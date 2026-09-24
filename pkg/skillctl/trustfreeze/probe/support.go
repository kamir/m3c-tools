package probe

import (
	"sort"
)

// ImplementationState says whether this build has code for a probe on a
// platform (SPEC-0471 TF06-R6).
type ImplementationState string

// Implementation states.
const (
	Implemented    ImplementationState = "implemented"
	NotImplemented ImplementationState = "not_implemented"
)

// EvidenceLevel is a build-time evidence level a probe may claim in code.
// Only levels a build can prove about itself exist here. Whether a probe ran
// on a real platform ("real-platform-tested") is never decided in code: that
// lives in evidence records tied to a commit SHA (SPEC-0471 TF06-R7).
type EvidenceLevel string

// Evidence levels a build can claim.
const (
	// FixtureTested: the probe logic for the platform is covered by fixture
	// tests that run on any host.
	FixtureTested EvidenceLevel = "fixture-tested"
	// CrossCompiled: the platform-specific code compiles for the platform.
	CrossCompiled EvidenceLevel = "cross-compiled"
)

// EvidenceClaimer is implemented by probes that state which build-time
// evidence levels they claim per platform. A probe that does not implement
// it claims nothing.
type EvidenceClaimer interface {
	EvidenceClaims() map[Platform][]EvidenceLevel
}

// SupportEntry is one row of the support matrix.
type SupportEntry struct {
	ProbeID  string              `json:"probe_id"`
	Platform Platform            `json:"platform"`
	State    ImplementationState `json:"state"`
	Evidence []EvidenceLevel     `json:"evidence"`
}

// SupportMatrix returns, for every probe id in ids (plus every registered
// probe) and every platform, the implementation state and the evidence
// levels this build claims (SPEC-0471 TF06-R6, section 4). It never reports a
// probe as supported: the strongest statement it can make is "implemented,
// fixture-tested, cross-compiled". Rows are sorted by probe id, then
// platform.
func SupportMatrix(reg *Registry, ids []string) []SupportEntry {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	if reg != nil {
		for _, id := range reg.IDs() {
			set[id] = true
		}
	}
	all := make([]string, 0, len(set))
	for id := range set {
		all = append(all, id)
	}
	sort.Strings(all)

	var out []SupportEntry
	for _, id := range all {
		var (
			p      Probe
			ok     bool
			claims map[Platform][]EvidenceLevel
		)
		if reg != nil {
			p, ok = reg.Get(id)
		}
		if ok {
			if c, isClaimer := p.(EvidenceClaimer); isClaimer {
				claims = c.EvidenceClaims()
			}
		}
		for _, plat := range AllPlatforms() {
			e := SupportEntry{ProbeID: id, Platform: plat, State: NotImplemented, Evidence: []EvidenceLevel{}}
			if ok && p.Descriptor().SupportsPlatform(string(plat)) {
				e.State = Implemented
				e.Evidence = knownLevels(claims[plat])
			}
			out = append(out, e)
		}
	}
	return out
}

// knownLevels keeps only the levels a build may claim, sorted and unique.
func knownLevels(in []EvidenceLevel) []EvidenceLevel {
	seen := map[EvidenceLevel]bool{}
	out := []EvidenceLevel{}
	for _, l := range in {
		if (l == FixtureTested || l == CrossCompiled) && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
