// Package semver is skillctl's one loose-semver comparator, used to pick the
// "highest non-revoked version" across every backend (git/oci/ER1) and to gate
// version monotonicity at propose time. It replaces four divergent copies of a
// compareSemver helper (git/oci, propose, registry/install_trust_mode) that
// disagreed on a leading "v" — e.g. the registry copy did NOT strip it, so
// compareSemver("v1.2.0","1.2.0") returned "v1.2.0 < 1.2.0" there (v1.2.0 parsed
// as major 0) while git/oci returned equal. That divergence is a latent
// version-ordering bug in a trust path; this package is the single source of truth.
//
// Semantics (loose by design — inputs come from manifests + git tags, not a
// validated SemVer parser):
//   - a single leading "v" is stripped ("v1.2.0" == "1.2.0");
//   - pre-release / build metadata (everything from the first '-' or '+') is
//     dropped, so "1.0.0-rc" compares EQUAL to "1.0.0" — matching the prior
//     behavior of all four call sites (git/oci reached 0 via Atoi-failure,
//     propose stripped it explicitly), NOT full SemVer pre-release precedence;
//   - the numeric core is split on '.', compared field-by-field, with missing
//     or non-numeric fields treated as 0 and shorter forms zero-extended.
package semver

import (
	"sort"
	"strconv"
	"strings"
)

// core extracts the comparable numeric core: trims space, strips one leading
// "v", and drops any pre-release/build suffix (from the first '-' or '+').
func core(s string) string {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	return s
}

// Compare returns -1 if a < b, 0 if a == b, +1 if a > b, under the loose
// semantics documented on the package.
func Compare(a, b string) int {
	ap := strings.Split(core(a), ".")
	bp := strings.Split(core(b), ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(ap) {
			ai, _ = strconv.Atoi(strings.TrimSpace(ap[i]))
		}
		if i < len(bp) {
			bi, _ = strconv.Atoi(strings.TrimSpace(bp[i]))
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Less reports whether a sorts before b.
func Less(a, b string) bool { return Compare(a, b) < 0 }

// Max returns the highest version in vs (empty string if vs is empty). Ties
// resolve to whichever the stable sort leaves last; callers that need a
// tie-break on another axis (e.g. admit time) must apply it themselves.
func Max(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	cp := append([]string(nil), vs...)
	sort.SliceStable(cp, func(i, j int) bool { return Less(cp[i], cp[j]) })
	return cp[len(cp)-1]
}
