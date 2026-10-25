package dependencies

import (
	"regexp"
	"strconv"
	"strings"
)

var releaseRE = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,3}$`)

func release(s string) ([4]uint64, error) {
	var out [4]uint64
	if !releaseRE.MatchString(s) {
		return out, ErrInvalid
	}
	for i, p := range strings.Split(s, ".") {
		n, e := strconv.ParseUint(p, 10, 64)
		if e != nil {
			return out, ErrInvalid
		}
		out[i] = n
	}
	return out, nil
}
func compare(a, b [4]uint64) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// matchRelease implements numeric-release/v1: comma-separated comparator AND.
// Empty accepts any valid numeric release. Prereleases, wildcards and OR fail.
func matchRelease(version, constraint string) (bool, error) {
	v, e := release(version)
	if e != nil {
		return false, e
	}
	if constraint == "" {
		return true, nil
	}
	if len(constraint) > 512 {
		return false, ErrInvalid
	}
	ok := true
	for _, term := range strings.Split(constraint, ",") {
		term = strings.TrimSpace(term)
		op := ""
		for _, candidate := range []string{">=", "<=", "==", "!=", ">", "<"} {
			if strings.HasPrefix(term, candidate) {
				op = candidate
				break
			}
		}
		if op == "" {
			return false, ErrInvalid
		}
		bound, e := release(strings.TrimSpace(strings.TrimPrefix(term, op)))
		if e != nil {
			return false, e
		}
		c := compare(v, bound)
		switch op {
		case ">=":
			ok = ok && c >= 0
		case "<=":
			ok = ok && c <= 0
		case "==":
			ok = ok && c == 0
		case "!=":
			ok = ok && c != 0
		case ">":
			ok = ok && c > 0
		case "<":
			ok = ok && c < 0
		}
	}
	return ok, nil
}
