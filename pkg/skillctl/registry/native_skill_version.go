package registry

import (
	"strconv"
	"strings"
)

// Native SKILL installation supports numeric release versions only. It does not guess
// ordering for prereleases, aliases or overflowing decimal components.
func nativeSkillVersion(text string) (out [4]uint64, err error) {
	if len(text) < 1 || len(text) > 83 || strings.Count(text, ".") > 3 {
		return out, ErrNativeEvidenceInvalid
	}
	parts := strings.Split(text, ".")
	for i, part := range parts {
		if len(part) == 0 || len(part) > 20 || (len(part) > 1 && part[0] == '0') {
			return out, ErrNativeEvidenceInvalid
		}
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				return out, ErrNativeEvidenceInvalid
			}
		}
		out[i], err = strconv.ParseUint(part, 10, 64)
		if err != nil {
			return [4]uint64{}, ErrNativeEvidenceInvalid
		}
	}
	return out, nil
}
func nativeSkillVersionValid(text string) bool { _, err := nativeSkillVersion(text); return err == nil }
func nativeSkillVersionOlder(candidate, old string) (bool, error) {
	a, err := nativeSkillVersion(candidate)
	if err != nil {
		return false, err
	}
	b, err := nativeSkillVersion(old)
	if err != nil {
		return false, err
	}
	for i := range a {
		if a[i] < b[i] {
			return true, nil
		}
		if a[i] > b[i] {
			return false, nil
		}
	}
	return false, nil
}
