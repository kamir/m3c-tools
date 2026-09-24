package common

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// sw_vers(1) property names.
const (
	swVersProductName         = "ProductName"
	swVersProductVersion      = "ProductVersion"
	swVersProductVersionExtra = "ProductVersionExtra"
	swVersBuildVersion        = "BuildVersion"
)

// swVersMaxValueLen bounds a property value. Real values are a few bytes
// ("macOS", "15.7.9", "(a)", "22F770820d").
const swVersMaxValueLen = 256

// ErrSwVersMalformed: the output is not what sw_vers prints. A known
// property has two different values, or a value holds control characters,
// invalid UTF-8 or more than swVersMaxValueLen bytes. The identity probe
// then reports the OS fields as failed instead of choosing a value.
var ErrSwVersMalformed = errors.New("common: malformed sw_vers output")

// swVersRecord holds the known properties. A property that was not printed
// is absent from values.
type swVersRecord struct {
	values map[string]string
}

func (r swVersRecord) get(key string) string { return r.values[key] }

// ParseSwVers parses the output of sw_vers without options: one
// "Key:<blanks>Value" line per property, the value after one or more tabs
// or spaces, LF or CRLF line ends, an optional UTF-8 byte order mark and an
// optional final line end (testdata/darwin covers Mac OS X 10.15 to macOS
// 26). Lines without a colon and lines with an unknown key are ignored; the
// raw output stays in the evidence.
//
// Mapping: ProductName to Name, ProductVersion to Version, BuildVersion to
// Build. ProductVersionExtra, the Rapid Security Response tag such as "(a)",
// is appended to Version after one space ("13.4.1 (c)"), the form Apple
// uses for such releases; without a ProductVersion it is dropped, never
// shown as a version. Names are kept as printed ("Mac OS X" stays).
//
// A property that was not printed, or printed empty, stays empty in the
// result: nothing is filled in, so the probe reports it as missing. Output
// with none of ProductName, ProductVersion and BuildVersion set is
// ErrNoFields; malformed output is ErrSwVersMalformed.
func ParseSwVers(b []byte) (OSInfo, error) {
	rec, err := parseSwVersRecord(b)
	if err != nil {
		return OSInfo{}, err
	}
	info := OSInfo{
		Name:    rec.get(swVersProductName),
		Version: rec.get(swVersProductVersion),
		Build:   rec.get(swVersBuildVersion),
	}
	if info.Name == "" && info.Version == "" && info.Build == "" {
		return OSInfo{}, ErrNoFields
	}
	if extra := rec.get(swVersProductVersionExtra); extra != "" && info.Version != "" {
		info.Version += " " + extra
	}
	return info, nil
}

// parseSwVersRecord collects the known properties. Repeating a property
// with the same value is harmless; a different value is malformed, because
// picking one of them would report a version nobody can vouch for.
func parseSwVersRecord(b []byte) (swVersRecord, error) {
	rec := swVersRecord{values: map[string]string{}}
	s := strings.TrimPrefix(string(b), "\xef\xbb\xbf")
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSuffix(line, "\r")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if !isSwVersKnownKey(k) {
			continue
		}
		v = strings.TrimSpace(v)
		if err := checkSwVersValue(k, v); err != nil {
			return swVersRecord{}, err
		}
		if prev, seen := rec.values[k]; seen && prev != v {
			return swVersRecord{}, fmt.Errorf("%w: %s printed twice with different values", ErrSwVersMalformed, k)
		}
		rec.values[k] = v
	}
	return rec, nil
}

func isSwVersKnownKey(k string) bool {
	switch k {
	case swVersProductName, swVersProductVersion, swVersProductVersionExtra, swVersBuildVersion:
		return true
	}
	return false
}

// checkSwVersValue rejects values no sw_vers prints. The message names the
// key only: the value itself may be anything and is not echoed.
func checkSwVersValue(key, v string) error {
	if len(v) > swVersMaxValueLen {
		return fmt.Errorf("%w: %s value is longer than %d bytes", ErrSwVersMalformed, key, swVersMaxValueLen)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s value is not valid UTF-8", ErrSwVersMalformed, key)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s value contains a control character", ErrSwVersMalformed, key)
		}
	}
	return nil
}
