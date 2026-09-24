package trustfreeze

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Canonicalization contract (SPEC-0466 R5, SPEC-0470 TF05-R4):
//
//   - encoding/json with HTML escaping off; object keys come from struct field
//     order or, for maps, sorted byte-wise by encoding/json;
//   - only string-keyed maps;
//   - no floating-point or complex numbers anywhere (int64 and strings only);
//   - no time.Time (times are strings from FormatTime), no json.Number, no
//     json.RawMessage (unsorted, unchecked bytes);
//   - every string and map key is valid UTF-8, so no two different inputs
//     collapse to the same bytes through U+FFFD replacement.
//
// MarshalCanonical: no indentation, no trailing newline. It is the form that
// digests and signatures are computed over.
// MarshalFile: two-space indentation, LF only, exactly one trailing "\n". It is
// the form every JSON file in a bundle is written in.
//
// Neither form depends on map iteration order, the OS path separator, the
// local time zone or the OS line ending.

// ErrNotCanonical is wrapped when a value cannot be encoded canonically, or a
// file is not in the canonical file form.
var ErrNotCanonical = errors.New("trustfreeze: value is not canonically encodable")

// MarshalCanonical returns the compact canonical JSON encoding of v.
func MarshalCanonical(v any) ([]byte, error) {
	return encode(v, false)
}

// MarshalFile returns the indented canonical file encoding of v.
func MarshalFile(v any) ([]byte, error) {
	return encode(v, true)
}

// Digest returns "sha256:" followed by the lowercase hex SHA-256 of b.
func Digest(b []byte) string {
	return "sha256:" + SHA256Hex(b)
}

// SHA256Hex returns the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func encode(v any, indent bool) ([]byte, error) {
	if err := checkCanonical(reflect.ValueOf(v), "$", 0); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	b := buf.Bytes()
	if !indent {
		b = bytes.TrimSuffix(b, []byte("\n"))
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

const maxCanonicalDepth = 256

var (
	timeType       = reflect.TypeOf(time.Time{})
	jsonNumberType = reflect.TypeOf(json.Number(""))
	rawMessageType = reflect.TypeOf(json.RawMessage(nil))
)

// checkCanonical walks v the way encoding/json would and rejects every value
// the canonicalization contract excludes.
func checkCanonical(v reflect.Value, at string, depth int) error {
	if depth > maxCanonicalDepth {
		return fmt.Errorf("%w: nesting deeper than %d at %s", ErrNotCanonical, maxCanonicalDepth, at)
	}
	if !v.IsValid() {
		return nil
	}
	switch v.Type() {
	case timeType:
		return fmt.Errorf("%w: time.Time at %s (use FormatTime strings)", ErrNotCanonical, at)
	case jsonNumberType:
		return fmt.Errorf("%w: json.Number at %s", ErrNotCanonical, at)
	case rawMessageType:
		return fmt.Errorf("%w: json.RawMessage at %s", ErrNotCanonical, at)
	}
	switch v.Kind() {
	case reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return fmt.Errorf("%w: floating-point value at %s", ErrNotCanonical, at)
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return fmt.Errorf("%w: %s value at %s", ErrNotCanonical, v.Kind(), at)
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return fmt.Errorf("%w: invalid UTF-8 at %s", ErrNotCanonical, at)
		}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return checkCanonical(v.Elem(), at, depth+1)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			// []byte encodes as base64: deterministic, and never a number.
			return nil
		}
		fallthrough
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := checkCanonical(v.Index(i), fmt.Sprintf("%s[%d]", at, i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("%w: map with %s keys at %s (string keys only)", ErrNotCanonical, v.Type().Key(), at)
		}
		iter := v.MapRange()
		for iter.Next() {
			k := iter.Key().String()
			if !utf8.ValidString(k) {
				return fmt.Errorf("%w: invalid UTF-8 map key at %s", ErrNotCanonical, at)
			}
			if err := checkCanonical(iter.Value(), at+"."+k, depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := f.Name
			if n, _, _ := strings.Cut(tag, ","); n != "" {
				name = n
			}
			if err := checkCanonical(v.Field(i), at+"."+name, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// UnmarshalStrict decodes exactly one JSON value from b into v. Unknown object
// fields and trailing data are errors.
func UnmarshalStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// UnmarshalCanonicalFile decodes b strictly into v and then requires that
// MarshalFile(v) reproduces b byte for byte. That rejects unknown fields,
// duplicate keys, reordered keys, CRLF line endings and any other formatting a
// bundle writer never produces.
func UnmarshalCanonicalFile(b []byte, v any) error {
	if err := UnmarshalStrict(b, v); err != nil {
		return fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	again, err := MarshalFile(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return fmt.Errorf("%w: bytes are not in canonical file form", ErrNotCanonical)
	}
	return nil
}
