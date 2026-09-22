package redact

import (
	"bytes"
	"reflect"
	"testing"
)

// TestRedactedCopiesOnConstruct: the constructor must not alias the caller's
// slice, or the raw buffer could be rewritten after redaction (SPEC-0467 R5).
func TestRedactedCopiesOnConstruct(t *testing.T) {
	src := []byte("redacted evidence")
	r := newRedacted(src)
	src[0] = 'X'
	if got := r.Bytes(); !bytes.Equal(got, []byte("redacted evidence")) {
		t.Fatalf("Bytes() = %q, want the value at construction time", got)
	}
}

// TestRedactedBytesReturnsCopy: mutating the accessor result must not change
// the stored evidence.
func TestRedactedBytesReturnsCopy(t *testing.T) {
	r := newRedacted([]byte("abc"))
	b := r.Bytes()
	b[0] = 'Z'
	if got := r.Bytes(); !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("Bytes() = %q after mutating a previous result, want %q", got, "abc")
	}
}

// TestRedactedZeroValueIsEmpty: the only value code outside this package can
// build is empty.
func TestRedactedZeroValueIsEmpty(t *testing.T) {
	var r Redacted
	if got := r.Bytes(); got == nil || len(got) != 0 {
		t.Fatalf("zero value Bytes() = %#v, want a non-nil empty slice", got)
	}
	if got := newRedacted(nil).Bytes(); len(got) != 0 {
		t.Fatalf("newRedacted(nil).Bytes() = %q, want empty", got)
	}
}

// TestRedactedFieldIsUnexported pins the type-level guard: a struct whose only
// field is unexported cannot be built from raw bytes outside this package.
func TestRedactedFieldIsUnexported(t *testing.T) {
	rt := reflect.TypeOf(Redacted{})
	if rt.Kind() != reflect.Struct {
		t.Fatalf("Redacted kind = %s, want struct (a named []byte could be converted from raw bytes)", rt.Kind())
	}
	for i := 0; i < rt.NumField(); i++ {
		if f := rt.Field(i); f.IsExported() {
			t.Fatalf("Redacted has exported field %q", f.Name)
		}
	}
}
