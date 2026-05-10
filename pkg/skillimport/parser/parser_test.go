package parser

import (
	"errors"
	"strings"
	"testing"
)

const validHex = "a3f5b9c4e8d2f1a0b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4"

func TestParse_HappyPath_ColonForm(t *testing.T) {
	ref, err := Parse("github.com:anthropics/code-reviewer@sha256:" + validHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Host != "github.com" {
		t.Errorf("Host = %q, want github.com", ref.Host)
	}
	if ref.Owner != "anthropics" {
		t.Errorf("Owner = %q, want anthropics", ref.Owner)
	}
	if ref.Name != "code-reviewer" {
		t.Errorf("Name = %q, want code-reviewer", ref.Name)
	}
	if ref.Pin != "sha256:"+validHex {
		t.Errorf("Pin = %q", ref.Pin)
	}
	if ref.PinHex() != validHex {
		t.Errorf("PinHex() = %q", ref.PinHex())
	}
	if got := ref.CanonicalSlug(); got != "github.com/anthropics/code-reviewer" {
		t.Errorf("CanonicalSlug() = %q", got)
	}
}

func TestParse_HappyPath_SlashForm(t *testing.T) {
	ref, err := Parse("skillhub.club/myorg/didactic-session@sha256:" + validHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Host != "skillhub.club" {
		t.Errorf("Host = %q", ref.Host)
	}
	if ref.Owner != "myorg" {
		t.Errorf("Owner = %q", ref.Owner)
	}
	if ref.Name != "didactic-session" {
		t.Errorf("Name = %q", ref.Name)
	}
}

func TestParse_TrimsWhitespace(t *testing.T) {
	ref, err := Parse("   github.com:anthropics/code-reviewer@sha256:" + validHex + "  \n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Host != "github.com" {
		t.Errorf("Host = %q (whitespace not trimmed)", ref.Host)
	}
}

func TestParse_String_RoundTrip(t *testing.T) {
	in := "github.com:anthropics/code-reviewer@sha256:" + validHex
	ref, err := Parse(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := ref.String(); got != in {
		t.Errorf("String() = %q, want %q", got, in)
	}
}

func TestParse_MissingPin(t *testing.T) {
	cases := []string{
		"github.com:anthropics/code-reviewer",
		"github.com/anthropics/code-reviewer",
	}
	for _, in := range cases {
		_, err := Parse(in)
		if !errors.Is(err, ErrPinRequired) {
			t.Errorf("Parse(%q) error = %v, want ErrPinRequired", in, err)
		}
	}
}

func TestParse_MalformedPin(t *testing.T) {
	cases := []struct {
		input  string
		expect string
	}{
		{"github.com:o/n@", "pin required"}, // empty after @ → ErrPinRequired
		{"github.com:o/n@md5:" + validHex, "must start with"},
		{"github.com:o/n@sha256:abc", "64 hex"},
		{"github.com:o/n@sha256:" + strings.Repeat("Z", 64), "lowercase hex"},
		{"github.com:o/n@sha256:" + strings.ToUpper(validHex), "lowercase hex"},
		{"github.com:o/n@sha256:" + validHex + "ff", "64 hex"},
	}
	for _, tc := range cases {
		_, err := Parse(tc.input)
		if err == nil {
			t.Errorf("Parse(%q) = nil error, want error containing %q", tc.input, tc.expect)
			continue
		}
		if !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("Parse(%q) error = %q, want substring %q", tc.input, err.Error(), tc.expect)
		}
	}
}

func TestParse_EmptyFields(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"@sha256:" + validHex,                                // empty body
		":anthropics/code-reviewer@sha256:" + validHex,       // empty host
		"github.com:/code-reviewer@sha256:" + validHex,       // empty owner
		"github.com:anthropics/@sha256:" + validHex,          // empty name
		"github.com:anthropics@sha256:" + validHex,           // missing /name
		"github.com:anthropics/foo/bar@sha256:" + validHex,   // too many slashes
		"github.com@sha256:" + validHex,                      // no owner/name at all
	}
	for _, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, expected error", in)
		}
	}
}

func TestParse_HostWithWhitespace(t *testing.T) {
	_, err := Parse("git hub.com:o/n@sha256:" + validHex)
	if err == nil {
		t.Errorf("expected error for host with internal whitespace")
	}
}

func TestParse_NilReferenceMethods(t *testing.T) {
	var r *Reference
	if got := r.String(); got != "" {
		t.Errorf("nil String() = %q", got)
	}
	if got := r.CanonicalSlug(); got != "" {
		t.Errorf("nil CanonicalSlug() = %q", got)
	}
	if got := r.PinHex(); got != "" {
		t.Errorf("nil PinHex() = %q", got)
	}
}
