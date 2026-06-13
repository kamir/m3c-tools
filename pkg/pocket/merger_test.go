package pocket

import (
	"errors"
	"strings"
	"testing"
)

// TestBuildFileList_RejectsConcatInjection is the regression for F43:
// a recording FilePath that embeds a newline must NOT be allowed to split the
// single-quoted concat token and inject a second `file '...'` directive into the
// ffmpeg concat-demuxer list. Before the fix, the only escaping was for single
// quotes (strings.ReplaceAll(path, "'", "'\\''")), which left newlines intact;
// combined with `-safe 0` this let an attacker-controlled path component (e.g. a
// parent directory name) smuggle a `file '/etc/passwd'` line into the list.
func TestBuildFileList_RejectsConcatInjection(t *testing.T) {
	// The attacker-chosen path: a benign-looking staged recording whose parent
	// directory name embeds  \n + an extra concat directive.
	malicious := "/raw/2026-04-02\nfile '/etc/passwd'\n/20260402163416.mp3"

	tests := []struct {
		name      string
		path      string
		wantErr   bool
		mustNotEq string // substring that must NOT appear in any produced list
	}{
		{
			name:      "newline_injects_directive",
			path:      malicious,
			wantErr:   true,
			mustNotEq: "file '/etc/passwd'",
		},
		{name: "carriage_return", path: "/raw/a\rfile 'x'.mp3", wantErr: true},
		{name: "nul_byte", path: "/raw/a\x00.mp3", wantErr: true},
		// Benign quote-bearing path stays accepted, single-quote-escaped.
		{name: "single_quote_ok", path: "/raw/it's a note.mp3", wantErr: false},
		{name: "plain_ok", path: "/raw/20260402163416.mp3", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := []Recording{
				{FilePath: "/raw/20260402091530.mp3"},
				{FilePath: tt.path},
			}

			got, err := BuildFileListChecked(recs)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("BuildFileListChecked() = %q, want error for unsafe path %q", got, tt.path)
				}
				if !errors.Is(err, errUnsafeConcatPath) {
					t.Fatalf("error = %v, want errUnsafeConcatPath", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildFileListChecked() unexpected error: %v", err)
			}

			// Defense-in-depth: the non-error (silent-drop) form must NEVER emit
			// a list whose line count exceeds one directive per recording, and must
			// never contain the injected directive.
			lines := strings.Split(strings.TrimRight(BuildFileList(recs), "\n"), "\n")
			for _, ln := range lines {
				if !strings.HasPrefix(ln, "file '") {
					t.Fatalf("produced non-directive line %q in list:\n%s", ln, BuildFileList(recs))
				}
			}
		})
	}
}

// TestBuildFileList_NoInjectionViaSilentForm proves the existing (non-error)
// BuildFileList seam — exercised by MergeGroup's reference path — cannot be
// coerced into emitting the injected `file '/etc/passwd'` directive even when
// fed a newline-bearing path.
func TestBuildFileList_NoInjectionViaSilentForm(t *testing.T) {
	recs := []Recording{
		{FilePath: "/raw/good.mp3"},
		{FilePath: "/raw/evil\nfile '/etc/passwd'\n.mp3"},
	}
	out := BuildFileList(recs)
	if strings.Contains(out, "file '/etc/passwd'") {
		t.Fatalf("concat list leaked injected directive:\n%s", out)
	}
}

// TestConcatEscape_PreservesQuoteEscape guards that the benign single-quote
// escaping (the original control) is retained for legal filenames.
func TestConcatEscape_PreservesQuoteEscape(t *testing.T) {
	got, err := concatEscape("/raw/it's.mp3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := `/raw/it'\''s.mp3`; got != want {
		t.Errorf("concatEscape() = %q, want %q", got, want)
	}
}
