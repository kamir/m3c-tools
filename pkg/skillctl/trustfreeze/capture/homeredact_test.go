package capture

import (
	"context"
	"strings"
	"testing"
)

// TestDefaultRedactorHomeSpellings: the home root is redacted in every
// spelling a tool prints, not only byte for byte (Windows letter case,
// forward slashes, JSON-escaped backslashes, the \\?\ prefix, WSL), and on
// Unix in another case or with backslashes.
func TestDefaultRedactorHomeSpellings(t *testing.T) {
	cases := map[string][]string{
		`C:\Users\alice`: {
			`C:\Users\alice\AppData\x`,
			`c:\users\alice\AppData\x`,
			`C:/Users/alice/AppData/x`,
			`C:\\Users\\alice\\AppData\\x`,
			`\\?\C:\Users\alice\AppData\x`,
			`/mnt/c/Users/alice/x`,
		},
		"/home/alice": {
			"/home/alice/.config/x",
			"/HOME/Alice/x",
			`\home\alice\x`,
		},
	}
	for home, inputs := range cases {
		red, err := DefaultRedactor(home)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range inputs {
			got, _, err := red.RedactString(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(got), "alice") || !strings.Contains(got, "[REDACTED:home_path]") {
				t.Errorf("home %s: %q became %q", home, s, got)
			}
		}
	}
	// Another user's path is left alone.
	red, err := DefaultRedactor("/home/alice")
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := red.RedactString(context.Background(), "/home/bob/x"); got != "/home/bob/x" {
		t.Errorf("unrelated path changed: %q", got)
	}
	if homePathPattern("C:") != "" || homePathPattern("/") != "" {
		t.Error("a bare drive or root yields a pattern")
	}
}
