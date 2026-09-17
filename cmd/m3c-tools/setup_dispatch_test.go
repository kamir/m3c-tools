package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestParseSetupVerb_Default(t *testing.T) {
	verb, rest, unknown := parseSetupVerb(nil, "whisper")
	if unknown || verb != "whisper" || len(rest) != 0 {
		t.Fatalf("parseSetupVerb(nil, whisper) = (%q, %v, %v)", verb, rest, unknown)
	}
}

func TestParseSetupVerb_Named(t *testing.T) {
	verb, rest, unknown := parseSetupVerb([]string{"er1", "--no-browser"}, "whisper")
	if unknown || verb != "er1" {
		t.Fatalf("verb = %q unknown=%v, want er1", verb, unknown)
	}
	if len(rest) != 1 || rest[0] != "--no-browser" {
		t.Fatalf("rest = %v, want [--no-browser]", rest)
	}
}

func TestParseSetupVerb_Unknown(t *testing.T) {
	verb, _, unknown := parseSetupVerb([]string{"nope"}, "er1")
	if !unknown || verb != "nope" {
		t.Fatalf("parseSetupVerb(nope) = (%q, unknown=%v)", verb, unknown)
	}
}

func TestParseSetupVerb_FlagsAreNotVerbs(t *testing.T) {
	verb, rest, unknown := parseSetupVerb([]string{"--force"}, "whisper")
	if unknown || verb != "whisper" || len(rest) != 1 || rest[0] != "--force" {
		t.Fatalf("flag parsed as verb: (%q, %v, %v)", verb, rest, unknown)
	}
}

func captureUsage(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	printUsage()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func TestPrintUsage_UploadNotMacOSOnly(t *testing.T) {
	out := captureUsage(t)
	if !strings.Contains(out, "upload") {
		t.Fatal("usage must list upload")
	}
	if i := strings.Index(out, "macOS-only"); i >= 0 && strings.Contains(out[i:], "upload") {
		t.Error("upload listed as macOS-only")
	}
}

func TestPrintUsage_ListsToken(t *testing.T) {
	out := captureUsage(t)
	if !strings.Contains(out, "token") {
		t.Fatal("usage must list token")
	}
}
