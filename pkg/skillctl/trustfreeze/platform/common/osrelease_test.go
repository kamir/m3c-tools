package common

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Linux fixtures in testdata/linux. Each one states where it comes from, so
// a transcription is never presented as a real capture (SPEC-0471 TF06-AC5):
//
//	ubuntu-24.04.os-release   byte-exact /etc/os-release of a real Ubuntu
//	                          24.04.1 LTS host (public distribution metadata,
//	                          no host data)
//	ubuntu-22.04.os-release   transcribed from the published 22.04.4 file
//	debian-12.os-release      transcribed from the published bookworm file
//	alpine-3.20.os-release    transcribed; unquoted VERSION_ID
//	almalinux-9.4.os-release  transcribed; RHEL-like, quoted ID, a blank line
//	arch.os-release           transcribed; rolling release, BUILD_ID and no
//	                          VERSION_ID
//	minimal.os-release        synthetic; only ID
//	malformed.os-release      synthetic; one issue class per line
func readLinuxFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "linux", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// linuxDistributions are the real-distribution fixtures with the OSInfo the
// mapping must give, the ID value and the number of assignments.
var linuxDistributions = []struct {
	file   string
	info   OSInfo
	id     string
	fields int
}{
	{"ubuntu-24.04.os-release", OSInfo{Name: "Ubuntu", Version: "24.04"}, "ubuntu", 13},
	{"ubuntu-22.04.os-release", OSInfo{Name: "Ubuntu", Version: "22.04"}, "ubuntu", 12},
	{"debian-12.os-release", OSInfo{Name: "Debian GNU/Linux", Version: "12"}, "debian", 9},
	{"alpine-3.20.os-release", OSInfo{Name: "Alpine Linux", Version: "3.20.3"}, "alpine", 6},
	{"almalinux-9.4.os-release", OSInfo{Name: "AlmaLinux", Version: "9.4"}, "almalinux", 18},
	{"arch.os-release", OSInfo{Name: "Arch Linux", Build: "rolling"}, "arch", 11},
}

// TestParseOSReleaseDistributions: every real distribution file parses
// without an issue and maps NAME, VERSION_ID and BUILD_ID only.
func TestParseOSReleaseDistributions(t *testing.T) {
	for _, tc := range linuxDistributions {
		t.Run(tc.file, func(t *testing.T) {
			b := readLinuxFixture(t, tc.file)
			d, err := ParseOSReleaseData(b)
			if err != nil || len(d.Issues) != 0 {
				t.Fatalf("err %v issues %+v", err, d.Issues)
			}
			if len(d.Fields) != tc.fields || d.Fields["ID"] != tc.id {
				t.Fatalf("%d fields, ID %q: %v", len(d.Fields), d.Fields["ID"], d.Fields)
			}
			if d.Info() != tc.info {
				t.Fatalf("info %+v, want %+v", d.Info(), tc.info)
			}
			info, err := ParseOSRelease(b)
			if err != nil || info != tc.info {
				t.Fatalf("ParseOSRelease %+v %v", info, err)
			}
		})
	}
	// VERSION and PRETTY_NAME are parsed but not mapped.
	d, _ := ParseOSReleaseData(readLinuxFixture(t, "ubuntu-24.04.os-release"))
	if d.Fields["VERSION"] != "24.04.1 LTS (Noble Numbat)" || d.Fields["PRETTY_NAME"] != "Ubuntu 24.04.1 LTS" {
		t.Fatalf("fields %v", d.Fields)
	}
}

// TestParseOSReleaseLineEndingsAndBOM: CRLF input, a missing final newline
// and a leading byte order mark do not change the result of any fixture
// (a file edited on Windows parses like the original).
func TestParseOSReleaseLineEndingsAndBOM(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "linux", "*.os-release"))
	if err != nil || len(files) < 8 {
		t.Fatalf("fixtures %v %v", files, err)
	}
	bom := []byte("\xef\xbb\xbf")
	for _, f := range files {
		lf := readLinuxFixture(t, filepath.Base(f))
		want, wantErr := ParseOSReleaseData(lf)
		crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
		variants := map[string][]byte{
			"crlf":            crlf,
			"no final eol":    bytes.TrimSuffix(lf, []byte("\n")),
			"bom lf":          append(append([]byte{}, bom...), lf...),
			"bom crlf":        append(append([]byte{}, bom...), crlf...),
			"crlf no final":   bytes.TrimSuffix(crlf, []byte("\r\n")),
			"bom no final lf": append(append([]byte{}, bom...), bytes.TrimSuffix(lf, []byte("\n"))...),
		}
		for name, in := range variants {
			got, gotErr := ParseOSReleaseData(in)
			if !reflect.DeepEqual(got, want) || !errors.Is(gotErr, wantErr) {
				t.Fatalf("%s %s: got %+v %v, want %+v %v", filepath.Base(f), name, got, gotErr, want, wantErr)
			}
		}
	}
}

// TestParseOSReleaseMalformedFixture: every malformed line is an issue with
// its line number, and its key when only the value is broken. Valid lines
// around them still count, and nothing is repaired or guessed.
func TestParseOSReleaseMalformedFixture(t *testing.T) {
	d, err := ParseOSReleaseData(readLinuxFixture(t, "malformed.os-release"))
	if err != nil {
		t.Fatal(err)
	}
	wantIssues := []OSReleaseIssue{
		{Line: 2, Key: "NAME", Reason: OSReleaseIssueUnterminated},
		{Line: 4, Reason: OSReleaseIssueNotAssignment},
		{Line: 5, Reason: OSReleaseIssueInvalidName},
		{Line: 6, Reason: OSReleaseIssueInvalidName},
		{Line: 7, Key: "PRETTY_NAME", Reason: OSReleaseIssueTextAfterQuote},
		{Line: 8, Key: "ID", Reason: OSReleaseIssueUnquotedBlank},
		{Line: 9, Key: "HOME_URL", Reason: OSReleaseIssueShellExpansion},
		{Line: 10, Key: "SUPPORT_URL", Reason: OSReleaseIssueUnquotedSpecial},
		{Line: 11, Key: "VERSION", Reason: OSReleaseIssueLineContinuation},
		{Line: 12, Key: "ID_LIKE", Reason: OSReleaseIssueUnterminated},
		{Line: 15, Reason: OSReleaseIssueInvalidName},
		{Line: 17, Key: "LOGO", Reason: OSReleaseIssueNonPrintable},
		{Line: 18, Key: "VARIANT_ID", Reason: OSReleaseIssueInvalidUTF8},
	}
	if !reflect.DeepEqual(d.Issues, wantIssues) {
		t.Fatalf("issues\n got %+v\nwant %+v", d.Issues, wantIssues)
	}
	wantFields := map[string]string{"VERSION_ID": "1.0", "IMAGE_ID": "single quoted", "ANSI_COLOR": "0;31"}
	if !reflect.DeepEqual(d.Fields, wantFields) {
		t.Fatalf("fields %v, want %v", d.Fields, wantFields)
	}
	// The unterminated NAME on line 2 neither swallows VERSION_ID on line 3
	// nor becomes a name.
	if d.Info() != (OSInfo{Version: "1.0"}) {
		t.Fatalf("info %+v", d.Info())
	}
}

// TestParseOSReleaseValues pins the value grammar line by line.
func TestParseOSReleaseValues(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		key    string // "" means "K"
		want   string
		reason string // "" means well-formed
	}{
		{name: "unquoted", line: `K=plain-1.0_x`, want: "plain-1.0_x"},
		{name: "double quoted", line: `K="a b"`, want: "a b"},
		{name: "single quoted", line: `K='a b'`, want: "a b"},
		{name: "single quoted is literal", line: `K='a\"b $x` + "`" + `'`, want: `a\"b $x` + "`"},
		{name: "escaped quote", line: `K="a\"b"`, want: `a"b`},
		{name: "escaped backslash", line: `K="a\\b"`, want: `a\b`},
		{name: "escaped dollar", line: `K="a\$b"`, want: `a$b`},
		{name: "escaped backtick", line: "K=\"a\\`b\"", want: "a`b"},
		{name: "other backslash kept", line: `K="a\nb"`, want: `a\nb`},
		{name: "unquoted escape", line: `K=a\ b`, want: "a b"},
		{name: "unquoted escaped trailing blank", line: `K=a\ `, want: "a "},
		{name: "empty", line: `K=`, want: ""},
		{name: "empty quoted", line: `K=""`, want: ""},
		{name: "trailing blanks after quote", line: "K=\"x\" \t ", want: "x"},
		{name: "trailing blanks unquoted", line: "K=x  ", want: "x"},
		{name: "leading blanks", line: "  \tK=x", want: "x"},
		{name: "blanks inside quotes kept", line: `K="  x  "`, want: "  x  "},
		{name: "equals in value", line: `K=a=b`, want: "a=b"},
		{name: "hash inside word", line: `K=a#b`, want: "a#b"},
		{name: "url", line: `K=https://example.org/a?b=c`, want: "https://example.org/a?b=c"},
		{name: "tilde inside word", line: `K=a~b`, want: "a~b"},
		{name: "utf-8", line: `K="Übung Ölçü 日本"`, want: "Übung Ölçü 日本"},
		{name: "lower-case name", line: `k_1=x`, key: "k_1", want: "x"},

		{name: "inline comment after quote", line: `K="x" # c`, reason: OSReleaseIssueTextAfterQuote},
		{name: "concatenation", line: `K="a"'b'`, reason: OSReleaseIssueTextAfterQuote},
		{name: "unquoted inline comment", line: `K=x # c`, reason: OSReleaseIssueUnquotedBlank},
		{name: "unquoted blank", line: `K=a b`, reason: OSReleaseIssueUnquotedBlank},
		{name: "unterminated double", line: `K="abc`, reason: OSReleaseIssueUnterminated},
		{name: "unterminated single", line: `K='abc`, reason: OSReleaseIssueUnterminated},
		{name: "escaped closing quote", line: `K="abc\"`, reason: OSReleaseIssueUnterminated},
		{name: "continuation in quotes", line: `K="abc\`, reason: OSReleaseIssueUnterminated},
		{name: "continuation unquoted", line: `K=abc\`, reason: OSReleaseIssueLineContinuation},
		{name: "parameter expansion", line: `K="$HOME"`, reason: OSReleaseIssueShellExpansion},
		{name: "command substitution", line: "K=\"`id`\"", reason: OSReleaseIssueShellExpansion},
		{name: "dollar parenthesis", line: `K="$(id)"`, reason: OSReleaseIssueShellExpansion},
		{name: "unquoted dollar", line: `K=$HOME`, reason: OSReleaseIssueShellExpansion},
		{name: "unquoted backtick", line: "K=a`id`", reason: OSReleaseIssueShellExpansion},
		{name: "semicolon", line: `K=a;b`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "pipe", line: `K=a|b`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "ampersand", line: `K=a&b`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "redirect", line: `K=a>b`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "parenthesis", line: `K=(a)`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "quote inside word", line: `K=a"b"`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "leading tilde", line: `K=~`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "tilde after colon", line: `K=a:~/b`, reason: OSReleaseIssueUnquotedSpecial},
		{name: "tab in quotes", line: "K=\"a\tb\"", reason: OSReleaseIssueNonPrintable},
		{name: "terminal escape", line: "K=\"\x1b[31mred\"", reason: OSReleaseIssueNonPrintable},
		{name: "NUL", line: "K=\"a\x00b\"", reason: OSReleaseIssueNonPrintable},
		{name: "C1 control", line: "K=\"a\u0085b\"", reason: OSReleaseIssueNonPrintable},
		{name: "bidi override", line: "K=\"a\u202eb\"", reason: OSReleaseIssueNonPrintable},
		{name: "line separator", line: "K=\"a b\"", reason: OSReleaseIssueNonPrintable},
		{name: "stray carriage return", line: "K=x\r\r", reason: OSReleaseIssueNonPrintable},
		{name: "invalid utf-8", line: "K=\"\xff\"", reason: OSReleaseIssueInvalidUTF8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.key
			if key == "" {
				key = "K"
			}
			d, err := ParseOSReleaseData([]byte(tc.line + "\n"))
			if tc.reason == "" {
				v, ok := d.Fields[key]
				if err != nil || len(d.Issues) != 0 || !ok || v != tc.want {
					t.Fatalf("got %q (set %v) issues %+v err %v, want %q", v, ok, d.Issues, err, tc.want)
				}
				return
			}
			want := []OSReleaseIssue{{Line: 1, Key: key, Reason: tc.reason}}
			if !errors.Is(err, ErrNoFields) || len(d.Fields) != 0 || !reflect.DeepEqual(d.Issues, want) {
				t.Fatalf("fields %v issues %+v err %v, want %+v", d.Fields, d.Issues, err, want)
			}
		})
	}
}

// TestParseOSReleaseNames: a line with a bad name or no "=" is an issue
// without a key.
func TestParseOSReleaseNames(t *testing.T) {
	cases := map[string]string{
		`K = v`:       OSReleaseIssueInvalidName,
		`export K=v`:  OSReleaseIssueInvalidName,
		`1K=v`:        OSReleaseIssueInvalidName,
		`K-X=v`:       OSReleaseIssueInvalidName,
		`=v`:          OSReleaseIssueInvalidName,
		`K`:           OSReleaseIssueNotAssignment,
		`NAME Ubuntu`: OSReleaseIssueNotAssignment,
	}
	for line, reason := range cases {
		d, err := ParseOSReleaseData([]byte(line + "\n"))
		want := []OSReleaseIssue{{Line: 1, Reason: reason}}
		if !errors.Is(err, ErrNoFields) || !reflect.DeepEqual(d.Issues, want) {
			t.Fatalf("%q: issues %+v err %v, want %+v", line, d.Issues, err, want)
		}
	}
}

// TestParseOSReleaseNoFields: content without any well-formed assignment is
// ErrNoFields, and ParseOSRelease then returns no OSInfo at all.
func TestParseOSReleaseNoFields(t *testing.T) {
	for _, in := range []string{"", "\n\n", "# only a comment\n", "\xef\xbb\xbf", "  \t \n\t# x\n", "garbage\n", "NAME=\"open\n"} {
		d, err := ParseOSReleaseData([]byte(in))
		if !errors.Is(err, ErrNoFields) || d.Fields == nil || len(d.Fields) != 0 {
			t.Fatalf("%q: fields %v err %v", in, d.Fields, err)
		}
		if info, err := ParseOSRelease([]byte(in)); !errors.Is(err, ErrNoFields) || info != (OSInfo{}) {
			t.Fatalf("%q: ParseOSRelease %+v %v", in, info, err)
		}
	}
	if _, err := ParseOSReleaseData(nil); !errors.Is(err, ErrNoFields) {
		t.Fatalf("nil: %v", err)
	}
}

// TestParseOSReleaseMissingNotInvented: absent keys stay empty. There is no
// os-release(5) default ("NAME=Linux") and no stand-in from PRETTY_NAME,
// VERSION or ID; a present but empty key is kept as empty.
func TestParseOSReleaseMissingNotInvented(t *testing.T) {
	d, err := ParseOSReleaseData(readLinuxFixture(t, "minimal.os-release"))
	if err != nil || d.Info() != (OSInfo{}) || !reflect.DeepEqual(d.Fields, map[string]string{"ID": "linux"}) {
		t.Fatalf("minimal: %+v %v", d, err)
	}
	info, err := ParseOSRelease([]byte("PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nID=ubuntu\n"))
	if err != nil || info != (OSInfo{}) {
		t.Fatalf("no stand-in expected: %+v %v", info, err)
	}
	d, err = ParseOSReleaseData([]byte("NAME=\"Example\"\nVERSION_ID=\"\"\n"))
	if v, ok := d.Fields["VERSION_ID"]; err != nil || !ok || v != "" || d.Info() != (OSInfo{Name: "Example"}) {
		t.Fatalf("empty VERSION_ID: %+v %v", d, err)
	}
}

// TestParseOSReleaseLaterAssignmentWins: shell semantics for a repeated key.
func TestParseOSReleaseLaterAssignmentWins(t *testing.T) {
	info, err := ParseOSRelease([]byte("NAME=first\nVERSION_ID=1\nNAME=\"second\"\n"))
	if err != nil || info != (OSInfo{Name: "second", Version: "1"}) {
		t.Fatalf("%+v %v", info, err)
	}
}

// TestIdentityLinuxDistributionFixtures runs the linux path of
// common.identity over every fixture through the default redactor
// (SPEC-0467 R5): real distribution files reach the parser unchanged, so a
// redaction false positive cannot silently drop NAME, and a file with a
// missing or malformed field never yields a captured identity.
func TestIdentityLinuxDistributionFixtures(t *testing.T) {
	for _, tc := range linuxDistributions {
		t.Run(tc.file, func(t *testing.T) {
			b := readLinuxFixture(t, tc.file)
			cc, ev := collectCtx("linux", linuxFiles(string(b)), unameRunner("6.8.0-45-generic"))
			r := NewIdentityProbe().Collect(context.Background(), cc)
			a := artifact(t, r, ArtifactOS)
			want := map[string]string{
				AttrOSFamily: "linux", AttrArch: "arm64", AttrKernelRelease: "6.8.0-45-generic",
				AttrOSName: tc.info.Name,
			}
			if tc.info.Version != "" {
				want[AttrOSVersion] = tc.info.Version
			}
			if tc.info.Build != "" {
				want[AttrOSBuild] = tc.info.Build
			}
			wantAttrs(t, a, want)
			if tc.info.Version != "" && r.Status != trustfreeze.StatusCaptured {
				t.Fatalf("status %s %+v", r.Status, r.Warnings)
			}
			found := false
			for _, item := range ev.Close() {
				if item.Name == "os-release" {
					found = true
					if !bytes.Equal(item.Data.Bytes(), b) {
						t.Fatalf("redaction changed a distribution file:\n%s", item.Data.Bytes())
					}
				}
			}
			if !found {
				t.Fatal("no os-release evidence")
			}
		})
	}
	for _, f := range []string{"minimal.os-release", "malformed.os-release"} {
		cc, _ := collectCtx("linux", linuxFiles(string(readLinuxFixture(t, f))), unameRunner("6.8.0"))
		r := NewIdentityProbe().Collect(context.Background(), cc)
		if r.Status == trustfreeze.StatusCaptured {
			t.Fatalf("%s: captured although NAME is missing", f)
		}
		if a := artifact(t, r, ArtifactOS); a.Attributes[AttrOSName] != "" {
			t.Fatalf("%s: os_name invented: %v", f, a.Attributes)
		}
	}
}
