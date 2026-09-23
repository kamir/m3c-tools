package trustfreeze

import (
	"errors"
	"path"
	"strings"
	"testing"
)

// TestCanonicalPath covers the SPEC-0466 path rules.
func TestCanonicalPath(t *testing.T) {
	ok := map[string]string{
		"capture.json":                    "capture.json",
		"probes/common.identity.json":     "probes/common.identity.json",
		`probes\common.identity.json`:     "probes/common.identity.json",
		`evidence\common.identity\stdout`: "evidence/common.identity/stdout",
		"a/b_c-d+e@f=g,h.json":            "a/b_c-d+e@f=g,h.json",
		".hidden":                         ".hidden",
		"state/Device.json":               "state/Device.json",
	}
	for in, want := range ok {
		got, err := CanonicalPath(in)
		if err != nil {
			t.Errorf("CanonicalPath(%q) error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CanonicalPath(%q) = %q, want %q", in, got, want)
		}
		if path.Clean(got) != got {
			t.Errorf("CanonicalPath(%q) = %q is not path.Clean", in, got)
		}
	}
	bad := map[string]string{
		"":                       "empty",
		"a\x00b":                 "NUL",
		"/etc/passwd":            "absolute",
		`\etc\passwd`:            "absolute via backslash",
		"//server/share/x":       "UNC",
		`\\server\share\x`:       "UNC via backslash",
		"C:/x":                   "drive letter",
		`C:\x`:                   "drive letter via backslash",
		"c:":                     "bare drive",
		"C:x":                    "drive relative",
		"../x":                   "parent traversal",
		`..\x`:                   "parent traversal via backslash",
		"a/../../x":              "inner traversal",
		"a/./b":                  "dot segment",
		".":                      "dot",
		"..":                     "dotdot",
		"a//b":                   "empty segment",
		"a/":                     "trailing slash",
		`a\`:                     "trailing backslash",
		"a/b:c":                  "colon (NTFS stream)",
		"a b":                    "space",
		"PROGRA~1/x":             "tilde (8.3 alias)",
		"caf\u00e9.json":         "non-ASCII",
		"a./b":                   "trailing dot",
		"con":                    "device name",
		"NUL.txt":                "device name with extension",
		"x/com1.json":            "COM port device name",
		"lpt9":                   "LPT device name",
		strings.Repeat("a", 256): "segment too long",
	}
	for in, why := range bad {
		if got, err := CanonicalPath(in); err == nil {
			t.Errorf("CanonicalPath(%q) = %q, want rejection (%s)", in, got, why)
		} else if !errors.Is(err, ErrBadPath) {
			t.Errorf("CanonicalPath(%q) error %v does not wrap ErrBadPath", in, err)
		}
	}
}

// TestTF01AC5WindowsAndUnixPathsCanonicalizeIdentically (SPEC-0466 TF01-AC5).
func TestTF01AC5WindowsAndUnixPathsCanonicalizeIdentically(t *testing.T) {
	pairs := [][2]string{
		{`probes\common.identity.json`, "probes/common.identity.json"},
		{`evidence\common.identity\sw_vers.stdout`, "evidence/common.identity/sw_vers.stdout"},
		{`state\device.json`, "state/device.json"},
		{`a\b/c`, "a/b/c"},
	}
	for _, p := range pairs {
		w, err := CanonicalPath(p[0])
		if err != nil {
			t.Fatal(err)
		}
		u, err := CanonicalPath(p[1])
		if err != nil {
			t.Fatal(err)
		}
		if w != u {
			t.Fatalf("%q -> %q but %q -> %q", p[0], w, p[1], u)
		}
		// The manifest representation of the file entry is identical too.
		a, err := MarshalCanonical(FileEntry{Path: w, Size: 1, SHA256: SHA256Hex([]byte("x"))})
		if err != nil {
			t.Fatal(err)
		}
		b, err := MarshalCanonical(FileEntry{Path: u, Size: 1, SHA256: SHA256Hex([]byte("x"))})
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("manifest entries differ: %s vs %s", a, b)
		}
	}
}

func TestPathFoldKey(t *testing.T) {
	if PathFoldKey("State/Device.JSON") != PathFoldKey("state/device.json") {
		t.Fatal("case-only variants must share a fold key")
	}
	if PathFoldKey("a.json") == PathFoldKey("b.json") {
		t.Fatal("different paths must not share a fold key")
	}
}

// An artifact id is text, and ranging over a string turns every invalid byte
// into U+FFFD, so the rune tests of ValidateArtifactID cannot see raw non-UTF-8
// bytes. The id below is the one a mutation battery produced out of dpkg
// output; it must be refused, not carried into a bundle.
func TestValidateArtifactIDRejectsInvalidUTF8(t *testing.T) {
	for _, id := range []string{
		"os/package/ac\xff\xfecountsservice",
		"os/package/\xff",
		"device/\xc3(",
	} {
		if err := ValidateArtifactID(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("ValidateArtifactID(%q) = %v, want ErrInvalidID", id, err)
		}
	}
	// The valid UTF-8 spelling of the same package name stays acceptable, so
	// the check refuses broken bytes and not non-ASCII text.
	for _, id := range []string{"os/package/accountsservice", "os/package/k\u00e4mpfer"} {
		if err := ValidateArtifactID(id); err != nil {
			t.Errorf("ValidateArtifactID(%q) = %v", id, err)
		}
	}
}

func TestValidateIDs(t *testing.T) {
	for _, id := range []string{"device/os", "device/host", "network/listener/tcp/203.0.113.10/4040", "claude/skill/user/code-reviewer", "device/user/S-1-5-21-1"} {
		if err := ValidateArtifactID(id); err != nil {
			t.Errorf("ValidateArtifactID(%q) = %v", id, err)
		}
	}
	for _, id := range []string{"", "/home/alice/x", "project/~/x", `C:\Users\alice`, "device/C:/x", "a//b", "a/../b", "a/./b", "a b", "a\tb"} {
		if err := ValidateArtifactID(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("ValidateArtifactID(%q) = %v, want ErrInvalidID", id, err)
		}
	}
	for _, id := range []string{"common.identity", "linux.ssh.effective", "platform.network.listeners", "a1_b-c"} {
		if err := ValidateProbeID(id); err != nil {
			t.Errorf("ValidateProbeID(%q) = %v", id, err)
		}
	}
	for _, id := range []string{"", "Common.identity", "1abc", "a..b", "a.", "a/b", "a b", "a:b", "../x"} {
		if err := ValidateProbeID(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("ValidateProbeID(%q) = %v, want ErrInvalidID", id, err)
		}
	}
	if p, err := ProbeResultPath("common.identity"); err != nil || p != "probes/common.identity.json" {
		t.Fatalf("ProbeResultPath = %q, %v", p, err)
	}
	if p, err := EvidencePath("common.identity", "sw_vers.stdout"); err != nil || p != "evidence/common.identity/sw_vers.stdout" {
		t.Fatalf("EvidencePath = %q, %v", p, err)
	}
	for _, name := range []string{"a/b", "..", "", "x:y", `a\b`} {
		if _, err := EvidencePath("common.identity", name); err == nil {
			t.Errorf("EvidencePath(%q) accepted", name)
		}
	}
}
