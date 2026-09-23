package redact

import (
	"regexp"
	"strings"
	"testing"
)

// separatorRunes are the characters that structure the output of the tools
// the Linux probes parse: colon in getent passwd and getent group, tab in
// dpkg-query and ss, comma in a GECOS field and in a group member list,
// semicolon in a sudoers rule, equals sign in an id(1) token and in a
// key=value line, space in sshd_config and in every whitespace separated
// table, and the two line terminators in every line oriented format. A
// replacement marker that carries one of them turns one record into two, or
// one field into two, and the parser then refuses the record. That is how a
// real capture on an Ubuntu host lost the root account: the marker for the
// home path carried a colon, so line 1 of getent passwd had eight fields
// instead of seven.
var separatorRunes = []struct {
	name string
	r    rune
}{
	{"colon", ':'},
	{"tab", '\t'},
	{"comma", ','},
	{"semicolon", ';'},
	{"equals sign", '='},
	{"space", ' '},
	{"line feed", '\n'},
	{"carriage return", '\r'},
}

// defaultClasses are the redaction classes this package can produce on its
// own: the pattern classes, the classes SensitiveKeyClass derives from a key,
// the argument secret class, and the two classes its callers register through
// WithLiteral and WithPattern (home_path in the capture engine,
// redaction_failed in the command runner).
func defaultClasses() []string {
	out := []string{ClassArgSecret, "home_path", "redaction_failed"}
	for _, r := range defaultRules() {
		if r.class != "" {
			out = append(out, r.class)
		}
	}
	for _, kc := range keyClasses {
		out = append(out, kc.class)
	}
	return out
}

// TestMarkerCarriesNoFieldSeparator is the guard for the defect measured on
// Ubuntu 22.04: no marker this package emits may carry a character that
// separates fields or records in the output the probes parse (SPEC-0467
// redaction contract).
func TestMarkerCarriesNoFieldSeparator(t *testing.T) {
	for _, class := range defaultClasses() {
		marker := Marker(class)
		for _, sep := range separatorRunes {
			if strings.ContainsRune(marker, sep.r) {
				t.Errorf("marker %q for class %q contains a %s; it would split the record it replaces a value in", marker, class, sep.name)
			}
		}
		if !isMarker([]byte(marker)) {
			t.Errorf("marker %q for class %q is not recognized by exactMarker", marker, class)
		}
	}
	for _, sep := range separatorRunes {
		if strings.ContainsRune(markerPrefix, sep.r) {
			t.Errorf("markerPrefix %q contains a %s", markerPrefix, sep.name)
		}
	}
}

// TestMarkerIsOneWhitespaceFreeToken states the contract positively: a marker
// is a single token, so a whitespace split of a line sees exactly one field
// where the value stood.
func TestMarkerIsOneWhitespaceFreeToken(t *testing.T) {
	for _, class := range defaultClasses() {
		if got := strings.Fields(Marker(class)); len(got) != 1 {
			t.Errorf("marker %q for class %q is %d whitespace separated tokens, want 1", Marker(class), class, len(got))
		}
	}
}

// TestClassWithSeparatorIsRefused: a class that would smuggle a separator
// into the marker is refused at registration, so a later custom class cannot
// reintroduce the defect.
func TestClassWithSeparatorIsRefused(t *testing.T) {
	for _, bad := range []string{"home:path", "home path", "home,path", "home;path", "home=path", "home\tpath", "home\npath", "", "Home_Path"} {
		if err := checkClass(bad); err == nil {
			t.Errorf("class %q was accepted", bad)
		}
		if _, err := New(WithLiteral("/home/alice", bad)); err == nil {
			t.Errorf("WithLiteral accepted class %q", bad)
		}
		if _, err := New(WithPattern(bad, "x", 0)); err == nil {
			t.Errorf("WithPattern accepted class %q", bad)
		}
	}
}

// TestExactMarkerMatchesTheMarkerItBuilds keeps Marker and exactMarker in one
// shape: a second redaction pass recognizes what the first one wrote, and the
// idempotence of quotedReplacement and keyedMarker rests on that.
func TestExactMarkerMatchesTheMarkerItBuilds(t *testing.T) {
	if !strings.HasPrefix(exactMarker.String(), "^"+regexp.QuoteMeta(markerPrefix)) {
		t.Fatalf("exactMarker %q does not start with the marker prefix %q", exactMarker.String(), markerPrefix)
	}
	out, _ := redactString(t, mustRedactor(t, WithLiteral("/home/alice", "home_path")), Marker("home_path"))
	if out != Marker("home_path") {
		t.Fatalf("a second pass changed the marker: %q", out)
	}
}

func mustRedactor(t *testing.T, opts ...Option) *Redactor {
	t.Helper()
	r, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}
