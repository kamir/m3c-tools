package cliargs

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func newSet() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("registry", "", "")
	fs.Bool("old", false, "")
	return fs
}

func TestFlagsFirst(t *testing.T) {
	for _, tc := range []struct {
		in, want []string
	}{
		{[]string{"demo", "--registry", "r"}, []string{"--registry", "r", "--", "demo"}},
		{[]string{"--registry", "r", "demo"}, []string{"--registry", "r", "--", "demo"}},
		{[]string{"demo", "--registry=r", "--old"}, []string{"--registry=r", "--old", "--", "demo"}},
		{[]string{"demo", "-registry", "r"}, []string{"-registry", "r", "--", "demo"}},
		// A value that looks like a flag is still the value of a known flag.
		{[]string{"demo", "--registry", "-x"}, []string{"--registry", "-x", "--", "demo"}},
		// A user's "--" ends flag handling; nothing after it becomes a flag.
		{[]string{"--old", "--", "demo", "--registry", "r"}, []string{"--old", "--", "demo", "--registry", "r"}},
		// "-" alone is a positional.
		{[]string{"-", "--old"}, []string{"--old", "--", "-"}},
		// Unknown flags stay flags, so Parse reports them.
		{[]string{"demo", "--nope"}, []string{"--nope", "--", "demo"}},
		// A dangling value flag ends the list, with no "--" for it to swallow.
		{[]string{"demo", "--old", "--registry"}, []string{"--old", "--registry"}},
	} {
		if got := FlagsFirst(newSet(), tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("FlagsFirst(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFlagsFirstParsesBothOrdersAlike(t *testing.T) {
	a, b := newSet(), newSet()
	if err := a.Parse(FlagsFirst(a, []string{"--registry", "r", "--old", "demo"})); err != nil {
		t.Fatal(err)
	}
	if err := b.Parse(FlagsFirst(b, []string{"demo", "--old", "--registry", "r"})); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"registry", "old"} {
		if a.Lookup(name).Value.String() != b.Lookup(name).Value.String() {
			t.Errorf("flag %s differs: %q vs %q", name, a.Lookup(name).Value, b.Lookup(name).Value)
		}
	}
	if !reflect.DeepEqual(a.Args(), b.Args()) || len(a.Args()) != 1 || a.Arg(0) != "demo" {
		t.Errorf("positionals differ: %q vs %q", a.Args(), b.Args())
	}
}

func TestFlagsFirstKeepsMissingValueAnError(t *testing.T) {
	fs := newSet()
	if err := fs.Parse(FlagsFirst(fs, []string{"demo", "--registry"})); err == nil {
		t.Fatal("a value flag without a value parsed without error")
	}
}
