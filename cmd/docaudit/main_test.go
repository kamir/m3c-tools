package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeFile writes s to dir/name and fails the test on error.
func writeFile(t *testing.T, dir, name, s string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestCanonCollapsesDashSpellings(t *testing.T) {
	for _, in := range []string{"force", "-force", "--force"} {
		if got := canon(in); got != "force" {
			t.Errorf("canon(%q) = %q, want %q", in, got, "force")
		}
	}
}

// codeFlags must find flags through all three strategies, and must NOT mistake
// another program's arguments for our own CLI surface.
func TestCodeFlagsThreeStrategies(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cmds.go", `package main

import (
	"flag"
	"os/exec"
)

func regs() {
	fs := flag.NewFlagSet("thing", flag.ContinueOnError)
	fs.String("reviewer-id", "", "who reviews")     // strategy 1: value form
	var p bool
	fs.BoolVar(&p, "dry-run", false, "preview")     // strategy 1: Var form
	fs.Func("limit", "k=v", nil)                    // strategy 1: Func form
	_ = fs
}

func handrolled(args []string) {
	for _, a := range args {
		switch a {
		case "--all":                                // strategy 2: -- literal
		case "-f", "--force":                        // strategy 3: alias + sibling
		case "--tags":
		}
		if a == "--dry-run" || a == "-n" {           // strategy 3: if-cond group
		}
	}
}

func foreign() {
	// NOT our flags: lone single-dash literals naming other programs' args.
	_ = exec.Command("open", "-a", "Google Chrome")
	if err := exec.Command("stty", "-echo").Run(); err == nil {
	}
	_ = exec.Command("security", "find-generic-password", "-s", "svc", "-w")
}
`)
	got, err := codeFlags(dir)
	if err != nil {
		t.Fatalf("codeFlags: %v", err)
	}
	want := []string{"all", "dry-run", "f", "force", "limit", "n", "reviewer-id", "tags"}
	if strings.Join(keys(got), " ") != strings.Join(want, " ") {
		t.Errorf("codeFlags = %v, want %v", keys(got), want)
	}
}

// A single-dash literal with no --long sibling in the same group is not a flag:
// that is the rule that keeps `open -a` / `stty -echo` out of the surface.
func TestShortAliasNeedsALongSibling(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "x.go", `package main

func f(a string) {
	switch a {
	case "-x":            // no --long sibling → not a flag
	}
	switch a {
	case "-y", "--yes":   // sibling present → -y is a flag
	}
}
`)
	got, err := codeFlags(dir)
	if err != nil {
		t.Fatalf("codeFlags: %v", err)
	}
	if got["x"] {
		t.Error(`"-x" was admitted without a --long sibling`)
	}
	if !got["y"] || !got["yes"] {
		t.Errorf(`want y and yes admitted, got %v`, keys(got))
	}
}

func TestCodeFlagsIgnoresTestFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real.go", "package main\n\nfunc a(s string) { switch s {\ncase \"--real\":\n} }\n")
	writeFile(t, dir, "real_test.go", "package main\n\nfunc b(s string) { switch s {\ncase \"--only-in-tests\":\n} }\n")
	got, err := codeFlags(dir)
	if err != nil {
		t.Fatalf("codeFlags: %v", err)
	}
	if !got["real"] {
		t.Error("--real not found in the non-test file")
	}
	if got["only-in-tests"] {
		t.Error("a flag from a _test.go file leaked into the surface")
	}
}

// docFlags counts a flag only where the manual DEFINES it: an inline code span
// that LEADS with the flag. A command line, or anything in a fenced block, is a
// mention, not a definition.
func TestDocFlagsCountsDefinitionsNotMentions(t *testing.T) {
	dir := t.TempDir()
	m := writeFile(t, dir, "manual.md", strings.Join([]string{
		"| Flag | Purpose |",
		"|------|---------|",
		"| `--skill <dir>` | defined: leads the span |",
		"| `-o, --output <path>` | defined: leading alias list |",
		"| `--author-intent green|yellow|red` | defined, value is not a flag |",
		"| `--a` / `--b` | two spans, both leading |",
		"",
		"Run `skillctl report --input <scan.json>`: a command line, so its --input is",
		"only mentioned, never defined.",
		"",
		"```bash",
		"skillctl thing --in-a-fence  `--also-fenced`",
		"```",
		"",
		"A path span like `~/.claude/skills` defines nothing.",
	}, "\n"))
	got, err := docFlags(m)
	if err != nil {
		t.Fatalf("docFlags: %v", err)
	}
	want := []string{"a", "author-intent", "b", "o", "output", "skill"}
	if strings.Join(keys(got), " ") != strings.Join(want, " ") {
		t.Errorf("docFlags = %v, want %v", keys(got), want)
	}
}

func TestSpanFlags(t *testing.T) {
	cases := []struct {
		span string
		want []string
	}{
		{"--skill <dir>", []string{"skill"}},
		{"-o, --output <path>", []string{"o", "output"}},
		{"--a / --b", []string{"a", "b"}},
		{"-key", []string{"key"}},
		{"skillctl verify --all", nil},
		{"~/.claude/skills", nil},
		{"--<flag> <value>", nil}, // the manuals' meta-placeholder
		{"", nil},
	}
	for _, c := range cases {
		got := spanFlags(c.span)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("spanFlags(%q) = %v, want %v", c.span, got, c.want)
		}
	}
}

// audit is bidirectional: a real-but-undocumented flag and a documented-but-gone
// flag are both drift, and an exemption silences either direction.
func TestAuditBothDirectionsAndExemptions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg/cli.go", "package main\n\nfunc f(s string) { switch s {\ncase \"--kept\":\ncase \"--undocumented\":\n} }\n")
	manual := writeFile(t, dir, "manual.md", "| `--kept` | ok |\n| `--phantom` | code moved on |\n")
	tg := target{Name: "toy", PkgDir: filepath.Join(dir, "pkg"), Manual: manual}

	r, err := audit(tg, map[string]bool{})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if strings.Join(r.Undocumented, " ") != "--undocumented" {
		t.Errorf("Undocumented = %v, want [--undocumented]", r.Undocumented)
	}
	if strings.Join(r.Phantom, " ") != "--phantom" {
		t.Errorf("Phantom = %v, want [--phantom]", r.Phantom)
	}
	if r.clean() {
		t.Error("report with drift reported clean")
	}

	exempt := map[string]bool{"toy:--undocumented": true, "--phantom": true}
	r2, err := audit(tg, exempt)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !r2.clean() {
		t.Errorf("exemptions did not silence both directions: %+v", r2)
	}
}

// An exemption scoped to another CLI must not silence this one. Otherwise one
// CLI's justified exemption would quietly widen the hole for every other.
func TestExemptionScopeIsPerCLI(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg/cli.go", "package main\n\nfunc f(s string) { switch s {\ncase \"--only-here\":\n} }\n")
	manual := writeFile(t, dir, "manual.md", "nothing documented\n")
	tg := target{Name: "toy", PkgDir: filepath.Join(dir, "pkg"), Manual: manual}

	r, err := audit(tg, map[string]bool{"other-cli:--only-here": true})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if r.clean() {
		t.Error("an exemption scoped to other-cli silenced toy's drift")
	}
}

func TestLoadIgnoreParsesCommentsAndScopes(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ignore.txt", strings.Join([]string{
		"# a comment line",
		"",
		"--global            # applies to every CLI",
		"skillctl:--scoped   # only skillctl",
		"   ",
	}, "\n"))
	got, err := loadIgnore(p)
	if err != nil {
		t.Fatalf("loadIgnore: %v", err)
	}
	want := []string{"--global", "skillctl:--scoped"}
	if strings.Join(keys(got), " ") != strings.Join(want, " ") {
		t.Errorf("loadIgnore = %v, want %v", keys(got), want)
	}
}

func TestLoadIgnoreMissingFileIsNotAnError(t *testing.T) {
	got, err := loadIgnore(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil {
		t.Fatalf("missing ignore file must not error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty exemption set, got %v", keys(got))
	}
}

// The gate's contract with CI: 0 = consistent, 1 = drift (block the release),
// 2 = usage/IO error. A broken invocation must never look like a pass.
func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "clean/cli.go", "package main\n\nfunc f(s string) { switch s {\ncase \"--ok\":\n} }\n")
	cleanManual := writeFile(t, dir, "clean.md", "| `--ok` | documented |\n")
	writeFile(t, dir, "dirty/cli.go", "package main\n\nfunc f(s string) { switch s {\ncase \"--ghost\":\n} }\n")
	dirtyManual := writeFile(t, dir, "dirty.md", "nothing\n")

	cfg := func(name string, tg []target) string {
		b, err := json.Marshal(tg)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		return writeFile(t, dir, name, string(b))
	}
	cleanCfg := cfg("clean.json", []target{{Name: "clean", PkgDir: filepath.Join(dir, "clean"), Manual: cleanManual}})
	dirtyCfg := cfg("dirty.json", []target{{Name: "dirty", PkgDir: filepath.Join(dir, "dirty"), Manual: dirtyManual}})
	missing := filepath.Join(dir, "no-such.json")
	noIgnore := filepath.Join(dir, "no-ignore.txt")

	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"consistent", []string{"-config", cleanCfg, "-ignore", noIgnore}, 0},
		{"drift blocks", []string{"-config", dirtyCfg, "-ignore", noIgnore}, 1},
		{"drift blocks in json mode", []string{"-config", dirtyCfg, "-ignore", noIgnore, "-json"}, 1},
		{"scaffold is advisory, not the gate", []string{"-config", dirtyCfg, "-ignore", noIgnore, "-scaffold"}, 0},
		{"unknown argument", []string{"--nope"}, 2},
		{"missing config", []string{"-config", missing}, 2},
		{"no CLI matches", []string{"-config", cleanCfg, "-ignore", noIgnore, "-cli", "nobody"}, 2},
		{"help", []string{"-h"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := run(c.argv); got != c.want {
				t.Errorf("run(%v) = %d, want %d", c.argv, got, c.want)
			}
		})
	}
}

// The repo's own surface must stay green: this is the test that turns the gate
// into a release blocker rather than a script someone remembers to run.
func TestRepoSurfaceIsConsistent(t *testing.T) {
	t.Chdir("../..") // restored by the test framework, so no other test is affected
	if got := run([]string{"-cli", "all"}); got != 0 {
		t.Errorf("docaudit -cli all = %d, want 0: the CLI surface and the manuals disagree; run `go run ./cmd/docaudit -cli <cli> -scaffold`", got)
	}
}

// usageAudit must read BOTH surfaces out of the same package by AST, and must
// treat a usage text made of many Fprintln calls exactly like one made of a
// single raw string: the two CLIs in this repository use the two different
// idioms, so a check that only understood one would silently pass the other.
func TestUsageAuditReadsBothUsageIdioms(t *testing.T) {
	fprintln := `package main

import (
	"fmt"
	"os"
)

func main() {
	switch os.Args[1] {
	case "pack":
	case "sign":
	case "help", "--help", "-h":
		printUsage(os.Stdout)
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage: tool <command>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Authoring")
	fmt.Fprintln(w, "  pack                    Build a bundle.")
	fmt.Fprintln(w, "                          Continuation: mentions sign but does not list it.")
	fmt.Fprintln(w, "  sign                    Sign a bundle.")
	fmt.Fprintln(w, "  help, --help, -h        Print this list.")
}
`
	rawString := "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\tswitch os.Args[1] {\n\tcase \"pack\":\n\tcase \"sign\":\n\tcase \"help\", \"--help\", \"-h\":\n\t\tprintUsage()\n\t}\n}\n\nfunc printUsage() {\n\tfmt.Println(`Usage: tool <command>\n\nAuthoring\n  pack                    Build a bundle.\n                          Continuation: mentions sign but does not list it.\n  sign                    Sign a bundle.\n  help, --help, -h        Print this list.`)\n}\n"

	for _, tc := range []struct{ name, src string }{
		{"fprintln-per-line", fprintln},
		{"one-raw-string", rawString},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "main.go", tc.src)
			dispatched, listed, err := usageAudit(dir)
			if err != nil {
				t.Fatalf("usageAudit: %v", err)
			}
			want := []string{"--help", "-h", "help", "pack", "sign"}
			if got := keys(dispatched); !equalStrings(got, want) {
				t.Errorf("dispatched = %v, want %v", got, want)
			}
			if got := keys(listed); !equalStrings(got, want) {
				t.Errorf("listed = %v, want %v", got, want)
			}
		})
	}
}

// A dispatched verb with no usage line is the whole point of the check. The
// continuation line that MENTIONS the verb must not count as naming it: only a
// line indented exactly two spaces does.
func TestUsageAuditFindsUnlistedAndPhantomVerbs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

import (
	"fmt"
	"os"
)

func main() {
	switch os.Args[1] {
	case "pack":
	case "revoke":
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Commands")
	fmt.Fprintln(w, "  pack       Build a bundle.")
	fmt.Fprintln(w, "             Superseded by revoke one day; this line must not list it.")
	fmt.Fprintln(w, "  seal       A verb the switch no longer dispatches.")
}
`)
	dispatched, listed, err := usageAudit(dir)
	if err != nil {
		t.Fatalf("usageAudit: %v", err)
	}
	if listed["revoke"] {
		t.Error("a continuation line must not count as naming a verb")
	}
	if !dispatched["revoke"] || listed["revoke"] {
		t.Error("revoke must be reported as dispatched-but-unlisted")
	}
	if dispatched["seal"] || !listed["seal"] {
		t.Error("seal must be reported as listed-but-never-dispatched")
	}
}

// The gate must not be disableable by a rename: a package that dispatches on
// os.Args[1] and has no printUsage is an ERROR, not a silent skip. A package
// that never dispatches is a legitimate skip.
func TestUsageAuditFailsClosedOnAMissingUsageFunc(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

import "os"

func main() {
	switch os.Args[1] {
	case "pack":
	}
}
`)
	if _, _, err := usageAudit(dir); err == nil {
		t.Fatal("want an error when a dispatching package has no printUsage, got nil")
	}

	skip := t.TempDir()
	writeFile(t, skip, "main.go", `package main

func main() {}
`)
	dispatched, listed, err := usageAudit(skip)
	if err != nil {
		t.Fatalf("a package without the dispatch idiom must be skipped, got %v", err)
	}
	if len(dispatched) != 0 || len(listed) != 0 {
		t.Errorf("want both surfaces empty on a skip, got %v / %v", keys(dispatched), keys(listed))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
