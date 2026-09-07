package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
)

// ---------------------------------------------------------------------------
// The guard that matters: the SHIPPED docs must agree with the SHIPPED register.
// Everything below it proves the individual findings actually fire, because a
// gate that cannot go red is decoration.
// ---------------------------------------------------------------------------

func TestShippedDocs_AgreeWithTheRegister(t *testing.T) {
	root := filepath.Join("..", "..")
	manual := filepath.Join(root, defaultManual)
	verbs := filepath.Join(root, defaultVerbs)
	mb, err := os.ReadFile(manual)
	if err != nil {
		t.Fatalf("read manual: %v", err)
	}
	vb, err := os.ReadFile(verbs)
	if err != nil {
		t.Fatalf("read verb register: %v", err)
	}
	rep, err := reconcile(manual, verbs, root, string(mb), string(vb))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !rep.ok() {
		t.Errorf("the shipped docs drifted from exitcode.AllCodes():\n  undocumented=%v\n  invented=%v\n  unaccounted=%v\n  bad_source=%v\n  verb_drift=%v",
			rep.Undocumented, rep.Invented, rep.Unaccounted, rep.BadSource, rep.VerbDrift)
	}
}

// The generated block in the shipped manual must be exactly what -write would
// produce, so `exitaudit -write` is a no-op on a clean tree and a reviewer never
// sees a spurious diff.
func TestShippedManual_RegisterBlockIsGenerated(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", defaultManual))
	if err != nil {
		t.Fatalf("read manual: %v", err)
	}
	text := string(b)
	rows, err := parseRegisterTable(text)
	if err != nil {
		t.Fatalf("parse register table: %v", err)
	}
	want := renderRegisterBlock(exitcode.AllCodes(), rows)
	got, err := blockBody(text, registerBegin, registerEnd)
	if err != nil {
		t.Fatalf("block body: %v", err)
	}
	if got != want {
		t.Errorf("the manual's register block is not what -write renders; run `go run ./cmd/exitaudit -write`.\n--- in the manual ---\n%s\n--- rendered ---\n%s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Fixtures: a synthetic manual carrying the REAL register block (so parity
// holds) plus whatever the individual case wants to break.
// ---------------------------------------------------------------------------

type fixture struct {
	root   string
	manual string
	verbs  string
}

// newFixture builds a passing manual + verb register in a temp dir. exitLines
// is appended verbatim inside a `pull` section, and every outside-table source
// points at a file the fixture actually creates.
func newFixture(t *testing.T, extraRegisterRows, extraOutsideRows, pullExit, pullCell string) fixture {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "owner.go"), []byte("package owner\n"), 0o600); err != nil {
		t.Fatalf("write owner: %v", err)
	}
	if pullExit == "" {
		pullExit = "Exit: `0` ok · `1` mixed · `2` usage."
	}
	if pullCell == "" {
		pullCell = "0/1/2"
	}
	manual := "# manual\n\n## Exit codes\n\n### The register\n\n" +
		registerBegin + renderRegisterBlock(exitcode.AllCodes(), nil) + extraRegisterRows + registerEnd + "\n\n" +
		"### Codes outside the register\n\n" +
		outsideBegin + "\n\n| Code | Surface | Source | Why |\n|---|---|---|---|\n" +
		"| `0` | all | `owner.go` | success |\n" +
		"| `1` | all | `owner.go` | generic |\n" +
		"| `2` | all | `owner.go` | usage |\n" +
		extraOutsideRows +
		"\n" + outsideEnd + "\n\n" +
		"### `pull`: the gauntlet\n\n" + pullExit + "\n"
	verbs := "# verbs\n\n## Verb register\n\n| Verb | Owning SPEC | Exit-Code space |\n| --- | --- | --- |\n" +
		"| `pull` | SPEC-0225 P2 | " + pullCell + " |\n"

	mp := filepath.Join(root, "manual.md")
	vp := filepath.Join(root, "verbs.md")
	if err := os.WriteFile(mp, []byte(manual), 0o600); err != nil {
		t.Fatalf("write manual: %v", err)
	}
	if err := os.WriteFile(vp, []byte(verbs), 0o600); err != nil {
		t.Fatalf("write verbs: %v", err)
	}
	return fixture{root: root, manual: mp, verbs: vp}
}

func (f fixture) run(t *testing.T) report {
	t.Helper()
	mb, err := os.ReadFile(f.manual)
	if err != nil {
		t.Fatalf("read manual: %v", err)
	}
	vb, err := os.ReadFile(f.verbs)
	if err != nil {
		t.Fatalf("read verbs: %v", err)
	}
	rep, err := reconcile(f.manual, f.verbs, f.root, string(mb), string(vb))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return rep
}

func TestFixture_Clean(t *testing.T) {
	rep := newFixture(t, "", "", "", "").run(t)
	if !rep.ok() {
		t.Fatalf("a clean fixture must pass, got %+v", rep)
	}
	if rep.RegisterRows != len(exitcode.AllCodes()) {
		t.Errorf("register rows = %d, want %d", rep.RegisterRows, len(exitcode.AllCodes()))
	}
}

// A code added to the register with no manual row: the drift this gate exists
// for, in the direction "the code moved first".
func TestFixture_UndocumentedCode(t *testing.T) {
	f := newFixture(t, "", "", "", "")
	b, err := os.ReadFile(f.manual)
	if err != nil {
		t.Fatal(err)
	}
	c := exitcode.SyncIngestRejected
	row := "| `29` | `" + c.Label + "` | `" + c.Family + "` | " + c.Theme + " |"
	text := string(b)
	idx := strings.Index(text, row)
	if idx < 0 {
		t.Fatalf("fixture does not contain the row for %d/%s", c.Number, c.Label)
	}
	end := strings.Index(text[idx:], "\n")
	text = text[:idx] + text[idx+end+1:]
	if err := os.WriteFile(f.manual, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := f.run(t)
	if len(rep.Undocumented) != 1 || !strings.Contains(rep.Undocumented[0], "ingest_rejected") {
		t.Errorf("dropping a register row must be reported, got %v", rep.Undocumented)
	}
	if rep.ok() {
		t.Error("the gate must go red")
	}
}

// A manual row for a code the register does not carry: the direction "someone
// wrote a number into the docs without allocating it".
func TestFixture_InventedCode(t *testing.T) {
	extra := "| `41` | `made_up` | `nowhere` | invented theme | not a real code |\n"
	rep := newFixture(t, extra, "", "", "").run(t)
	if len(rep.Invented) != 1 || !strings.Contains(rep.Invented[0], "made_up") {
		t.Errorf("an unregistered register row must be reported, got %v", rep.Invented)
	}
}

// A number cited in a per-command Exit statement that neither table accounts
// for. This is the check that makes codes living OUTSIDE the register visible.
func TestFixture_UnaccountedNumber(t *testing.T) {
	rep := newFixture(t, "", "", "Exit: `0` ok · `1` mixed · `2` usage · `42` mystery.", "0/1/2, 42").run(t)
	if len(rep.Unaccounted) == 0 {
		t.Fatal("citing an unallocated number must be reported")
	}
	for _, c := range rep.Unaccounted {
		if c.Number != 42 {
			t.Errorf("unexpected unaccounted number %d", c.Number)
		}
	}
}

// An outside-table row whose owning file is gone: the anchor rots, the row goes
// red instead of becoming folklore.
func TestFixture_BadSource(t *testing.T) {
	extra := "| `3` | `audit` | `gone/nowhere.go` | posture verdict |\n"
	rep := newFixture(t, "", extra, "", "").run(t)
	if len(rep.BadSource) != 1 || !strings.Contains(rep.BadSource[0], "gone/nowhere.go") {
		t.Errorf("a missing source file must be reported, got %v", rep.BadSource)
	}
}

// (unimplemented) is the one non-path value a Source cell may carry.
func TestFixture_UnimplementedSourceIsAllowed(t *testing.T) {
	extra := "| `7` | `future` | `" + unimplementedToken + "` | a spec allocates it, this tree does not build it |\n"
	rep := newFixture(t, "", extra, "", "").run(t)
	if len(rep.BadSource) != 0 {
		t.Errorf("%s must be accepted, got %v", unimplementedToken, rep.BadSource)
	}
}

// The per-verb check: Befund 2.1, reduced to its mechanism. `pull` returned
// 6/10/11/12/13 while both documents claimed a bare usage space.
func TestFixture_VerbDrift(t *testing.T) {
	rep := newFixture(t, "", "", "Exit: `0` ok · `2` usage.", "0/1/2, 6, 10..13").run(t)
	if len(rep.VerbDrift) != 1 || !strings.Contains(rep.VerbDrift[0], "pull") {
		t.Fatalf("a per-verb disagreement must be reported, got %v", rep.VerbDrift)
	}
	if !strings.Contains(rep.VerbDrift[0], "0 2") || !strings.Contains(rep.VerbDrift[0], "0 1 2 6 10 11 12 13") {
		t.Errorf("the message must print both sets, got %q", rep.VerbDrift[0])
	}
}

// A section that defers ("Exit: same as `install`") states no set, so it is not
// compared: inventing one for it would be the guesswork this gate ends.
func TestFixture_DeferredExitStatementIsNotCompared(t *testing.T) {
	rep := newFixture(t, "", "", "Exit: same as `install` (see the table).", "0/1/2, 6").run(t)
	if len(rep.VerbDrift) != 0 {
		t.Errorf("a deferring Exit statement must not be compared, got %v", rep.VerbDrift)
	}
}

// ---------------------------------------------------------------------------
// Parsing units: the two notations the docs actually use.
// ---------------------------------------------------------------------------

func TestSpannedInts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"Exit: `0` ok · `2` usage.", []int{0, 2}},
		{"Exit: `0`, `1`, `2`, `10`–`13`.", []int{0, 1, 2, 10, 11, 12, 13}},
		{"Exit: `0` ok · `11` sig · `1` other · `2` usage.", []int{0, 11, 1, 2}},
		{"Exit: `0` and the flag `--bundle` and `17`.", []int{0, 17}},
	}
	for _, c := range cases {
		got := spannedInts(c.in)
		if !sameInts(got, c.want) {
			t.Errorf("spannedInts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCellInts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"0/1/2", []int{0, 1, 2}},
		{"0/1/2, 10..13", []int{10, 11, 12, 13, 0, 1, 2}},
		{"0/2 (17/22/25/28 in refusal_code)", []int{0, 2, 17, 22, 25, 28}},
		{"0", []int{0}},
	}
	for _, c := range cases {
		got := cellInts(c.in)
		if !sameSet(got, c.want) {
			t.Errorf("cellInts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A fenced code block that happens to contain the word Exit must not be read as
// an exit statement.
func TestCitedNumbers_IgnoresFencedCode(t *testing.T) {
	text := "```\nExit: `77` not a statement\n```\n\nExit: `0` real.\n"
	got := citedNumbers("m.md", text)
	if len(got) != 1 || got[0].Number != 0 {
		t.Errorf("fenced text must be ignored, got %v", got)
	}
}

func TestRenderRegisterBlock_CarriesProseForward(t *testing.T) {
	c := exitcode.VerifyBlobMissing
	existing := []regRow{{Number: c.Number, Label: c.Label, Family: c.Family, Theme: c.Theme, Meaning: "KEEP ME"}}
	out := renderRegisterBlock(exitcode.AllCodes(), existing)
	if !strings.Contains(out, "KEEP ME") {
		t.Error("-write must carry the hand-written Meaning column forward")
	}
	if strings.Count(out, "\n|") < len(exitcode.AllCodes()) {
		t.Errorf("every registered code must get a row, got:\n%s", out)
	}
}

func sameInts(a, b []int) bool {
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

func sameSet(a, b []int) bool {
	m := map[int]int{}
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		m[v]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}
