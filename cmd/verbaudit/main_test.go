package main

import (
	"os"
	"path/filepath"
	"testing"
)

// sampleMain is a minimal main.go carrying a top-level `switch os.Args[1]`
// dispatch with a canonical verb, an aliased verb, and a default clause. A
// second, unrelated switch (over a different tag) is present to prove the AST
// walk locks onto the os.Args[1] one and ignores the decoy.
const sampleMain = `package main

import (
	"fmt"
	"os"
)

func main() {
	switch flavour := "x"; flavour {
	case "decoy":
		fmt.Println("not a verb")
	}
	switch os.Args[1] {
	case "login":
		os.Exit(0)
	case "version", "--version", "-v":
		fmt.Println("dev")
	case "audit":
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
`

// sampleRegister is a well-formed register: a main table (login/version/audit)
// plus a reserved section (capability). It deliberately does NOT register the
// prose bullets that also contain backticks, to prove only pipe-rows are read.
const sampleRegister = "# skillctl CLI verb register\n" +
	"\n" +
	"- **Verb** `not-a-row` should be ignored (not a table row).\n" +
	"\n" +
	"## Verb register\n" +
	"\n" +
	"| Verb | Owning SPEC | Exit-Code space |\n" +
	"| --- | --- | --- |\n" +
	"| `login` | FR-0043 | 0/1/2 |\n" +
	"| `version` (`--version`, `-v`) | built-in | 0 |\n" +
	"| `audit` | SPEC-0189 §14 | 0/2/3 |\n" +
	"\n" +
	"## Reserved (registered before implemented)\n" +
	"\n" +
	"| Verb | Owning SPEC | Exit-Code space |\n" +
	"| --- | --- | --- |\n" +
	"| `capability` | SPEC-0378 | 0/1 |\n"

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestDispatchVerbs_ExtractsCasesIncludingAliases(t *testing.T) {
	p := writeTemp(t, "main.go", sampleMain)
	got, err := dispatchVerbs(p)
	if err != nil {
		t.Fatalf("dispatchVerbs: %v", err)
	}
	want := []string{"login", "version", "--version", "-v", "audit"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("dispatch missing %q; got %v", w, got)
		}
	}
	if got["decoy"] {
		t.Error("decoy case from the non-os.Args switch leaked into the dispatch set")
	}
	if len(got) != len(want) {
		t.Errorf("dispatch size = %d, want %d (%v)", len(got), len(want), got)
	}
}

func TestRegisterRows_MainAndReserved(t *testing.T) {
	p := writeTemp(t, "CLI-VERBS.md", sampleRegister)
	rows, err := registerRows(p)
	if err != nil {
		t.Fatalf("registerRows: %v", err)
	}
	byName := map[string]row{}
	for _, r := range rows {
		byName[r.Canonical] = r
	}
	if _, ok := byName["not-a-row"]; ok {
		t.Error("a prose backtick span was parsed as a verb row")
	}
	ver, ok := byName["version"]
	if !ok {
		t.Fatal("version row not parsed")
	}
	if len(ver.Aliases) != 2 || ver.Aliases[0] != "--version" || ver.Aliases[1] != "-v" {
		t.Errorf("version aliases = %v, want [--version -v]", ver.Aliases)
	}
	if ver.ExitSpace != "0" {
		t.Errorf("version exit space = %q, want 0", ver.ExitSpace)
	}
	cap, ok := byName["capability"]
	if !ok {
		t.Fatal("capability row not parsed")
	}
	if !cap.Reserved {
		t.Error("capability should be a reserved row")
	}
	if ver.Reserved {
		t.Error("version should NOT be a reserved row")
	}
}

func TestReconcile_CleanTree(t *testing.T) {
	mp := writeTemp(t, "main.go", sampleMain)
	rp := writeTemp(t, "CLI-VERBS.md", sampleRegister)
	disp, err := dispatchVerbs(mp)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := registerRows(rp)
	if err != nil {
		t.Fatal(err)
	}
	rep := reconcile(mp, rp, disp, rows)
	if !rep.ok() {
		t.Errorf("expected clean, got unregistered=%v missingExit=%v", rep.Unregistered, rep.MissingExit)
	}
	if len(rep.Stale) != 0 {
		t.Errorf("expected no stale rows, got %v", rep.Stale)
	}
	if rep.ReservedRows != 1 {
		t.Errorf("reserved rows = %d, want 1", rep.ReservedRows)
	}
}

func TestReconcile_UnregisteredDispatchFails(t *testing.T) {
	// main.go dispatches an extra verb the register does not carry.
	extra := sampleMain[:len(sampleMain)-len("	default:\n\t\tos.Exit(2)\n\t}\n}\n")] +
		"	case \"zzztest\":\n\t\tos.Exit(0)\n" +
		"	default:\n\t\tos.Exit(2)\n\t}\n}\n"
	mp := writeTemp(t, "main.go", extra)
	rp := writeTemp(t, "CLI-VERBS.md", sampleRegister)
	disp, err := dispatchVerbs(mp)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := registerRows(rp)
	if err != nil {
		t.Fatal(err)
	}
	rep := reconcile(mp, rp, disp, rows)
	if rep.ok() {
		t.Fatal("expected FAIL for an unregistered dispatched verb")
	}
	found := false
	for _, u := range rep.Unregistered {
		if u == "zzztest" {
			found = true
		}
	}
	if !found {
		t.Errorf("unregistered set %v does not name zzztest", rep.Unregistered)
	}
}

func TestReconcile_MissingExitFails(t *testing.T) {
	reg := "## Verb register\n\n" +
		"| Verb | Owning SPEC | Exit-Code space |\n" +
		"| --- | --- | --- |\n" +
		"| `login` | FR-0043 |  |\n"
	mp := writeTemp(t, "main.go", sampleMain)
	rp := writeTemp(t, "CLI-VERBS.md", reg)
	disp, err := dispatchVerbs(mp)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := registerRows(rp)
	if err != nil {
		t.Fatal(err)
	}
	rep := reconcile(mp, rp, disp, rows)
	if rep.ok() {
		t.Fatal("expected FAIL for a main-table row with an empty Exit-Code cell")
	}
	if len(rep.MissingExit) != 1 || rep.MissingExit[0] != "login" {
		t.Errorf("missingExit = %v, want [login]", rep.MissingExit)
	}
}

func TestReconcile_StaleRowWarnsButPasses(t *testing.T) {
	// A registered main-table verb the dispatch does not carry: warn, not fail.
	reg := "## Verb register\n\n" +
		"| Verb | Owning SPEC | Exit-Code space |\n" +
		"| --- | --- | --- |\n" +
		"| `login` | FR-0043 | 0/1/2 |\n" +
		"| `version` (`--version`, `-v`) | built-in | 0 |\n" +
		"| `audit` | SPEC-0189 §14 | 0/2/3 |\n" +
		"| `ghostverb` | SPEC-9999 | 0/1 |\n"
	mp := writeTemp(t, "main.go", sampleMain)
	rp := writeTemp(t, "CLI-VERBS.md", reg)
	disp, err := dispatchVerbs(mp)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := registerRows(rp)
	if err != nil {
		t.Fatal(err)
	}
	rep := reconcile(mp, rp, disp, rows)
	if !rep.ok() {
		t.Errorf("a stale row must NOT fail the gate; got unregistered=%v missingExit=%v", rep.Unregistered, rep.MissingExit)
	}
	if len(rep.Stale) != 1 || rep.Stale[0] != "ghostverb" {
		t.Errorf("stale = %v, want [ghostverb]", rep.Stale)
	}
}

// TestRun_RealTree pins the checker green against the actual repository tree, so
// this test regresses if a future verb lands in main.go without a register row.
func TestRun_RealTree(t *testing.T) {
	code := run([]string{"-main", "../skillctl/main.go", "-register", "../../docs/CLI-VERBS.md"})
	if code != 0 {
		t.Fatalf("verbaudit on the real tree returned %d, want 0 (register out of sync with dispatch)", code)
	}
}
