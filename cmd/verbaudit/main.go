// Command verbaudit is the dispatch-to-register consistency gate for the
// skillctl top-level verb surface (FR-0113, SPEC-0404 §7-K3, REQ-7.8 .. 7.10).
//
// It answers one release-gate question: is every DISPATCHED verb registered?
//
//   - A `case "<verb>":` in the top-level dispatch switch with no row in
//     docs/CLI-VERBS.md is UNREGISTERED and turns CI red (REQ-7.10). Allocation
//     of a verb is thereby a WRITE (add the row first), not a READ of main.go.
//   - A main-table row whose Verb appears nowhere in the dispatch is a STALE row
//     (the code moved on): a warning, not a failure.
//   - A main-table row with an empty Exit-Code cell fails the mandatory-column
//     rule (REQ-7.9): the exit-code space is what both known verb collisions
//     turned on, so it may not be left blank.
//
// The DISPATCHED surface is read mechanism-independently by AST, the same
// discipline cmd/docaudit uses for the flag surface: verbaudit parses
// cmd/skillctl/main.go, finds the `switch os.Args[1]` statement, and collects
// the string literals of its case clauses (aliases included, e.g. "--version").
// A verb the switch never names cannot be dispatched at runtime, so the set of
// case literals IS the dispatch surface.
//
// The REGISTERED surface is docs/CLI-VERBS.md. Its "Verb register" table lists
// dispatched verbs (canonical name plus any aliases, each in a backtick span in
// the Verb cell); its "Reserved (registered before implemented)" table lists
// names allocated before their case lands. A dispatched literal is registered if
// it matches a canonical name OR an alias in either table. Reserved rows with no
// dispatch are allowed (that is the point of reserving); a MAIN-table row with no
// dispatch warns.
//
// Exit codes: 0 = consistent; 1 = a violation found (the gate blocks); 2 = a
// usage/IO/parse error. Pure Go stdlib, portable (runs on the cheap CI runner).
//
// Usage:
//
//	verbaudit [-main <path>] [-register <path>] [-json]
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultMain     = "cmd/skillctl/main.go"
	defaultRegister = "docs/CLI-VERBS.md"
)

// backtickRe captures the content of one inline backtick span (never spanning a
// line break). The Verb cell of a register row leads with the canonical name in
// a span, followed by any aliases each in their own span.
var backtickRe = regexp.MustCompile("`([^`\n]+)`")

// sepCellRe matches a markdown table separator cell (---, :--, --:, :--:).
var sepCellRe = regexp.MustCompile(`^:?-{2,}:?$`)

// row is one parsed register row.
type row struct {
	Canonical string   `json:"canonical"`
	Aliases   []string `json:"aliases,omitempty"`
	Spec      string   `json:"spec"`
	ExitSpace string   `json:"exit_space"`
	Reserved  bool     `json:"reserved"`
}

// tokens returns the canonical name plus every alias: the full set of literals
// that route to this row.
func (r row) tokens() []string { return append([]string{r.Canonical}, r.Aliases...) }

type report struct {
	MainFile     string   `json:"main_file"`
	RegisterFile string   `json:"register_file"`
	Dispatched   int      `json:"dispatched"`
	MainRows     int      `json:"main_rows"`
	ReservedRows int      `json:"reserved_rows"`
	Unregistered []string `json:"unregistered"` // dispatched, no register row (FAIL)
	MissingExit  []string `json:"missing_exit"` // main row, empty Exit-Code cell (FAIL)
	Stale        []string `json:"stale"`        // main row, no dispatch (WARN)
}

func (r report) ok() bool { return len(r.Unregistered) == 0 && len(r.MissingExit) == 0 }

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	mainPath := defaultMain
	regPath := defaultRegister
	asJSON := false
	// Minimal flag parsing, no external deps: matches cmd/docaudit's idiom.
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-main":
			i++
			if i < len(argv) {
				mainPath = argv[i]
			}
		case "-register":
			i++
			if i < len(argv) {
				regPath = argv[i]
			}
		case "-json":
			asJSON = true
		case "-h", "--help":
			fmt.Fprint(os.Stdout, "usage: verbaudit [-main <path>] [-register <path>] [-json]\n")
			return 0
		default:
			fmt.Fprintf(os.Stderr, "verbaudit: unknown argument %q\n", argv[i])
			return 2
		}
	}

	dispatched, err := dispatchVerbs(mainPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verbaudit: %v\n", err)
		return 2
	}
	rows, err := registerRows(regPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verbaudit: %v\n", err)
		return 2
	}

	rep := reconcile(mainPath, regPath, dispatched, rows)

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return 2
		}
	} else {
		printHuman(rep)
	}
	if !rep.ok() {
		return 1
	}
	return 0
}

// reconcile computes the drift between the dispatch surface and the register.
func reconcile(mainPath, regPath string, dispatched map[string]bool, rows []row) report {
	rep := report{MainFile: mainPath, RegisterFile: regPath, Dispatched: len(dispatched)}

	// registered token -> is it a reserved-only token.
	registered := map[string]bool{}
	for _, r := range rows {
		if r.Reserved {
			rep.ReservedRows++
		} else {
			rep.MainRows++
		}
		for _, t := range r.tokens() {
			registered[t] = true
		}
	}

	// REQ-7.10: any dispatched verb with no register row (main OR reserved).
	for v := range dispatched {
		if !registered[v] {
			rep.Unregistered = append(rep.Unregistered, v)
		}
	}
	sort.Strings(rep.Unregistered)

	for _, r := range rows {
		if r.Reserved {
			continue
		}
		// REQ-7.9: the Exit-Code column is mandatory on every main-table row.
		if strings.TrimSpace(r.ExitSpace) == "" {
			rep.MissingExit = append(rep.MissingExit, r.Canonical)
		}
		// A main-table row none of whose tokens are dispatched is stale.
		dispatchedRow := false
		for _, t := range r.tokens() {
			if dispatched[t] {
				dispatchedRow = true
				break
			}
		}
		if !dispatchedRow {
			rep.Stale = append(rep.Stale, r.Canonical)
		}
	}
	sort.Strings(rep.MissingExit)
	sort.Strings(rep.Stale)
	return rep
}

// dispatchVerbs AST-parses main.go and returns the string literals of every case
// clause in the top-level `switch os.Args[1]` dispatch (aliases included).
func dispatchVerbs(path string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var sw *ast.SwitchStmt
	ast.Inspect(f, func(n ast.Node) bool {
		if sw != nil {
			return false
		}
		s, ok := n.(*ast.SwitchStmt)
		if ok && isOsArgsIndex(s.Tag) {
			sw = s
			return false
		}
		return true
	})
	if sw == nil {
		return nil, fmt.Errorf("%s: no `switch os.Args[1]` dispatch found", path)
	}
	out := map[string]bool{}
	for _, stmt := range sw.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue // default clause has no List
		}
		for _, e := range cc.List {
			lit, ok := e.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			if v != "" {
				out[v] = true
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: dispatch switch has no string-literal cases", path)
	}
	return out, nil
}

// isOsArgsIndex reports whether expr is the index expression `os.Args[1]`.
func isOsArgsIndex(expr ast.Expr) bool {
	idx, ok := expr.(*ast.IndexExpr)
	if !ok {
		return false
	}
	sel, ok := idx.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Args" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "os" {
		return false
	}
	lit, ok := idx.Index.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "1"
}

// registerRows parses docs/CLI-VERBS.md into the main and reserved verb rows.
// A table row is a line whose trimmed form starts with "|". The Verb cell (first
// data cell) contributes the canonical name (its first backtick span) and any
// aliases (further spans). Rows after a heading matching /reserved/i are marked
// reserved.
func registerRows(path string) ([]row, error) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- path is a trusted CLI argument (the register markdown, default docs/CLI-VERBS.md), not attacker input: same trust model as cmd/docaudit's manual read.
	if err != nil {
		return nil, fmt.Errorf("read register: %w", err)
	}
	var rows []row
	inReserved := false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			if strings.Contains(strings.ToLower(trimmed), "reserved") {
				inReserved = true
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := splitRow(trimmed)
		if len(cells) < 3 {
			continue
		}
		verbCell, specCell, exitCell := cells[0], cells[1], cells[2]
		// Skip the header row and the separator row.
		if strings.EqualFold(verbCell, "Verb") {
			continue
		}
		if isSeparatorRow(cells) {
			continue
		}
		spans := backtickRe.FindAllStringSubmatch(verbCell, -1)
		if len(spans) == 0 {
			continue // not a verb row (no backtick-quoted verb)
		}
		tokens := make([]string, 0, len(spans))
		for _, m := range spans {
			tokens = append(tokens, strings.TrimSpace(m[1]))
		}
		rows = append(rows, row{
			Canonical: tokens[0],
			Aliases:   tokens[1:],
			Spec:      specCell,
			ExitSpace: exitCell,
			Reserved:  inReserved,
		})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: no verb rows parsed (is the register table present?)", path)
	}
	return rows, nil
}

// splitRow splits a markdown table row into its trimmed cells, dropping the
// empty fields produced by the leading and trailing pipe.
func splitRow(line string) []string {
	parts := strings.Split(line, "|")
	var cells []string
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	// Drop a leading and/or trailing empty cell from the border pipes.
	if len(cells) > 0 && cells[0] == "" {
		cells = cells[1:]
	}
	if len(cells) > 0 && cells[len(cells)-1] == "" {
		cells = cells[:len(cells)-1]
	}
	return cells
}

// isSeparatorRow reports whether every cell is a markdown separator (---).
func isSeparatorRow(cells []string) bool {
	for _, c := range cells {
		if !sepCellRe.MatchString(c) {
			return false
		}
	}
	return len(cells) > 0
}

func printHuman(r report) {
	const (
		green  = "\033[0;32m"
		red    = "\033[0;31m"
		yellow = "\033[0;33m"
		bold   = "\033[1m"
		dim    = "\033[2m"
		nc     = "\033[0m"
	)
	fmt.Println("=== skillctl verb register consistency (verbaudit) ===")
	fmt.Printf("\n%sdispatch%s %s(%d verbs in %s)%s vs %sregister%s %s(%d main + %d reserved rows in %s)%s\n",
		bold, nc, dim, r.Dispatched, r.MainFile, nc, bold, nc, dim, r.MainRows, r.ReservedRows, r.RegisterFile, nc)

	if len(r.Unregistered) > 0 {
		fmt.Printf("  %s✗ UNREGISTERED%s (dispatched in main.go, no row in the register: add a row first):\n", red, nc)
		for _, v := range r.Unregistered {
			fmt.Printf("      %s\n", v)
		}
	}
	if len(r.MissingExit) > 0 {
		fmt.Printf("  %s✗ MISSING EXIT-CODE%s (main-table row with an empty Exit-Code cell: mandatory per REQ-7.9):\n", red, nc)
		for _, v := range r.MissingExit {
			fmt.Printf("      %s\n", v)
		}
	}
	if len(r.Stale) > 0 {
		fmt.Printf("  %s! STALE ROW%s (registered in the main table, not dispatched: the code may have moved on):\n", yellow, nc)
		for _, v := range r.Stale {
			fmt.Printf("      %s\n", v)
		}
	}

	fmt.Println("\n─────────────────────────────")
	if r.ok() {
		fmt.Printf("%sPASS%s: every dispatched verb is registered and every main row carries an exit-code space.\n", green, nc)
	} else {
		fmt.Printf("%sFAIL%s: the dispatch and the register disagree (release gate blocks). See docs/CLI-VERBS.md.\n", red, nc)
	}
}
