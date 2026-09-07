// Command exitaudit is the register-to-manual consistency gate for the skillctl
// exit-code surface. It is the "Phase 2" that pkg/skillctl/exitcode/registry.go
// has been promising in its package comment since FR-0023: the manual's
// exit-code table is no longer hand-maintained prose that happens to agree with
// the code, it is checked against exitcode.AllCodes() on every run of
// scripts/check-docs.sh, and drift turns the gate red.
//
// The drift class this kills, measured 2026-09-07 before the gate existed:
// `pull` mapped five gates onto 12/10/11/13/6 while the manual said "0 ok, 2
// usage" and docs/CLI-VERBS.md said "0/1/2"; `verify-sig` returned 10 for an
// altered bundle and the manual named only 0/11/1/2; verify-hook's refusal_code
// space was 17/22/25/28 in code, 17/22 in the manual and 25/26/28 in CLI-VERBS
// (26 belongs to `enforce`). Every one of those is a number an operator or a
// script branches on, and every one was wrong in at least one place.
//
// WHAT IS CHECKED
//
//  1. REGISTER PARITY (fail). The manual carries a delimited register table
//     (between the exitaudit:register markers). Its (Code, Label, Surface,
//     Theme) tuples must equal exitcode.AllCodes() exactly, in both
//     directions. The Meaning column is free prose the gate never touches.
//  2. OUTSIDE-THE-REGISTER CENSUS (fail). Not every exit number lives in the
//     register: 0/1/2 are the shared base space, `audit` exits 3 from
//     pkg/skillctl/audit, the skillgate 30-39 band is a library constant band.
//     Those must be listed in the manual's second delimited table, each row
//     naming the source file that owns the number. A number cited ANYWHERE in
//     the manual's per-command Exit lines or in a CLI-VERBS exit-code cell
//     that is in neither table fails the gate: to document a number you must
//     first say where it comes from. That is what makes the codes outside the
//     register visible, which is the whole point (they are how bundle_revoked
//     briefly claimed a 20 that verify.ExitSelfAttested had been shipping for
//     weeks).
//  3. SOURCE ANCHORING (fail). Every outside-table row's Source cell must be a
//     repo-relative file that EXISTS, or the literal token (unimplemented) for
//     a number a specification assigns to a surface this tree does not build.
//     A moved or deleted owner turns the row red instead of leaving folklore.
//  4. PER-VERB AGREEMENT (fail). For a verb whose manual section states an
//     Exit line, that line and the verb register's Exit-Code cell must name the
//     same numbers.
//  5. THE PULL GATE, READ AS CODE (fail). cmd/skillctl/pull_cmds.go's gateExit
//     is AST-parsed, its exitcode.<Name>.Number selectors resolved through
//     pkg/skillctl/exitcode/registry.go, and the resulting number set compared
//     with the `pull` cell. This is the one check that reads Go rather than
//     markdown, and it exists because a symbol swapped inside gateExit still
//     compiles, still passes checks 1 to 4, and still moves the number a
//     caller's script branches on.
//
// WHAT IS NOT CHECKED, said plainly because a gate that hides its edges is
// worse than no gate:
//
//   - Only `pull` is read as code. Every other verb's cell is compared against
//     the MANUAL, never against its handler, so a raw `return 13` added to
//     cmd/skillctl/runbook_cmds.go is invisible here (that one was found by
//     hand, 2026-09-07, after this tool shipped green). Widening check 5 to the
//     other verbs means resolving cross-file helpers (verify.ExitCode), raw
//     literals and os.Exit call sites; it is worth doing and it is not done.
//   - Only per-command Exit statements and CLI-VERBS Exit-Code cells are
//     scanned for numbers. A number in ordinary prose, or in the verify-hook
//     refusal_code table, is NOT scanned: measured 2026-09-07, an invented 77
//     in prose and an invented 88 in that table both left the gate green.
//   - A verb whose manual section states no Exit line falls out of check 4
//     entirely. That is now COUNTED and PRINTED rather than silent, because a
//     wrong `pin` cell (0/1/2 for a verb that exits 3) survived this gate's
//     own first release exactly that way.
//   - Check 4 proves the two DOCUMENTS agree, never that either matches the
//     handler. Two wrong-but-identical statements are green: `audit` claimed
//     0/2/3 in both while its handler also returns 1, and `install`/`verify`
//     claimed 23 in both while the only function that raises
//     ErrLogInclusionMissing has no caller outside its own test file. Both were
//     corrected by hand on 2026-09-07; nothing here would have caught either.
//
// Exit codes: 0 = consistent; 1 = a violation found (the gate blocks); 2 = a
// usage/IO/parse error. Pure Go stdlib, portable, no network.
//
// Usage:
//
//	exitaudit [-manual <path>] [-verbs <path>] [-root <dir>] [-json]
//	exitaudit -scaffold           # print the register table rows from AllCodes()
//	exitaudit -write              # rewrite the manual's register block in place
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
)

const (
	defaultManual = "docs/manual-skillctl.md"
	defaultVerbs  = "docs/CLI-VERBS.md"

	registerBegin = "<!-- exitaudit:register:begin -->"
	registerEnd   = "<!-- exitaudit:register:end -->"
	outsideBegin  = "<!-- exitaudit:outside:begin -->"
	outsideEnd    = "<!-- exitaudit:outside:end -->"

	// unimplementedToken is the one non-path value the Source cell of an
	// outside-table row may carry: a number a specification allocates to a
	// surface that this tree does not build (SPEC-0201's import-public).
	unimplementedToken = "(unimplemented)"

	// The two sources of the SYMBOLIC check (check 5). Kept narrow on purpose:
	// see the WHAT IS NOT CHECKED note in the package comment.
	pullGateSource = "cmd/skillctl/pull_cmds.go"
	exitcodeSource = "pkg/skillctl/exitcode/registry.go"
	pullGateFunc   = "gateExit"
	pullVerb       = "pull"
)

// backtickRe captures the content of one inline backtick span (never spanning a
// line break), the same convention cmd/verbaudit reads verb cells with.
var backtickRe = regexp.MustCompile("`([^`\n]+)`")

// sepCellRe matches a markdown table separator cell (---, :--, --:, :--:).
var sepCellRe = regexp.MustCompile(`^:?-{2,}:?$`)

// intRe matches a bare integer, used on CLI-VERBS exit-code cells.
var intRe = regexp.MustCompile(`\d+`)

// rangeRe matches an inclusive numeric range as CLI-VERBS writes it (10..17).
var rangeRe = regexp.MustCompile(`(\d+)\s*\.\.\s*(\d+)`)

// regRow is one row of the manual's generated register table.
type regRow struct {
	Number int    `json:"number"`
	Label  string `json:"label"`
	Family string `json:"family"`
	Theme  string `json:"theme"`
	// Meaning is the human column. The gate never compares it; -scaffold
	// carries it forward so regenerating the table costs no prose.
	Meaning string `json:"meaning,omitempty"`
}

// key is the tuple compared against exitcode.AllCodes().
func (r regRow) key() string {
	return fmt.Sprintf("%d|%s|%s|%s", r.Number, r.Label, r.Family, r.Theme)
}

func (r regRow) String() string {
	return fmt.Sprintf("exit %d %s/%s (theme %q)", r.Number, r.Family, r.Label, r.Theme)
}

// outRow is one row of the manual's outside-the-register table.
type outRow struct {
	Number  int    `json:"number"`
	Surface string `json:"surface"`
	Source  string `json:"source"`
	Reason  string `json:"reason"`
}

// citation is one place a number is documented outside the two tables.
type citation struct {
	Number int    `json:"number"`
	Where  string `json:"where"`
}

type report struct {
	ManualFile   string     `json:"manual_file"`
	VerbsFile    string     `json:"verbs_file"`
	Registered   int        `json:"registered"`
	RegisterRows int        `json:"register_rows"`
	OutsideRows  int        `json:"outside_rows"`
	Citations    int        `json:"citations"`
	Undocumented []string   `json:"undocumented"`  // in AllCodes(), not in the manual (FAIL)
	Invented     []string   `json:"invented"`      // in the manual register table, not in AllCodes() (FAIL)
	Unaccounted  []citation `json:"unaccounted"`   // cited number in neither table (FAIL)
	BadSource    []string   `json:"bad_source"`    // outside row whose Source does not exist (FAIL)
	DuplicateOut []string   `json:"duplicate_out"` // two outside rows for the same number+surface (FAIL)
	VerbDrift    []string   `json:"verb_drift"`    // manual and verb register disagree per verb (FAIL)
	PullDrift    []string   `json:"pull_drift"`    // the pull gate's SYMBOLS vs the pull cell (FAIL)

	// NotChecked is the census of verb rows the per-verb comparison never
	// reaches, because their manual section states no Exit line (or has no
	// section at all). Informational, never a failure: it is printed so the
	// gate's reach is a number a reader can see rather than silence. A wrong
	// `pin` cell survived this gate's first release precisely because nothing
	// said out loud that `pin` was never compared.
	NotChecked []string `json:"not_checked"`
	// VerbRows is how many rows the verb register carries, so NotChecked can be
	// printed as a fraction of the whole rather than a bare count.
	VerbRows int `json:"verb_rows"`
	// PullSymbols is what the pull gate can actually return, resolved from
	// source. PullSkipped says why the symbolic check did not run.
	PullSymbols []int  `json:"pull_symbols,omitempty"`
	PullSkipped string `json:"pull_skipped,omitempty"`
}

func (r report) ok() bool {
	return len(r.Undocumented) == 0 && len(r.Invented) == 0 &&
		len(r.Unaccounted) == 0 && len(r.BadSource) == 0 &&
		len(r.DuplicateOut) == 0 && len(r.VerbDrift) == 0 &&
		len(r.PullDrift) == 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(argv []string, stdout, stderr io.Writer) int {
	manualPath := defaultManual
	verbsPath := defaultVerbs
	root := "."
	asJSON, scaffold, write := false, false, false

	// Minimal flag parsing, no external deps: matches cmd/docaudit and
	// cmd/verbaudit.
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-manual":
			i++
			if i < len(argv) {
				manualPath = argv[i]
			}
		case "-verbs":
			i++
			if i < len(argv) {
				verbsPath = argv[i]
			}
		case "-root":
			i++
			if i < len(argv) {
				root = argv[i]
			}
		case "-json":
			asJSON = true
		case "-scaffold":
			scaffold = true
		case "-write":
			write = true
		case "-h", "--help":
			fmt.Fprint(stdout, "usage: exitaudit [-manual <path>] [-verbs <path>] [-root <dir>] [-json|-scaffold|-write]\n")
			return 0
		default:
			fmt.Fprintf(stderr, "exitaudit: unknown argument %q\n", argv[i])
			return 2
		}
	}

	manual, err := os.ReadFile(manualPath) // #nosec G304 G703 -- a trusted CLI argument (the manual markdown), same trust model as cmd/verbaudit's register read.
	if err != nil {
		fmt.Fprintf(stderr, "exitaudit: read manual: %v\n", err)
		return 2
	}
	manualText := string(manual)

	if scaffold || write {
		existing, _ := parseRegisterTable(manualText) // best effort: carry prose forward
		block := renderRegisterBlock(exitcode.AllCodes(), existing)
		if scaffold {
			fmt.Fprint(stdout, block)
			return 0
		}
		updated, err := replaceBlock(manualText, registerBegin, registerEnd, block)
		if err != nil {
			fmt.Fprintf(stderr, "exitaudit: %v\n", err)
			return 2
		}
		if err := os.WriteFile(manualPath, []byte(updated), 0o644); err != nil { // #nosec G306 G703 -- documentation, world-readable by design; the path is the same trusted CLI argument.
			fmt.Fprintf(stderr, "exitaudit: write manual: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "exitaudit: rewrote the register block in %s from exitcode.AllCodes()\n", manualPath)
		return 0
	}

	verbs, err := os.ReadFile(verbsPath) // #nosec G304 G703 -- see above.
	if err != nil {
		fmt.Fprintf(stderr, "exitaudit: read verb register: %v\n", err)
		return 2
	}

	rep, err := reconcile(manualPath, verbsPath, root, manualText, string(verbs))
	if err != nil {
		fmt.Fprintf(stderr, "exitaudit: %v\n", err)
		return 2
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return 2
		}
	} else {
		printHuman(stdout, rep)
	}
	if !rep.ok() {
		return 1
	}
	return 0
}

// reconcile computes the drift between exitcode.AllCodes() and the docs.
func reconcile(manualPath, verbsPath, root, manualText, verbsText string) (report, error) {
	regRows, err := parseRegisterTable(manualText)
	if err != nil {
		return report{}, fmt.Errorf("%s: %w", manualPath, err)
	}
	outRows, err := parseOutsideTable(manualText)
	if err != nil {
		return report{}, fmt.Errorf("%s: %w", manualPath, err)
	}

	all := exitcode.AllCodes()
	rep := report{
		ManualFile:   manualPath,
		VerbsFile:    verbsPath,
		Registered:   len(all),
		RegisterRows: len(regRows),
		OutsideRows:  len(outRows),
	}

	// 1. Register parity, both directions.
	documented := map[string]bool{}
	for _, r := range regRows {
		documented[r.key()] = true
	}
	registered := map[string]bool{}
	for _, c := range all {
		row := regRow{Number: c.Number, Label: c.Label, Family: c.Family, Theme: c.Theme}
		registered[row.key()] = true
		if !documented[row.key()] {
			rep.Undocumented = append(rep.Undocumented, row.String())
		}
	}
	for _, r := range regRows {
		if !registered[r.key()] {
			rep.Invented = append(rep.Invented, r.String())
		}
	}
	sort.Strings(rep.Undocumented)
	sort.Strings(rep.Invented)

	// 2 + 3. The outside table: anchored to a real source, no duplicate rows.
	seenOut := map[string]bool{}
	accounted := map[int]bool{}
	for _, c := range all {
		accounted[c.Number] = true
	}
	for _, o := range outRows {
		accounted[o.Number] = true
		k := fmt.Sprintf("%d|%s", o.Number, o.Surface)
		if seenOut[k] {
			rep.DuplicateOut = append(rep.DuplicateOut, fmt.Sprintf("exit %d on surface %q listed twice", o.Number, o.Surface))
			continue
		}
		seenOut[k] = true
		if o.Source == unimplementedToken {
			continue
		}
		// #nosec G703 -- o.Source is a repo-relative path READ OUT OF THE MANUAL that
		// this gate is checking, joined under the -root the operator passed. The call
		// only stats: it opens nothing, and the result decides one boolean (does the
		// named owner file still exist).
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(o.Source))); err != nil {
			rep.BadSource = append(rep.BadSource, fmt.Sprintf("exit %d (%s): source %q does not exist; name the file that owns the number, or %s",
				o.Number, o.Surface, o.Source, unimplementedToken))
		}
	}
	sort.Strings(rep.BadSource)
	sort.Strings(rep.DuplicateOut)

	// 4. Every cited number must be accounted for by one of the two tables.
	cites := citedNumbers(manualPath, manualText)
	cites = append(cites, verbCitedNumbers(verbsPath, verbsText)...)
	rep.Citations = len(cites)
	seenCite := map[string]bool{}
	for _, c := range cites {
		if accounted[c.Number] {
			continue
		}
		k := fmt.Sprintf("%d|%s", c.Number, c.Where)
		if seenCite[k] {
			continue
		}
		seenCite[k] = true
		rep.Unaccounted = append(rep.Unaccounted, c)
	}
	// 5. Per-verb agreement between the manual and the verb register, plus the
	// census of the verbs that comparison never reaches.
	rep.VerbDrift, rep.NotChecked, rep.VerbRows = verbDrift(manualText, verbsText)

	// 5b. The one SYMBOLIC check: the pull gate's own exit expressions against
	// the pull cell. Everything above reads documents only.
	rep.PullSymbols, rep.PullDrift, rep.PullSkipped = pullSymbolDrift(root, verbsText)

	sort.Slice(rep.Unaccounted, func(i, j int) bool {
		if rep.Unaccounted[i].Number != rep.Unaccounted[j].Number {
			return rep.Unaccounted[i].Number < rep.Unaccounted[j].Number
		}
		return rep.Unaccounted[i].Where < rep.Unaccounted[j].Where
	})
	return rep, nil
}

// parseRegisterTable reads the delimited register block into rows.
func parseRegisterTable(text string) ([]regRow, error) {
	body, err := blockBody(text, registerBegin, registerEnd)
	if err != nil {
		return nil, err
	}
	var rows []regRow
	for _, cells := range tableRows(body) {
		if len(cells) < 4 {
			continue
		}
		n, ok := firstInt(cells[0])
		if !ok {
			continue
		}
		r := regRow{Number: n, Label: unspan(cells[1]), Family: unspan(cells[2]), Theme: unspan(cells[3])}
		if len(cells) >= 5 {
			r.Meaning = strings.TrimSpace(cells[4])
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the exitaudit:register block holds no parsable rows")
	}
	return rows, nil
}

// parseOutsideTable reads the delimited outside-the-register block into rows.
func parseOutsideTable(text string) ([]outRow, error) {
	body, err := blockBody(text, outsideBegin, outsideEnd)
	if err != nil {
		return nil, err
	}
	var rows []outRow
	for _, cells := range tableRows(body) {
		if len(cells) < 4 {
			continue
		}
		n, ok := firstInt(cells[0])
		if !ok {
			continue
		}
		rows = append(rows, outRow{
			Number:  n,
			Surface: unspan(cells[1]),
			Source:  unspan(cells[2]),
			Reason:  strings.TrimSpace(cells[3]),
		})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the exitaudit:outside block holds no parsable rows")
	}
	return rows, nil
}

// blockBody returns the text strictly between the two markers.
func blockBody(text, begin, end string) (string, error) {
	i := strings.Index(text, begin)
	if i < 0 {
		return "", fmt.Errorf("marker %s not found", begin)
	}
	j := strings.Index(text[i:], end)
	if j < 0 {
		return "", fmt.Errorf("marker %s not found after %s", end, begin)
	}
	return text[i+len(begin) : i+j], nil
}

// replaceBlock swaps the content between the markers (markers kept).
func replaceBlock(text, begin, end, body string) (string, error) {
	i := strings.Index(text, begin)
	if i < 0 {
		return "", fmt.Errorf("marker %s not found in the manual: add the block first (exitaudit -scaffold prints it)", begin)
	}
	j := strings.Index(text[i:], end)
	if j < 0 {
		return "", fmt.Errorf("marker %s not found after %s", end, begin)
	}
	return text[:i+len(begin)] + body + text[i+j:], nil
}

// tableRows splits a markdown fragment into its table rows' trimmed cells,
// skipping the header and separator rows.
func tableRows(body string) [][]string {
	var out [][]string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := splitRow(trimmed)
		if len(cells) == 0 || isSeparatorRow(cells) {
			continue
		}
		out = append(out, cells)
	}
	return out
}

// splitRow splits a markdown table row into trimmed cells, dropping the empty
// fields the leading and trailing pipes produce.
func splitRow(line string) []string {
	parts := strings.Split(line, "|")
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	if len(cells) > 0 && cells[0] == "" {
		cells = cells[1:]
	}
	if len(cells) > 0 && cells[len(cells)-1] == "" {
		cells = cells[:len(cells)-1]
	}
	return cells
}

func isSeparatorRow(cells []string) bool {
	for _, c := range cells {
		if !sepCellRe.MatchString(c) {
			return false
		}
	}
	return len(cells) > 0
}

// unspan strips one surrounding backtick span, so `pull` and pull both read as
// pull. Cells are written with the span; the gate does not depend on it.
func unspan(cell string) string {
	if m := backtickRe.FindStringSubmatch(cell); m != nil {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(cell)
}

// firstInt reads the first integer out of a cell (`17` or 17).
func firstInt(cell string) (int, bool) {
	m := intRe.FindString(cell)
	if m == "" {
		return 0, false
	}
	n, err := strconv.Atoi(m)
	if err != nil {
		return 0, false
	}
	return n, true
}

// citedNumbers collects every exit number the manual states OUTSIDE the two
// delimited tables: the per-command "Exit:" lines, which are what a reader of a
// single command section actually believes. A statement continues until the
// first blank line, so a wrapped Exit sentence is read whole.
func citedNumbers(path, text string) []citation {
	var out []citation
	lines := strings.Split(text, "\n")
	inBlock := false
	inFence := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.Contains(line, registerBegin), strings.Contains(line, outsideBegin):
			inBlock = true
			continue
		case strings.Contains(line, registerEnd), strings.Contains(line, outsideEnd):
			inBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inBlock || inFence {
			continue
		}
		if !isExitStatement(trimmed) {
			continue
		}
		stmt := trimmed
		for j := i + 1; j < len(lines); j++ {
			next := strings.TrimSpace(lines[j])
			if next == "" {
				break
			}
			stmt += " " + next
			i = j
		}
		where := fmt.Sprintf("%s:%d", path, i+1)
		for _, n := range spannedInts(stmt) {
			out = append(out, citation{Number: n, Where: where})
		}
	}
	return out
}

// isExitStatement reports whether a line opens a per-command exit statement.
// The manual writes them as "Exit: …", "Exit codes: …" or "Exit (`verify`): …".
func isExitStatement(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "Exit") {
		return false
	}
	rest := strings.TrimPrefix(trimmed, "Exit")
	return strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, " codes:") || strings.HasPrefix(rest, " (")
}

// spannedInts returns every integer written in a backtick span, expanding an
// inclusive range written as `10`-`16` (any dash between two spans).
func spannedInts(s string) []int {
	spans := backtickRe.FindAllStringSubmatchIndex(s, -1)
	var nums []int
	type span struct {
		n        int
		lo, hi   int
		isNumber bool
	}
	var found []span
	for _, m := range spans {
		content := s[m[2]:m[3]]
		n, err := strconv.Atoi(strings.TrimSpace(content))
		found = append(found, span{n: n, lo: m[0], hi: m[1], isNumber: err == nil})
	}
	for i, f := range found {
		if !f.isNumber {
			continue
		}
		nums = append(nums, f.n)
		// A range: two numeric spans separated only by a dash-ish rune.
		if i+1 < len(found) && found[i+1].isNumber {
			between := strings.TrimSpace(s[f.hi:found[i+1].lo])
			if isDash(between) && found[i+1].n > f.n && found[i+1].n-f.n < 64 {
				for v := f.n + 1; v < found[i+1].n; v++ {
					nums = append(nums, v)
				}
			}
		}
	}
	return nums
}

// isDash reports whether the text between two numbers makes them a range. The
// manual uses an en dash; a hyphen and the two-dot form are accepted too.
func isDash(s string) bool {
	switch s {
	case "-", "\u2013", "..", "to":
		return true
	}
	return false
}

// verbCitedNumbers collects the numbers in the Exit-Code cells of the verb
// register, expanding its "10..17" ranges. Every one is a promise to a script.
func verbCitedNumbers(path, text string) []citation {
	var out []citation
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := splitRow(trimmed)
		if len(cells) < 3 || isSeparatorRow(cells) {
			continue
		}
		if strings.EqualFold(cells[0], "Verb") {
			continue
		}
		if backtickRe.FindString(cells[0]) == "" {
			continue // not a verb row
		}
		where := fmt.Sprintf("%s:%d (verb %s)", path, i+1, unspan(cells[0]))
		for _, n := range cellInts(cells[2]) {
			out = append(out, citation{Number: n, Where: where})
		}
	}
	return out
}

// cellInts reads an exit-code cell such as "0/1/2, 10..17" or
// "0/2 (25/26/28 in refusal_code)" into its numbers, ranges expanded.
func cellInts(cell string) []int {
	var nums []int
	rest := cell
	for _, m := range rangeRe.FindAllStringSubmatch(cell, -1) {
		lo, err1 := strconv.Atoi(m[1])
		hi, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil || hi < lo || hi-lo > 64 {
			continue
		}
		for v := lo; v <= hi; v++ {
			nums = append(nums, v)
		}
		rest = strings.Replace(rest, m[0], " ", 1)
	}
	for _, m := range intRe.FindAllString(rest, -1) {
		if n, err := strconv.Atoi(m); err == nil {
			nums = append(nums, n)
		}
	}
	return nums
}

// renderRegisterBlock renders the register table from AllCodes(), carrying the
// Meaning prose of any row that already exists forward so regenerating costs no
// writing. Sorted by Number, then Family, then Label: stable output.
func renderRegisterBlock(codes []exitcode.Code, existing []regRow) string {
	prose := map[string]string{}
	for _, r := range existing {
		prose[r.key()] = r.Meaning
	}
	rows := make([]regRow, 0, len(codes))
	for _, c := range codes {
		r := regRow{Number: c.Number, Label: c.Label, Family: c.Family, Theme: c.Theme}
		r.Meaning = prose[r.key()]
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Number != rows[j].Number {
			return rows[i].Number < rows[j].Number
		}
		if rows[i].Family != rows[j].Family {
			return rows[i].Family < rows[j].Family
		}
		return rows[i].Label < rows[j].Label
	})

	var b strings.Builder
	b.WriteString("\n\n| Code | Label | Surface | Theme | Meaning |\n")
	b.WriteString("|-----:|-------|---------|-------|---------|\n")
	for _, r := range rows {
		meaning := r.Meaning
		if meaning == "" {
			meaning = "TODO: say what an operator should DO about it."
		}
		fmt.Fprintf(&b, "| `%d` | `%s` | `%s` | %s | %s |\n", r.Number, r.Label, r.Family, r.Theme, meaning)
	}
	b.WriteString("\n")
	return b.String()
}

// verbDrift compares, per verb, the manual's own "Exit:" statement against the
// Exit-Code cell of the verb register. Only verbs whose manual section names at
// least one number are compared: a section that defers ("Exit: same as
// `install`") states no set, and inventing one for it would be the very
// guesswork this gate exists to end.
func verbDrift(manualText, verbsText string) (drift []string, notChecked []string, verbRows int) {
	want := map[string]map[int]bool{}
	for _, line := range strings.Split(verbsText, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := splitRow(trimmed)
		if len(cells) < 3 || isSeparatorRow(cells) || strings.EqualFold(cells[0], "Verb") {
			continue
		}
		m := backtickRe.FindStringSubmatch(cells[0])
		if m == nil {
			continue
		}
		set := map[int]bool{}
		for _, n := range cellInts(cells[2]) {
			set[n] = true
		}
		want[strings.TrimSpace(m[1])] = set
	}

	got := map[string]map[int]bool{}
	lines := strings.Split(manualText, "\n")
	cur := ""
	inFence, inBlock := false, false
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		switch {
		case strings.Contains(trimmed, registerBegin), strings.Contains(trimmed, outsideBegin):
			inBlock = true
			continue
		case strings.Contains(trimmed, registerEnd), strings.Contains(trimmed, outsideEnd):
			inBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inFence || inBlock {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			cur = ""
			if m := backtickRe.FindStringSubmatch(trimmed); m != nil {
				name := strings.Fields(strings.TrimSpace(m[1]))[0]
				if _, ok := want[name]; ok {
					cur = name
				}
			}
			continue
		}
		if cur == "" || !isExitStatement(trimmed) {
			continue
		}
		stmt := trimmed
		for j := i + 1; j < len(lines); j++ {
			next := strings.TrimSpace(lines[j])
			if next == "" {
				break
			}
			stmt += " " + next
			i = j
		}
		for _, n := range spannedInts(stmt) {
			if got[cur] == nil {
				got[cur] = map[int]bool{}
			}
			got[cur][n] = true
		}
	}

	for verb, have := range got {
		w := want[verb]
		if setsEqual(have, w) {
			continue
		}
		drift = append(drift, fmt.Sprintf("%s: the manual says {%s}, the verb register says {%s}",
			verb, joinSet(have), joinSet(w)))
	}
	sort.Strings(drift)

	for verb := range want {
		if _, ok := got[verb]; !ok {
			notChecked = append(notChecked, verb)
		}
	}
	sort.Strings(notChecked)
	return drift, notChecked, len(want)
}

func setsEqual(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func joinSet(s map[int]bool) string {
	nums := make([]int, 0, len(s))
	for k := range s {
		nums = append(nums, k)
	}
	sort.Ints(nums)
	parts := make([]string, 0, len(nums))
	for _, n := range nums {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, " ")
}

func printHuman(out io.Writer, r report) {
	const (
		green = "\033[0;32m"
		red   = "\033[0;31m"
		bold  = "\033[1m"
		dim   = "\033[2m"
		nc    = "\033[0m"
	)
	fmt.Fprintln(out, "=== skillctl exit-code register consistency (exitaudit) ===")
	fmt.Fprintf(out, "\n%sregister%s %s(%d codes in pkg/skillctl/exitcode)%s vs %smanual%s %s(%d register rows + %d outside rows in %s; %d cited numbers incl. %s)%s\n",
		bold, nc, dim, r.Registered, nc, bold, nc, dim, r.RegisterRows, r.OutsideRows, r.ManualFile, r.Citations, r.VerbsFile, nc)

	if len(r.Undocumented) > 0 {
		fmt.Fprintf(out, "  %sx UNDOCUMENTED%s (in exitcode.AllCodes(), missing from the manual's register table):\n", red, nc)
		for _, v := range r.Undocumented {
			fmt.Fprintf(out, "      %s\n", v)
		}
	}
	if len(r.Invented) > 0 {
		fmt.Fprintf(out, "  %sx NOT REGISTERED%s (a row in the manual's register table that exitcode.AllCodes() does not carry):\n", red, nc)
		for _, v := range r.Invented {
			fmt.Fprintf(out, "      %s\n", v)
		}
	}
	if len(r.Unaccounted) > 0 {
		fmt.Fprintf(out, "  %sx UNACCOUNTED NUMBER%s (documented, but in neither the register nor the outside table):\n", red, nc)
		for _, c := range r.Unaccounted {
			fmt.Fprintf(out, "      exit %d at %s\n", c.Number, c.Where)
		}
	}
	if len(r.BadSource) > 0 {
		fmt.Fprintf(out, "  %sx SOURCE MISSING%s (an outside-table row names a file that is not there):\n", red, nc)
		for _, v := range r.BadSource {
			fmt.Fprintf(out, "      %s\n", v)
		}
	}
	if len(r.VerbDrift) > 0 {
		fmt.Fprintf(out, "  %sx PER-VERB DRIFT%s (the manual's Exit statement and the verb register's Exit-Code cell disagree):\n", red, nc)
		for _, v := range r.VerbDrift {
			fmt.Fprintf(out, "      %s\n", v)
		}
	}
	if len(r.DuplicateOut) > 0 {
		fmt.Fprintf(out, "  %sx DUPLICATE ROW%s:\n", red, nc)
		for _, v := range r.DuplicateOut {
			fmt.Fprintf(out, "      %s\n", v)
		}
	}
	if len(r.PullDrift) > 0 {
		fmt.Fprintf(out, "  %sx PULL GATE DRIFT%s (%s in %s and the verb register's `pull` cell disagree):\n", red, nc, pullGateFunc, pullGateSource)
		for _, v := range r.PullDrift {
			fmt.Fprintf(out, "      %s\n", v)
		}
	}

	// The reach of the gate, said out loud. Not a failure: a number.
	if r.PullSkipped != "" {
		fmt.Fprintf(out, "\n  %s- pull gate NOT read as code: %s%s\n", dim, r.PullSkipped, nc)
	} else if len(r.PullSymbols) > 0 {
		fmt.Fprintf(out, "\n  %s. pull gate read as code: %s returns {%s}%s\n", dim, pullGateFunc, joinInts(r.PullSymbols), nc)
	}
	if len(r.NotChecked) > 0 {
		fmt.Fprintf(out, "  %s- %d of %d verb rows are NOT compared per verb (their manual section states no Exit line):%s\n",
			dim, len(r.NotChecked), r.VerbRows, nc)
		fmt.Fprintf(out, "      %s%s%s\n", dim, strings.Join(r.NotChecked, " "), nc)
		fmt.Fprintf(out, "      %sTheir cells are still census-checked (every number must have an owner), but nothing\n", dim)
		fmt.Fprintf(out, "      compares them with the manual. Add an `Exit:` line to that section to close the gap.%s\n", nc)
	}

	fmt.Fprintln(out, "\n─────────────────────────────")
	if r.ok() {
		fmt.Fprintf(out, "%sPASS%s: the manual's exit-code tables match exitcode.AllCodes(), and every documented number has an owner.\n", green, nc)
	} else {
		fmt.Fprintf(out, "%sFAIL%s: the exit-code register and the manual disagree (release gate blocks).\n", red, nc)
		fmt.Fprintln(out, "      Regenerate the register table with:  go run ./cmd/exitaudit -write")
		fmt.Fprintln(out, "      Or print it for review with:         go run ./cmd/exitaudit -scaffold")
	}
}

// ---------------------------------------------------------------------------
// The symbolic check (5): the pull gate's own exit expressions.
//
// Checks 1 to 4 read two markdown files and stat a handful of paths. That is
// blind to the change that started AUDIT-0001 in the first place: a symbol
// swapped inside `gateExit` (say exitcode.VerifyDigestMismatch for
// exitcode.VerifyBlobMissing) still compiles, still passes every doc check, and
// silently moves the number a caller's script branches on. So `pull`, the verb
// whose five gates were the original finding, is also read AS CODE.
// ---------------------------------------------------------------------------

// exitcodeVarNumbers AST-parses the register source and maps each `Code`
// variable's Go name to its number. AllCodes() cannot answer this: a Code value
// carries Number/Label/Family/Theme, never the identifier a call site writes.
func exitcodeVarNumbers(path string) (map[string]int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[string]int{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok || len(cl.Elts) == 0 {
					continue
				}
				if id, ok := cl.Type.(*ast.Ident); !ok || id.Name != "Code" {
					continue
				}
				if n, ok := intLit(cl.Elts[0]); ok {
					out[name.Name] = n
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no Code variables found", path)
	}
	return out, nil
}

// gateExitNumbers AST-parses one function and returns every exit number it can
// return: bare integer literals, plus `exitcode.<Name>.Number` selectors
// resolved through names. An expression it cannot resolve is reported rather
// than skipped, because a silently skipped return is how the number moves.
func gateExitNumbers(path, fn string, names map[string]int) (map[int]bool, []string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name != nil && fd.Name.Name == fn && fd.Recv == nil {
			body = fd.Body
			break
		}
	}
	if body == nil {
		return nil, nil, fmt.Errorf("%s: func %s not found", path, fn)
	}

	nums := map[int]bool{}
	var unresolved []string
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		switch e := ret.Results[0].(type) {
		case *ast.BasicLit:
			if v, ok := intLit(e); ok {
				nums[v] = true
				return true
			}
		case *ast.SelectorExpr:
			// exitcode.<Name>.Number
			if e.Sel != nil && e.Sel.Name == "Number" {
				if inner, ok := e.X.(*ast.SelectorExpr); ok {
					if pkg, ok := inner.X.(*ast.Ident); ok && pkg.Name == "exitcode" && inner.Sel != nil {
						if v, ok := names[inner.Sel.Name]; ok {
							nums[v] = true
							return true
						}
						unresolved = append(unresolved, fmt.Sprintf("exitcode.%s is not a Code variable in %s", inner.Sel.Name, exitcodeSource))
						return true
					}
				}
			}
		}
		unresolved = append(unresolved, fmt.Sprintf("%s line %d returns an expression exitaudit cannot resolve to a number",
			fn, fset.Position(ret.Pos()).Line))
		return true
	})
	sort.Strings(unresolved)
	return nums, unresolved, nil
}

// intLit reads an untyped integer literal.
func intLit(e ast.Expr) (int, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(bl.Value)
	if err != nil {
		return 0, false
	}
	return n, true
}

// pullSymbolDrift compares what the pull gate can return with what the verb
// register documents for `pull`. The base space 0/1/2 is exempt in the
// documented direction: `runPull` reaches those outside gateExit (0 on success,
// 2 on usage), so the cell may carry them without gateExit naming them.
//
// Returns the resolved numbers, the drift, and (when the sources are not on
// disk, as in the unit fixtures) the reason the check did not run.
func pullSymbolDrift(root, verbsText string) (nums []int, drift []string, skipped string) {
	gatePath := filepath.Join(root, filepath.FromSlash(pullGateSource))
	regPath := filepath.Join(root, filepath.FromSlash(exitcodeSource))
	for _, p := range []string{gatePath, regPath} {
		// #nosec G703 -- both paths are CONSTANTS in this file joined under the
		// -root the operator passed; nothing here comes from a document or a
		// network. The call only stats, and its result decides whether the
		// symbolic check runs at all.
		if _, err := os.Stat(p); err != nil {
			return nil, nil, fmt.Sprintf("%s is not under -root %s, so the pull gate was NOT read as code", p, root)
		}
	}

	names, err := exitcodeVarNumbers(regPath)
	if err != nil {
		return nil, []string{err.Error()}, ""
	}
	got, unresolved, err := gateExitNumbers(gatePath, pullGateFunc, names)
	if err != nil {
		return nil, []string{err.Error()}, ""
	}
	drift = append(drift, unresolved...)

	want := map[int]bool{}
	found := false
	for _, line := range strings.Split(verbsText, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := splitRow(trimmed)
		if len(cells) < 3 || isSeparatorRow(cells) {
			continue
		}
		if unspan(cells[0]) != pullVerb {
			continue
		}
		for _, n := range cellInts(cells[2]) {
			want[n] = true
		}
		found = true
		break
	}
	if !found {
		drift = append(drift, fmt.Sprintf("the verb register has no `%s` row to check %s against", pullVerb, pullGateSource))
		return sortedKeys(got), drift, ""
	}

	base := map[int]bool{0: true, 1: true, 2: true}
	for _, n := range sortedKeys(got) {
		if !want[n] {
			drift = append(drift, fmt.Sprintf("%s can return %d, the `%s` cell in the verb register does not list it",
				pullGateFunc, n, pullVerb))
		}
	}
	for _, n := range sortedKeys(want) {
		if base[n] || got[n] {
			continue
		}
		drift = append(drift, fmt.Sprintf("the `%s` cell claims %d, but %s in %s cannot produce it",
			pullVerb, n, pullGateFunc, pullGateSource))
	}
	return sortedKeys(got), drift, ""
}

// sortedKeys returns a set's members in ascending order.
func sortedKeys(s map[int]bool) []int {
	out := make([]int, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// joinInts renders a sorted number set for the human line.
func joinInts(ns []int) string {
	parts := make([]string, 0, len(ns))
	for _, n := range ns {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, " ")
}
