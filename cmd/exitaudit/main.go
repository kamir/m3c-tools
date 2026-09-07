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
}

func (r report) ok() bool {
	return len(r.Undocumented) == 0 && len(r.Invented) == 0 &&
		len(r.Unaccounted) == 0 && len(r.BadSource) == 0 &&
		len(r.DuplicateOut) == 0 && len(r.VerbDrift) == 0
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

	manual, err := os.ReadFile(manualPath) // #nosec G304 -- a trusted CLI argument (the manual markdown), same trust model as cmd/verbaudit's register read.
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
		if err := os.WriteFile(manualPath, []byte(updated), 0o644); err != nil { // #nosec G306 -- documentation, world-readable by design.
			fmt.Fprintf(stderr, "exitaudit: write manual: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "exitaudit: rewrote the register block in %s from exitcode.AllCodes()\n", manualPath)
		return 0
	}

	verbs, err := os.ReadFile(verbsPath) // #nosec G304 -- see above.
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
	// 5. Per-verb agreement between the manual and the verb register.
	rep.VerbDrift = verbDrift(manualText, verbsText)

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
func verbDrift(manualText, verbsText string) []string {
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

	var out []string
	for verb, have := range got {
		w := want[verb]
		if setsEqual(have, w) {
			continue
		}
		out = append(out, fmt.Sprintf("%s: the manual says {%s}, the verb register says {%s}",
			verb, joinSet(have), joinSet(w)))
	}
	sort.Strings(out)
	return out
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

	fmt.Fprintln(out, "\n─────────────────────────────")
	if r.ok() {
		fmt.Fprintf(out, "%sPASS%s: the manual's exit-code tables match exitcode.AllCodes(), and every documented number has an owner.\n", green, nc)
	} else {
		fmt.Fprintf(out, "%sFAIL%s: the exit-code register and the manual disagree (release gate blocks).\n", red, nc)
		fmt.Fprintln(out, "      Regenerate the register table with:  go run ./cmd/exitaudit -write")
		fmt.Fprintln(out, "      Or print it for review with:         go run ./cmd/exitaudit -scaffold")
	}
}
