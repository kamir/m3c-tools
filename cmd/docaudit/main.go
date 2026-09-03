// Command docaudit is the code↔manual consistency gate for the CLI surface.
//
// It answers two release-gate questions, per CLI, in BOTH directions:
//
//   - Is every real CLI flag documented?        (code flag with no manual entry = UNDOCUMENTED)
//   - Is every documented flag real?             (manual entry with no code flag  = PHANTOM)
//
// The "real" surface is extracted mechanism-independently by the UNION of two
// AST strategies, because the two CLIs use different idioms:
//
//   - flag.FlagSet registration — the authoritative name is the first STRING
//     literal argument of a fs.String/Bool/Int/Duration/Var/Func(...) call
//     (skillctl: `fs.String("reviewer-id", def, "usage")`). The usage string is
//     right there, which is why it is also the scaffolding source for --fix.
//   - `"--flag"` string literals — a hand-rolled `case "--x":` switch never
//     registers a FlagSet, so its surface is the double-dash literals it matches
//     (m3c-tools).
//   - SHORT ALIASES named alongside their long form — `case "-f", "--force":` or
//     `if a == "--dry-run" || a == "-n"`. A lone `-x` literal is NOT a flag (it is
//     usually another program's argument: `open -a`, `stty -echo`, `security -w`),
//     so a single-dash literal counts only when the SAME switch-case list or `if`
//     condition also names a `--long` flag. That sibling is the evidence.
//
// Flag names are CANONICALISED to their dashless form before comparison, so the
// Go flag package's equivalent `-x` and `--x` spellings (which the manuals mix)
// collapse to one flag. A flag the code never names cannot be matched at
// runtime, so the union IS the surface.
//
// The "documented" surface is every flag DEFINED by an inline code span in the
// manual — the house convention. A span DEFINES the flags it LEADS with:
//
//	`--skill <dir>`                        → skill
//	`-o, --output <path>`                  → output, o
//	`--author-intent green|yellow|red`     → author-intent
//	`skillctl report --input <scan.json>`  → nothing: a command line, not a definition
//
// so a flag that appears only inside a copy-paste example — a fenced block (those
// are stripped first) or an inline command line — is NOT documented. That is
// deliberate: the gate enforces "described", not merely "mentioned". Intentional
// exemptions — a flag documented to state its ABSENCE, an internal debug flag —
// live in docs/docaudit-ignore.txt, fail-closed with a written reason.
//
// Exit codes: 0 = consistent; 1 = drift found (the release gate blocks); 2 = a
// usage/IO error. Pure Go stdlib + portable (runs on the Windows gate too).
//
// Usage:
//
//	docaudit [-cli m3c-tools|skillctl|all] [-json] [-config <path>] [-ignore <path>]
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// target is one auditable CLI: its command package and its manual.
type target struct {
	Name   string `json:"name"`
	PkgDir string `json:"pkg_dir"`
	Manual string `json:"manual"`
}

// defaultTargets is the built-in surface; override with -config for reuse on
// other CLIs / other repos (the same gate, keyed by config — see CODESTYLE.md).
var defaultTargets = []target{
	{Name: "m3c-tools", PkgDir: "cmd/m3c-tools", Manual: "docs/manual-m3c-tools.md"},
	{Name: "skillctl", PkgDir: "cmd/skillctl", Manual: "docs/manual-skillctl.md"},
}

// nameRe accepts a canonical (dashless) long-flag name: word, two-words,
// er1-url, int64-ish. It rejects markdown rules and short/empty tokens.
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// dashLitRe matches a `--flag` double-dash string literal in code.
var dashLitRe = regexp.MustCompile(`^--([a-z][a-z0-9-]*)$`)

// shortLitRe matches a `-f` SINGLE-dash string literal. Admitted only inside a
// group that also names a `--long` flag — see shortAliases.
var shortLitRe = regexp.MustCompile(`^-([a-z][a-z0-9-]*)$`)

// codeSpanRe matches one inline code span (never spanning a line break).
var codeSpanRe = regexp.MustCompile("`([^`\n]+)`")

// leadFlagRe matches the flag a span LEADS with; contFlagRe matches each further
// flag in a leading `-o, --output` / `--a / --b` alias list. The Go flag package
// treats `-x` and `--x` as the same flag, so both spellings are accepted.
var (
	leadFlagRe = regexp.MustCompile(`^\s*(-{1,2}[a-z][a-z0-9-]*)`)
	contFlagRe = regexp.MustCompile(`^\s*[,/]\s*(-{1,2}[a-z][a-z0-9-]*)`)
)

// fenceRe matches a fenced-code-block delimiter line (``` or ~~~).
var fenceRe = regexp.MustCompile("^\\s*(```|~~~)")

// flagMethods are the *flag.FlagSet (and top-level flag.*) registration methods.
// For every one, the flag NAME is the first string-literal argument — true for
// the value-returning forms String(name,…), the *Var forms StringVar(&p,name,…),
// and Var(value,name,…)/Func(name,…) alike.
var flagMethods = map[string]bool{
	"String": true, "StringVar": true, "Bool": true, "BoolVar": true,
	"Int": true, "IntVar": true, "Int64": true, "Int64Var": true,
	"Uint": true, "UintVar": true, "Uint64": true, "Uint64Var": true,
	"Float64": true, "Float64Var": true, "Duration": true, "DurationVar": true,
	"Var": true, "TextVar": true, "Func": true, "BoolFunc": true,
}

// canon reduces a flag token (`--x`, `-x`, or bare `x`) to its dashless name.
func canon(s string) string { return strings.TrimLeft(s, "-") }

type report struct {
	CLI          string   `json:"cli"`
	CodeFlags    int      `json:"code_flags"`
	DocFlags     int      `json:"doc_flags"`
	Undocumented []string `json:"undocumented"` // in code, not in manual
	Phantom      []string `json:"phantom"`      // in manual, not in code
}

func (r report) clean() bool { return len(r.Undocumented) == 0 && len(r.Phantom) == 0 }

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	var (
		cliSel     = "all"
		asJSON     bool
		scaffold   bool
		configPath string
		ignorePath = "docs/docaudit-ignore.txt"
	)
	// Minimal flag parsing — no external deps, matches the repo idiom.
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-cli":
			i++
			if i < len(argv) {
				cliSel = argv[i]
			}
		case "-json":
			asJSON = true
		case "-scaffold":
			scaffold = true
		case "-config":
			i++
			if i < len(argv) {
				configPath = argv[i]
			}
		case "-ignore":
			i++
			if i < len(argv) {
				ignorePath = argv[i]
			}
		case "-h", "--help":
			fmt.Fprint(os.Stdout, "usage: docaudit [-cli m3c-tools|skillctl|all] [-json|-scaffold] [-config <path>] [-ignore <path>]\n")
			return 0
		default:
			fmt.Fprintf(os.Stderr, "docaudit: unknown argument %q\n", argv[i])
			return 2
		}
	}

	targets := defaultTargets
	if configPath != "" {
		t, err := loadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "docaudit: %v\n", err)
			return 2
		}
		targets = t
	}

	ignore, err := loadIgnore(ignorePath) // absent file → empty, not an error.
	if err != nil {
		fmt.Fprintf(os.Stderr, "docaudit: %v\n", err)
		return 2
	}

	var reports []report
	var matched []target
	for _, t := range targets {
		if cliSel != "all" && cliSel != t.Name {
			continue
		}
		r, err := audit(t, ignore)
		if err != nil {
			fmt.Fprintf(os.Stderr, "docaudit: %s: %v\n", t.Name, err)
			return 2
		}
		reports = append(reports, r)
		matched = append(matched, t)
	}
	if len(reports) == 0 {
		fmt.Fprintf(os.Stderr, "docaudit: no CLI matched %q\n", cliSel)
		return 2
	}

	if scaffold {
		for i, r := range reports {
			if err := printScaffold(matched[i], r); err != nil {
				fmt.Fprintf(os.Stderr, "docaudit: %s: %v\n", matched[i].Name, err)
				return 2
			}
		}
		return 0 // scaffold is advisory drafting, not the gate
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return 2
		}
	} else {
		printHuman(reports)
	}

	for _, r := range reports {
		if !r.clean() {
			return 1
		}
	}
	return 0
}

// audit computes the bidirectional drift for one CLI target.
func audit(t target, ignore map[string]bool) (report, error) {
	code, err := codeFlags(t.PkgDir)
	if err != nil {
		return report{}, err
	}
	doc, err := docFlags(t.Manual)
	if err != nil {
		return report{}, err
	}
	r := report{CLI: t.Name, CodeFlags: len(code), DocFlags: len(doc)}
	exempt := func(name string) bool {
		disp := "--" + name
		return ignore[t.Name+":"+disp] || ignore[disp] || ignore[t.Name+":"+name] || ignore[name]
	}
	for f := range code {
		if !doc[f] && !exempt(f) {
			r.Undocumented = append(r.Undocumented, "--"+f)
		}
	}
	for f := range doc {
		if !code[f] && !exempt(f) {
			r.Phantom = append(r.Phantom, "--"+f)
		}
	}
	sort.Strings(r.Undocumented)
	sort.Strings(r.Phantom)
	return r, nil
}

// codeFlags returns the canonical (dashless) names of every flag the CLI's
// command package defines, via the UNION of the two AST strategies: FlagSet
// registrations and `--x` double-dash literals. Non-test .go files only.
func codeFlags(pkgDir string) (map[string]bool, error) {
	out := map[string]bool{}
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read pkg dir: %w", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				// Strategy 2: a `--flag` double-dash string literal.
				if node.Kind == token.STRING {
					if m := dashLitRe.FindStringSubmatch(strings.Trim(node.Value, "`\"")); m != nil {
						out[canon(m[1])] = true
					}
				}
			case *ast.CallExpr:
				// Strategy 1: a FlagSet registration — name = first string arg.
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || !flagMethods[sel.Sel.Name] {
					return true
				}
				for _, a := range node.Args {
					lit, ok := a.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v := canon(strings.Trim(lit.Value, "`\"")); nameRe.MatchString(v) {
						out[v] = true
					}
					break // only the first string literal is the name
				}
			}
			return true
		})
		// Strategy 3: short aliases named alongside their long form.
		for name := range shortAliases(f) {
			out[name] = true
		}
	}
	return out, nil
}

// shortAliases returns the canonical names of the short flags in n that are
// named ALONGSIDE a long flag. The group is one switch-case list or one `if`
// condition — a scope small enough that a `--long` literal in it is real
// evidence that the neighbouring `-x` is that flag's alias.
//
// Only the case LIST and the `if` COND are scanned, never their bodies: that is
// what keeps another program's arguments out of the surface, since those live in
// call expressions (`exec.Command("open", "-a", …)`) or in an `if` INIT statement
// (`if err := stty("-echo"); err == nil`).
func shortAliases(n ast.Node) map[string]bool {
	out := map[string]bool{}
	admit := func(exprs []ast.Expr) {
		var long, short []string
		for _, e := range exprs {
			ast.Inspect(e, func(m ast.Node) bool {
				lit, ok := m.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v := strings.Trim(lit.Value, "`\"")
				switch {
				case dashLitRe.MatchString(v):
					long = append(long, v)
				default:
					if sm := shortLitRe.FindStringSubmatch(v); sm != nil {
						short = append(short, sm[1])
					}
				}
				return true
			})
		}
		if len(long) == 0 {
			return // no long flag in this group: a lone -x is not our flag
		}
		for _, sh := range short {
			if v := canon(sh); nameRe.MatchString(v) {
				out[v] = true
			}
		}
	}
	ast.Inspect(n, func(m ast.Node) bool {
		switch node := m.(type) {
		case *ast.CaseClause:
			admit(node.List)
		case *ast.IfStmt:
			if node.Cond != nil {
				admit([]ast.Expr{node.Cond})
			}
		}
		return true
	})
	return out
}

// docFlags returns the canonical (dashless) names of every flag the manual
// DEFINES. Fenced code blocks are stripped first (a copy-paste example does not
// document anything), then each inline code span contributes the flags it LEADS
// with — see the package doc for why leading position is the definition signal.
func docFlags(manual string) (map[string]bool, error) {
	b, err := os.ReadFile(manual)
	if err != nil {
		return nil, fmt.Errorf("read manual: %w", err)
	}
	out := map[string]bool{}
	inFence := false
	for _, line := range strings.Split(string(b), "\n") {
		if fenceRe.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, span := range codeSpanRe.FindAllStringSubmatch(line, -1) {
			for _, tok := range spanFlags(span[1]) {
				out[tok] = true
			}
		}
	}
	return out, nil
}

// spanFlags returns the canonical names of the flags an inline code span LEADS
// with: the first token, plus any further tokens in a `,`/`/`-separated alias
// list that follows it immediately. A span that does not start with a flag (a
// command line, a path, a value) defines nothing.
func spanFlags(span string) []string {
	m := leadFlagRe.FindStringSubmatchIndex(span)
	if m == nil {
		return nil
	}
	var out []string
	add := func(tok string) {
		if v := canon(tok); nameRe.MatchString(v) {
			out = append(out, v)
		}
	}
	add(span[m[2]:m[3]])
	rest := span[m[1]:]
	for {
		c := contFlagRe.FindStringSubmatchIndex(rest)
		if c == nil {
			return out
		}
		add(rest[c[2]:c[3]])
		rest = rest[c[1]:]
	}
}

type flagInfo struct {
	Usage string
	Sub   string
}

// scaffoldFlags returns, per canonical flag name, its usage string and the
// subcommand it belongs to — for drafting manual entries. It walks each
// FuncDecl and attributes flags to the flag.NewFlagSet("<sub>", …) created in
// that function (or, absent one, to the function's own name).
func scaffoldFlags(pkgDir string) (map[string]flagInfo, error) {
	out := map[string]flagInfo{}
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read pkg dir: %w", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			sub := subName(fn.Name.Name)
			// Prefer the FlagSet's own subcommand name, if the function makes one.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewFlagSet" && len(call.Args) > 0 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v := strings.Trim(lit.Value, "`\""); nameRe.MatchString(v) {
							sub = v
						}
					}
				}
				return true
			})
			// Attribute flag registrations (name + usage) and dash literals.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok || !flagMethods[sel.Sel.Name] {
						return true
					}
					var strs []string
					for _, a := range node.Args {
						if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							strs = append(strs, strings.Trim(lit.Value, "`\""))
						}
					}
					if len(strs) == 0 {
						return true
					}
					flagName := canon(strs[0])
					usage := ""
					if len(strs) > 1 {
						usage = strs[len(strs)-1] // last string arg is the usage text
					}
					if nameRe.MatchString(flagName) {
						if _, seen := out[flagName]; !seen {
							out[flagName] = flagInfo{Usage: usage, Sub: sub}
						}
					}
				case *ast.BasicLit:
					if node.Kind == token.STRING {
						if m := dashLitRe.FindStringSubmatch(strings.Trim(node.Value, "`\"")); m != nil {
							if nm := canon(m[1]); nameRe.MatchString(nm) {
								if _, seen := out[nm]; !seen {
									out[nm] = flagInfo{Sub: sub}
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	return out, nil
}

// subName derives a subcommand label from a handler function name by trimming a
// leading run/cmd/handle/do and lower-casing the first letter.
func subName(fnName string) string {
	for _, p := range []string{"run", "cmd", "handle", "do"} {
		if strings.HasPrefix(fnName, p) && len(fnName) > len(p) {
			r := fnName[len(p):]
			return strings.ToLower(r[:1]) + r[1:]
		}
	}
	return fnName
}

// printScaffold emits manual-ready draft entries for a CLI's UNDOCUMENTED flags,
// grouped by subcommand, seeded from each flag's own usage string.
func printScaffold(t target, r report) error {
	if len(r.Undocumented) == 0 {
		fmt.Printf("## %s — no undocumented flags ✓\n\n", t.Name)
		return nil
	}
	info, err := scaffoldFlags(t.PkgDir)
	if err != nil {
		return err
	}
	bySub := map[string][]string{}
	for _, disp := range r.Undocumented {
		fi := info[canon(disp)]
		usage := fi.Usage
		if usage == "" {
			usage = "TODO — describe (read the handler)"
		}
		sub := fi.Sub
		if sub == "" {
			sub = "(ungrouped)"
		}
		bySub[sub] = append(bySub[sub], fmt.Sprintf("- `%s` — %s", disp, usage))
	}
	subs := make([]string, 0, len(bySub))
	for s := range bySub {
		subs = append(subs, s)
	}
	sort.Strings(subs)
	fmt.Printf("## %s — %d undocumented flag(s) to add\n\n", t.Name, len(r.Undocumented))
	for _, s := range subs {
		fmt.Printf("### %s\n", s)
		sort.Strings(bySub[s])
		for _, l := range bySub[s] {
			fmt.Println(l)
		}
		fmt.Println()
	}
	return nil
}

func loadConfig(path string) ([]target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var t []target
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(t) == 0 {
		return nil, fmt.Errorf("config %s has no targets", path)
	}
	return t, nil
}

// loadIgnore reads intentional exemptions: one per line, `--flag` or
// `cli:--flag`, `#` starts a comment. An absent file is not an error.
func loadIgnore(path string) (map[string]bool, error) {
	out := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read ignore: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if fields := strings.Fields(line); len(fields) > 0 {
			out[fields[0]] = true
		}
	}
	return out, nil
}

func printHuman(reports []report) {
	const (
		green  = "\033[0;32m"
		red    = "\033[0;31m"
		yellow = "\033[0;33m"
		dim    = "\033[2m"
		nc     = "\033[0m"
	)
	fmt.Println("=== CLI ↔ Manual Consistency (docaudit) ===")
	for _, r := range reports {
		fmt.Printf("\n%s%s%s  %s(%d code flags · %d documented)%s\n", "\033[1m", r.CLI, nc, dim, r.CodeFlags, r.DocFlags, nc)
		if r.clean() {
			fmt.Printf("  %s✓%s consistent\n", green, nc)
			continue
		}
		if len(r.Undocumented) > 0 {
			fmt.Printf("  %s✗ UNDOCUMENTED%s (in code, not in manual — add to %s):\n", red, nc, "the manual")
			for _, f := range r.Undocumented {
				fmt.Printf("      %s\n", f)
			}
		}
		if len(r.Phantom) > 0 {
			fmt.Printf("  %s✗ PHANTOM%s (documented, not in code — remove, code moved on):\n", yellow, nc)
			for _, f := range r.Phantom {
				fmt.Printf("      %s\n", f)
			}
		}
	}
	fmt.Println("\n─────────────────────────────")
	bad := false
	for _, r := range reports {
		if !r.clean() {
			bad = true
		}
	}
	if bad {
		fmt.Printf("%sFAIL%s: CLI surface and manual disagree (release gate blocks).\n", red, nc)
	} else {
		fmt.Printf("%sPASS%s: every real flag is documented and every documented flag is real.\n", green, nc)
	}
}
