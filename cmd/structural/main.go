// Command structural inventories the DECISIONS in the trust path and states what
// modified condition/decision coverage would require of each one.
//
// It exists because three different coverage numbers were being read as if they
// substituted for one another. They do not:
//
//	model coverage       which states of the abstract gate composition were visited
//	mutation detection   whether the harness can see a control being disabled
//	structural coverage  which conditions in the CODE were exercised, and how
//
// The first two are measured elsewhere in this repository. The third was reported
// as "currently zero", which was accurate and useless: nobody knew how large zero
// was. This tool answers that, mechanically, by parsing the source rather than by
// anybody's recollection of it.
//
// What it does NOT do is measure execution. It produces the OBLIGATION: the list
// of decisions, their atomic conditions, whether short-circuit evaluation applies,
// and the number of test pairs MC/DC demands. Demonstrating that those pairs are
// actually executed needs an instrumented run, and that is a separate job.
//
// On the MC/DC requirement itself: for a decision with n atomic conditions,
// showing that each condition independently affects the outcome needs at least
// n+1 test cases. That is the standard lower bound and it is what the "pairs"
// column reports. Go evaluates && and || with short circuit, so a condition to the
// right of a false && is not evaluated at all, which is why the tool records it:
// an unexecuted condition cannot be shown to influence anything.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
)

// decision is one branching point in the trust path.
type decision struct {
	File       string
	Line       int
	Text       string
	Conditions int
	ShortCirc  bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: structural <file.go> [file.go ...]")
		fmt.Fprintln(os.Stderr, "  Prints the MC/DC obligation for every decision in the given files.")
		os.Exit(2)
	}
	var all []decision
	for _, path := range os.Args[1:] {
		ds, err := inventory(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "structural: %s: %v\n", path, err)
			os.Exit(1)
		}
		all = append(all, ds...)
	}
	report(all)
}

// inventory parses one file and returns its decisions.
func inventory(path string) ([]decision, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	var out []decision
	ast.Inspect(f, func(n ast.Node) bool {
		var cond ast.Expr
		switch s := n.(type) {
		case *ast.IfStmt:
			cond = s.Cond
		case *ast.ForStmt:
			cond = s.Cond
		case *ast.SwitchStmt:
			cond = s.Tag
		}
		if cond == nil {
			return true
		}
		pos := fset.Position(cond.Pos())
		out = append(out, decision{
			File:       shortPath(path),
			Line:       pos.Line,
			Text:       exprText(cond),
			Conditions: countAtomic(cond),
			ShortCirc:  hasShortCircuit(cond),
		})
		return true
	})
	return out, nil
}

// countAtomic counts the atomic conditions of a decision: the leaves of the &&
// and || tree. A decision with one leaf needs 2 test cases, one with n leaves
// needs at least n+1 for MC/DC.
func countAtomic(e ast.Expr) int {
	switch x := e.(type) {
	case *ast.BinaryExpr:
		if x.Op == token.LAND || x.Op == token.LOR {
			return countAtomic(x.X) + countAtomic(x.Y)
		}
	case *ast.ParenExpr:
		return countAtomic(x.X)
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			return countAtomic(x.X)
		}
	}
	return 1
}

func hasShortCircuit(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok && (b.Op == token.LAND || b.Op == token.LOR) {
			found = true
		}
		return true
	})
	return found
}

func exprText(e ast.Expr) string {
	var b strings.Builder
	render(&b, e)
	s := strings.Join(strings.Fields(b.String()), " ")
	if len(s) > 72 {
		s = s[:72] + " ..."
	}
	return s
}

// render is a deliberately small printer: enough to identify a decision in a
// report, not a formatter. Anything it cannot name becomes "expr", which is
// honest about what the reader has to look up.
func render(b *strings.Builder, e ast.Expr) {
	switch x := e.(type) {
	case *ast.Ident:
		b.WriteString(x.Name)
	case *ast.SelectorExpr:
		render(b, x.X)
		b.WriteString("." + x.Sel.Name)
	case *ast.CallExpr:
		render(b, x.Fun)
		b.WriteString("(...)")
	case *ast.BinaryExpr:
		render(b, x.X)
		b.WriteString(" " + x.Op.String() + " ")
		render(b, x.Y)
	case *ast.UnaryExpr:
		b.WriteString(x.Op.String())
		render(b, x.X)
	case *ast.ParenExpr:
		b.WriteString("(")
		render(b, x.X)
		b.WriteString(")")
	case *ast.BasicLit:
		b.WriteString(x.Value)
	case *ast.IndexExpr:
		render(b, x.X)
		b.WriteString("[...]")
	default:
		b.WriteString("expr")
	}
}

func shortPath(p string) string {
	if i := strings.Index(p, "pkg/"); i >= 0 {
		return p[i:]
	}
	return p
}

func report(ds []decision) {
	sort.Slice(ds, func(i, j int) bool {
		if ds[i].File != ds[j].File {
			return ds[i].File < ds[j].File
		}
		return ds[i].Line < ds[j].Line
	})
	totalPairs, multi, sc := 0, 0, 0
	fmt.Println("structural coverage obligation: MC/DC over the trust path")
	fmt.Println()
	fmt.Printf("%-46s %5s %5s %6s  %s\n", "file:line", "cond", "cases", "short", "decision")
	for _, d := range ds {
		cases := d.Conditions + 1
		totalPairs += cases
		if d.Conditions > 1 {
			multi++
		}
		if d.ShortCirc {
			sc++
		}
		short := "n/a"
		if d.ShortCirc {
			short = "yes"
		}
		fmt.Printf("%-46s %5d %5d %6s  %s\n",
			fmt.Sprintf("%s:%d", d.File, d.Line), d.Conditions, cases, short, d.Text)
	}
	fmt.Println()
	fmt.Printf("  decisions                        : %d\n", len(ds))
	fmt.Printf("  with more than one condition     : %d\n", multi)
	fmt.Printf("  using short-circuit evaluation   : %d\n", sc)
	fmt.Printf("  test cases demanded by MC/DC     : %d (lower bound, sum of n+1)\n", totalPairs)
	fmt.Println()
	fmt.Println("  This is the OBLIGATION, not the achievement. It says how large the")
	fmt.Println("  structural coverage question is; it does not answer it. Showing that")
	fmt.Println("  each condition independently affects its decision needs an instrumented")
	fmt.Println("  run, and a condition to the right of a short-circuit operator may not be")
	fmt.Println("  evaluated at all, which is why that column exists.")
	fmt.Println()
	fmt.Println("  Report this number separately from model coverage and from mutation")
	fmt.Println("  detection. None of the three substitutes for another.")
}
