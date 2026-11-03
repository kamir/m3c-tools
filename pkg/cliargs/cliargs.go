// Package cliargs holds argument handling shared by the CLIs of this module.
//
// It exists because Go's flag package stops parsing at the first non-flag
// argument, and the binaries answered that differently: skillctl publish
// reordered its arguments, while secretctl and skillctl install, verify and
// export-bundle rejected a flag after the name with a usage line (BUG-0450).
// One rule in one place makes the order learnable.
package cliargs

import (
	"flag"
	"strings"
)

// FlagsFirst returns args with every flag (and its value) moved before the
// positionals, so that `secretctl inventory <name> --registry <path>` parses like
// `secretctl inventory --registry <path> <name>` (BUG-0450). Go's flag package stops at
// the first non-flag argument, which turned the second order into a usage
// error. Only tokens naming a flag of fs consume a following value; an
// unknown flag stays a flag so Parse reports it. A literal "--" ends flag
// parsing and is kept, so nothing after it is ever read as a flag. A value
// flag that ends the arguments stays a parse error.
func FlagsFirst(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		t := args[i]
		if t == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(t) < 2 || t[0] != '-' {
			positional = append(positional, t)
			continue
		}
		flags = append(flags, t)
		name := strings.TrimLeft(t, "-")
		if strings.Contains(name, "=") {
			continue
		}
		fl := fs.Lookup(name)
		if fl == nil {
			continue
		}
		if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 == len(args) {
			// A value flag with nothing after it: return it last and
			// without the "--", so Parse reports the missing value instead
			// of reading "--" or a positional as the value.
			return flags
		}
		i++
		flags = append(flags, args[i])
	}
	return append(append(flags, "--"), positional...)
}
