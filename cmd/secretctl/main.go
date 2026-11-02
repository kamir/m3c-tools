// Command secretctl manages the life of a shared service secret: who holds it,
// whether they hold the current one, and whether it is still accepted.
//
// SPEC-0438. It lives beside m3c-tools and skillctl rather than inside either,
// because rotating a key has as little to do with fetching transcripts as with
// distributing skills, and neither of the two covers more than a third of the
// job on its own.
//
// The hard rule of this tool: it NEVER prints a secret. Not in output, not in a
// command line, not in an error. It says WHERE a value sits and WHETHER it is
// right, never WHICH one it is. Comparisons run over fingerprints. The occasion
// is recorded in SPEC-0438 §6.
//
// This build carries the READING half (inventory, verify). The writing half
// (new, stage, distribute, retire) follows under supervision, because it
// touches secrets and redeploys services.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "inventory":
		return cmdInventory(rest, stdout, stderr)
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "new", "stage", "distribute", "retire":
		fmt.Fprintf(stderr, "secretctl %s: not built yet.\n", cmd)
		fmt.Fprintf(stderr, "  The writing half of SPEC-0438 is deliberately separate from the\n")
		fmt.Fprintf(stderr, "  reading half: it touches secrets and redeploys services, and it is\n")
		fmt.Fprintf(stderr, "  built with a human watching. Until then: inventory, verify.\n")
		return 2
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "secretctl: unknown command %q\n\n", cmd)
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `secretctl: the life of a shared service secret (SPEC-0438)

  inventory <name>     who holds this secret, and does each hold the current value
  verify <name>        ask the service, per holder, whether its value is accepted
                       --old: expect refusal instead (the proof that a rotation finished)

  new | stage | distribute | retire     the writing half, not built yet

It never prints a secret. It reports places and fingerprints.

  --registry <path>    default: $SECRETCTL_REGISTRY, else ~/.config/m3c/secrets.yaml
`)
}

// registryFlag wires the shared --registry flag onto a flag set.
func registryFlag(fs *flag.FlagSet) *string {
	return fs.String("registry", DefaultRegistryPath(), "Path to the secret registry.")
}
