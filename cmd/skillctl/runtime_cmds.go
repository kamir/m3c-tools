package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
)

type runtimeTreeResult struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
	OK        bool   `json:"ok"`
	ExitCode  int    `json:"exit_code"`
	Error     string `json:"error,omitempty"`
	*dependencies.TreeObservation
}

func runRuntime(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "fingerprint" {
		if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
			if !runtimeWrite(stdout, []byte("usage: skillctl runtime fingerprint --path <absolute-tree> [--json]\nRead-only tree observation; no baseline approval or profile changes.\n")) {
				return 1
			}
			return 0
		}
		fmt.Fprintln(stderr, "usage: skillctl runtime fingerprint --path <absolute-tree> [--json]")
		return 2
	}
	fs := flag.NewFlagSet("runtime fingerprint", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	path := fs.String("path", "", "Explicit absolute tree path to observe (no automatic discovery).")
	asJSON := fs.Bool("json", false, "Emit JSON; place first to include flag parse failures.")
	fs.Usage = func() {
		fmt.Fprintln(&flagOutput, "usage: skillctl runtime fingerprint [--json] --path <absolute-tree>")
		fs.PrintDefaults()
	}
	result := runtimeTreeResult{Schema: "m3c.skillctl.runtime-tree-observation/v1", Operation: "runtime_fingerprint"}
	render := func(code int, message string) int {
		result.ExitCode = code
		result.OK = code == 0
		result.Error = message
		var body []byte
		if *asJSON {
			var err error
			body, err = json.Marshal(result)
			if err != nil {
				return 1
			}
			body = append(body, '\n')
		} else if code != 0 {
			fmt.Fprintln(stderr, message)
			return code
		} else {
			body = []byte(fmt.Sprintf("Tree fingerprint observed: %q\nAlgorithm: %s\nDigest: %s\nThis does not approve a runtime baseline or change a profile.\n", result.Path, result.Algorithm, result.Digest))
		}
		if !runtimeWrite(stdout, body) {
			return 1
		}
		return code
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if !runtimeWrite(stdout, flagOutput.Bytes()) {
				return 1
			}
			return 0
		}
		if !runtimeWrite(stderr, flagOutput.Bytes()) {
			return 1
		}
		return render(2, "invalid runtime fingerprint arguments")
	}
	if fs.NArg() != 0 || *path == "" || len(*path) > 4096 || !utf8.ValidString(*path) || strings.ContainsAny(*path, "\x00\r\n") || !filepath.IsAbs(*path) {
		return render(2, "runtime fingerprint requires one explicit absolute --path and no operands")
	}
	observation, err := dependencies.FingerprintTree(context.Background(), *path)
	if err != nil {
		return render(1, "runtime tree observation failed")
	}
	result.TreeObservation = observation
	return render(0, "")
}

func runtimeWrite(w io.Writer, body []byte) bool {
	n, err := w.Write(body)
	return err == nil && n == len(body)
}
