//go:build !darwin

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/plaud"
)

// BUG-0168 fix direction 4: when 'plaud auth login' cannot find the token in
// the Chrome it reads, it names the manual ways in that work without CDP.
func TestReportPlaudLoginFailure_NamesTheManualPaths(t *testing.T) {
	var buf bytes.Buffer
	reportPlaudLoginFailure(&buf, errors.New("no plaud.ai tab found among 12 Chrome target(s)"))
	out := buf.String()
	for _, want := range []string{
		"no plaud.ai tab found among 12 Chrome target(s)",
		"m3c-tools plaud auth --from-er1",
		"m3c-tools plaud auth --token-file <path>",
		plaud.PlaudTokenEnvVar + "=<token> m3c-tools plaud auth",
		"tokenstr",
		"authorization",
		"starts with 'eyJ'",
		"leave out any 'bearer'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("failure output lacks %q:\n%s", want, out)
		}
	}
}
