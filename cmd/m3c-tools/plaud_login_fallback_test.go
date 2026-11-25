//go:build !darwin

package main

import (
	"bytes"
	"errors"
	"runtime"
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
	wants := []string{
		"no plaud.ai tab found among 12 Chrome target(s)",
		"m3c-tools plaud auth --from-er1",
		"m3c-tools plaud auth --token-file <path>",
		"tokenstr",
		"authorization",
		"starts with 'eyJ'",
		"leave out any 'bearer'",
	}
	if runtime.GOOS == "windows" {
		wants = append(wants, "$env:"+plaud.PlaudTokenEnvVar+"='<token>'; m3c-tools plaud auth", "cmd.exe: set \""+plaud.PlaudTokenEnvVar+"=<token>\" && m3c-tools plaud auth")
	} else {
		wants = append(wants, plaud.PlaudTokenEnvVar+"=<token> m3c-tools plaud auth")
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("failure output lacks %q:\n%s", want, out)
		}
	}
}

func TestPlaudLoginEnvHintTargetShell(t *testing.T) {
	for _, goos := range []string{"windows", "linux"} {
		var out bytes.Buffer
		printPlaudTokenEnvLoginHint(&out, goos)
		text := out.String()
		if goos == "windows" {
			if !strings.Contains(text, "$env:M3C_PLAUD_TOKEN='<token>'; m3c-tools plaud auth") || !strings.Contains(text, "set \"M3C_PLAUD_TOKEN=<token>\" && m3c-tools plaud auth") {
				t.Fatalf("missing Windows shell syntax: %s", text)
			}
		} else if text != "  M3C_PLAUD_TOKEN=<token> m3c-tools plaud auth\n" {
			t.Fatalf("unexpected POSIX hint: %s", text)
		}
	}
}
