package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type nativeStateShortWriter struct{}

func (nativeStateShortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestNativeStateDiagnosticsAndUsage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		code     int
		fragment string
	}{
		{"source", errors.Join(registry.ErrNativeEvidenceSourceIO, errors.New("https://private.invalid/token-secret")), 1, "source I/O"},
		{"source before evidence", errors.Join(registry.ErrNativeEvidenceInvalid, registry.ErrNativeEvidenceSourceIO), 1, "source I/O"},
		{"persistence", errors.Join(registry.ErrNativePersistence, errors.New("/private/sensitive-path")), 1, "may already have changed"},
		{"profile", projectpolicy.ErrInvalid, 12, "profile selection"},
		{"unsupported", projectpolicy.ErrUnsupported, 12, "unsupported"},
		{"history", registry.ErrNativeHistoryRequired, 22, "history"},
		{"authentication", registry.ErrNativeEvidenceInvalid, 12, "authentication"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if got := nativeStateFailure(&out, tc.err); got != tc.code {
				t.Fatalf("code=%d want=%d", got, tc.code)
			}
			if !strings.Contains(out.String(), tc.fragment) || strings.Contains(out.String(), "token-secret") || strings.Contains(out.String(), "sensitive-path") {
				t.Fatalf("unsafe or unhelpful diagnostic %q", out.String())
			}
		})
	}
	if got := writeNativeStateHelp(nativeStateShortWriter{}); got != 1 {
		t.Fatalf("short help write=%d", got)
	}
	for _, args := range [][]string{nil, {"enroll"}, {"reset"}, {"adopt"}, {"adopt", "--force"}, {"adopt", "--enterprise-profile", "x", "positional"}} {
		if got := runTrustNativeState(args, io.Discard, io.Discard); got != 2 {
			t.Errorf("usage %q code=%d", args, got)
		}
	}
	var out bytes.Buffer
	if got := runTrust([]string{"native-state", "help"}, &out, io.Discard); got != 0 || !strings.Contains(out.String(), "native-state adopt") || !strings.Contains(out.String(), "native-state enroll") || !strings.Contains(out.String(), "Neither operation resets history or grants installation") {
		t.Fatalf("native dispatcher help: %d %q", got, out.String())
	}
}
