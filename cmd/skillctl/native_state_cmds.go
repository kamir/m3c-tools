package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// runTrustNativeState exposes explicit initial enrollment and evidence adoption.
// It never resolves legacy registry settings, credentials or install permissions.
func runTrustNativeState(args []string, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return exitUsage
	}
	if len(args) > 0 && args[0] == "enroll" {
		return runNativeStateEnroll(args[1:], stdout, stderr)
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		return writeNativeStateHelp(stdout)
	}
	if len(args) == 0 || args[0] != "adopt" {
		_ = writeNativeStateHelp(stderr)
		return exitUsage
	}
	fs := flag.NewFlagSet("trust native-state adopt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("enterprise-profile", "", "Explicit absolute native Enterprise project profile")
	pin := fs.String("enterprise-profile-sha256", "", "Optional SHA-256 pin of the selected profile")
	home := fs.String("home", "", "Artifact home bound by the profile (default: user home)")
	asJSON := fs.Bool("json", false, "Print authenticated history status as JSON")
	helpCode := exitOK
	fs.Usage = func() { helpCode = writeNativeStateHelp(stderr) }
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return helpCode
		}
		return exitUsage
	}
	if fs.NArg() != 0 || *profile == "" {
		fs.Usage()
		return exitUsage
	}
	pinSelected, homeSelected := false, false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "enterprise-profile-sha256" {
			pinSelected = true
		}
		if f.Name == "home" {
			homeSelected = true
		}
	})
	if homeSelected && *home == "" {
		return nativeStateFailure(stderr, projectpolicy.ErrSelection)
	}
	if !filepath.IsAbs(*profile) {
		return nativeStateFailure(stderr, projectpolicy.ErrSelection)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nativeStateFailure(stderr, projectpolicy.ErrSelection)
	}
	if *home == "" {
		*home, err = os.UserHomeDir()
		if err != nil {
			return nativeStateFailure(stderr, projectpolicy.ErrSelection)
		}
	}
	var policy *projectpolicy.NativePolicy
	if pinSelected {
		policy, err = projectpolicy.LoadNativePinned(*profile, *pin, cwd, *home)
	} else {
		policy, err = projectpolicy.LoadNative(*profile, cwd, *home)
	}
	if err != nil {
		return nativeStateFailure(stderr, err)
	}
	if err = policy.ValidateSelection(cwd, *home, policy.CarrierSelection().Locator); err != nil {
		return nativeStateFailure(stderr, err)
	}
	status, err := policy.AdoptFromSource(context.Background())
	if err != nil {
		return nativeStateFailure(stderr, err)
	}
	output := []byte(fmt.Sprintf("Native history updated: epoch %d, evidence %s. This does not authorize installation.\n", status.Epoch, status.EvidenceDigest))
	if *asJSON {
		output, err = json.Marshal(struct {
			HistoryAuthorityID string    `json:"history_authority_id"`
			EvidenceSHA256     string    `json:"evidence_sha256"`
			Epoch              int64     `json:"epoch"`
			IssuedAt           time.Time `json:"issued_at"`
			LastSeen           time.Time `json:"last_seen"`
		}{status.HistoryAuthorityID, status.EvidenceDigest, status.Epoch, status.IssuedAt, status.LastSeen})
		if err != nil {
			fmt.Fprintln(stderr, "Native history may already be updated; status output failed.")
			return exitGeneric
		}
		output = append(output, '\n')
	}
	if n, writeErr := stdout.Write(output); writeErr != nil || n != len(output) {
		fmt.Fprintln(stderr, "Native history may already be updated; status output failed.")
		return exitGeneric
	}
	return exitOK
}

func writeNativeStateHelp(w io.Writer) int {
	const help = "Usage: skillctl trust native-state adopt --enterprise-profile ABS [--enterprise-profile-sha256 SHA] [--home H] [--json]\n       skillctl trust native-state enroll --enterprise-profile ABS --evidence ABS [--enterprise-profile-sha256 SHA] [--home H] [--json]\nExplicitly adopt HTTPS evidence into existing history, or initially enroll complete signed local evidence. Neither operation resets history or grants installation. Lost-history recovery requires the documented operator procedure.\n"
	n, err := io.WriteString(w, help)
	if err != nil || n != len(help) {
		return exitGeneric
	}
	return exitOK
}

func nativeStateFailure(w io.Writer, err error) int {
	code := verify.ExitCode(err)
	message := "Native evidence source operation failed."
	switch {
	case errors.Is(err, registry.ErrNativeEvidenceSourceIO):
		message = "Native evidence source I/O failed; no successful adoption was confirmed."
	case errors.Is(err, registry.ErrNativePersistence):
		message = "Native history persistence failed; history may already have changed."
	case errors.Is(err, projectpolicy.ErrInvalid), errors.Is(err, projectpolicy.ErrSelection), errors.Is(err, projectpolicy.ErrUnsupported):
		code = verify.ExitRegistryNotTrusted
		message = "Native Enterprise profile selection or source configuration is invalid or unsupported."
	case code == verify.ExitRegistryNotTrusted:
		message = "Native evidence authentication or policy validation failed."
	case code == verify.ExitRevocationStale:
		message = "Native history is unavailable, invalid or behind its required trust floor."
	}
	fmt.Fprintln(w, message)
	return code
}
