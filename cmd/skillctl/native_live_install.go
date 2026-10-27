package main

import (
	"context"
	"encoding/base64"
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

type nativePullFlags struct {
	profile, pin, home, selector, digest, kind string
	install, trustMode, nativeSession          bool
}

func runSelectedNativePull(ctx context.Context, fs *flag.FlagSet, options nativePullFlags, input io.Reader, stdout, stderr io.Writer) int {
	profile, pin, home, selector, digest, kind := options.profile, options.pin, options.home, options.selector, options.digest, options.kind
	allowed := map[string]bool{"enterprise-profile": true, "enterprise-profile-sha256": true, "home": true, "registry": true, "digest": true, "kind": true, "install": true, "trust-mode": true, "native-session": true}
	valid, profileSelected, pinSelected, homeSelected, registrySelected, kindSelected := true, false, false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		valid = valid && allowed[f.Name]
		profileSelected = profileSelected || f.Name == "enterprise-profile"
		pinSelected = pinSelected || f.Name == "enterprise-profile-sha256"
		homeSelected = homeSelected || f.Name == "home"
		registrySelected = registrySelected || f.Name == "registry"
		kindSelected = kindSelected || f.Name == "kind"
	})
	if !valid || fs.NArg() != 0 || !options.nativeSession || !options.install || !options.trustMode || (kind != "agent" && kind != "skill") || !kindSelected || !profileSelected || profile == "" || digest == "" {
		fmt.Fprintln(stderr, "Native installation requires --native-session --enterprise-profile ABS --kind agent|skill --digest sha256:HEX --install --trust-mode; unrelated pull flags are unsupported.")
		return exitUsage
	}
	if !filepath.IsAbs(profile) || (homeSelected && home == "") {
		return nativePullFailure(stderr, projectpolicy.ErrSelection)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nativePullFailure(stderr, projectpolicy.ErrSelection)
	}
	if !homeSelected {
		home, err = os.UserHomeDir()
		if err != nil {
			return nativePullFailure(stderr, projectpolicy.ErrSelection)
		}
	}
	var policy *projectpolicy.NativePolicy
	if pinSelected {
		policy, err = projectpolicy.LoadNativePinned(profile, pin, cwd, home)
	} else {
		policy, err = projectpolicy.LoadNative(profile, cwd, home)
	}
	if err != nil {
		return nativePullFailure(stderr, err)
	}
	if !registrySelected {
		selector = policy.CarrierSelection().Locator
	}
	if err = policy.ValidateSelection(cwd, home, selector); err != nil {
		return nativePullFailure(stderr, err)
	}
	if kind == "skill" {
		return runNativeSkillPull(ctx, input, stdout, stderr, policy, digest)
	}
	return runNativeAgentPull(ctx, input, stdout, stderr, policy, digest)
}

func runNativeAgentPull(ctx context.Context, input io.Reader, stdout, stderr io.Writer, policy *projectpolicy.NativePolicy, digest string) (code int) {
	if ctx == nil || input == nil || stdout == nil || stderr == nil {
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, registry.TokenTTL)
	defer cancel()
	var session *registry.NativeLiveAgentSession
	var err error
	if policy.CarrierSelection().Kind == "git" {
		session, err = policy.BeginGitAgentInstall(ctx, digest)
	} else {
		session, err = policy.BeginER1AgentInstall(ctx, digest)
	}
	if err != nil {
		return nativePullFailure(stderr, err)
	}
	closed := false
	defer func() {
		if !closed {
			if err := session.Close(); err != nil {
				fmt.Fprintln(stderr, "Native session release failed; inspect trust and destination state before retrying.")
				code = exitGeneric
			}
		}
	}()
	plan, err := session.Plan(ctx)
	if err != nil {
		return nativePullFailure(stderr, err)
	}
	if err = writeNativeSessionJSON(stdout, struct {
		Type      string                          `json:"type"`
		Rows      []registry.NativeInstallPlanRow `json:"rows"`
		Token     string                          `json:"token"`
		ExpiresAt time.Time                       `json:"expires_at"`
	}{"native-agent-plan", plan.Rows, plan.Token, plan.ExpiresAt}); err != nil {
		fmt.Fprintln(stderr, "Native plan output failed; installation was not confirmed.")
		return exitGeneric
	}
	const prompt = "Review the plan. To confirm, enter its complete token followed by Enter in this process (maximum five minutes). EOF cancels.\n"
	if n, err := io.WriteString(stderr, prompt); err != nil || n != len(prompt) {
		return exitGeneric
	}
	token, err := readNativeConsentLine(ctx, input)
	if err != nil {
		return nativePullFailure(stderr, errors.Join(registry.ErrNativeConsentInvalid, err))
	}
	results, err := session.Confirm(ctx, token)
	if err != nil {
		return nativePullFailure(stderr, err)
	}
	// A successful publication is not successful command completion until the
	// held journal lease has been released with its Close result checked.
	err = session.Close()
	closed = true
	if err != nil {
		fmt.Fprintln(stderr, "Native installation may already have changed files; session release failed. Inspect trust and destination state before retrying.")
		return exitGeneric
	}
	if err = writeNativeSessionJSON(stdout, struct {
		Type    string                    `json:"type"`
		Results []*registry.InstallResult `json:"results"`
	}{"native-agent-installed", results}); err != nil {
		fmt.Fprintln(stderr, "Native installation may already have changed files; completion output failed. Inspect destination state before retrying.")
		return exitGeneric
	}
	return exitOK
}

func writeNativeSessionJSON(w io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return err
}

// Read exactly one bounded confirmation line. A terminal remains open after
// Enter; later input is never interpreted. Cancellation stops the command, not
// a borrowed reader: one blocked read goroutine may live until process exit.
func readNativeConsentLine(ctx context.Context, r io.Reader) (string, error) {
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		var raw [45]byte
		for i := range raw {
			n, err := r.Read(raw[i : i+1])
			if err != nil && !errors.Is(err, io.EOF) {
				done <- result{err: errors.Join(registry.ErrNativeLiveSourceIO, err)}
				return
			}
			if n == 1 && raw[i] == '\n' {
				if i == 43 || (i == 44 && raw[43] == '\r') {
					token := string(raw[:43])
					decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(token)
					if decodeErr == nil && len(decoded) == 32 {
						done <- result{token: token}
						return
					}
				}
				done <- result{err: registry.ErrNativeConsentInvalid}
				return
			}
			if n != 1 || err != nil {
				done <- result{err: registry.ErrNativeConsentInvalid}
				return
			}
		}
		done <- result{err: registry.ErrNativeConsentInvalid}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case v := <-done:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return v.token, v.err
	}
}

func nativePullFailure(w io.Writer, err error) int {
	// These SDK decisions predate the live CLI. Classify them only for this
	// selected native action, preserving legacy command exit contracts.
	if errors.Is(err, registry.ErrAgentEvidenceInvalid) || errors.Is(err, registry.ErrAgentEvidenceRequired) || errors.Is(err, registry.ErrPlanDrift) {
		err = errors.Join(registry.ErrNativeEvidenceInvalid, err)
	}
	if errors.Is(err, projectpolicy.ErrInvalid) || errors.Is(err, projectpolicy.ErrSelection) || errors.Is(err, projectpolicy.ErrUnsupported) {
		err = errors.Join(registry.ErrNativeEvidenceInvalid, err)
	}
	code := verify.ExitCode(err)
	// Do not print carrier, credential, JSON or filesystem errors. Even a
	// server-reflected credential must never enter the command's diagnostics.
	if errors.Is(err, registry.ErrAgentPublicationIncomplete) || errors.Is(err, registry.ErrNativePersistence) {
		code = exitGeneric
		fmt.Fprintln(w, "Native installation or trust persistence is uncertain; files or history may already have changed. Inspect state before retrying.")
	} else {
		fmt.Fprintln(w, "Native installation was not confirmed. Check the selected profile, signed evidence, history freshness and consent.")
	}
	return code
}
