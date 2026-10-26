package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"io"
	"time"
)

func runNativeSkillPull(ctx context.Context, input io.Reader, stdout, stderr io.Writer, policy *projectpolicy.NativePolicy, digest string) (code int) {
	if ctx == nil || input == nil || stdout == nil || stderr == nil {
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, registry.TokenTTL)
	defer cancel()
	session, err := policy.BeginER1SkillInstall(ctx, digest)
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
		Type      string                               `json:"type"`
		Rows      []registry.NativeSkillInstallPlanRow `json:"rows"`
		Token     string                               `json:"token"`
		ExpiresAt time.Time                            `json:"expires_at"`
	}{"native-skill-plan", plan.Rows, plan.Token, plan.ExpiresAt}); err != nil {
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
	}{"native-skill-installed", results}); err != nil {
		fmt.Fprintln(stderr, "Native installation may already have changed files; completion output failed. Inspect destination state before retrying.")
		return exitGeneric
	}
	return exitOK
}
