package main

import (
	"errors"
	"flag"
	"os"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
)

var errNativeProfileUsage = errors.New("native Enterprise profile flags require --enterprise-profile")

// nativeEnterprisePreflight consumes explicit operator intent before any legacy
// credential, signer, backend or install-state resolution. A valid native
// profile is diagnostic configuration, never permission to mutate without a
// durable native trust session.
func nativeEnterprisePreflight(fs *flag.FlagSet, path, pin, home, selector string) error {
	selected, related := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "enterprise-profile":
			selected = true
		case "enterprise-profile-sha256", "home":
			related = true
		}
	})
	if !selected {
		if related {
			return errNativeProfileUsage
		}
		return nil
	}
	if path == "" {
		return projectpolicy.ErrInvalid
	}
	cwd, err := os.Getwd()
	if err != nil {
		return projectpolicy.ErrSelection
	}
	if home == "" {
		home, err = os.UserHomeDir()
		if err != nil {
			return projectpolicy.ErrSelection
		}
	}
	var policy *projectpolicy.NativePolicy
	if pin != "" {
		policy, err = projectpolicy.LoadNativePinned(path, pin, cwd, home)
	} else {
		policy, err = projectpolicy.LoadNative(path, cwd, home)
	}
	if err != nil {
		return err
	}
	if err = policy.ValidateSelection(cwd, home, selector); err != nil {
		return err
	}
	return artifact.RejectNativeEnterpriseMutation(policy.Intent())
}
