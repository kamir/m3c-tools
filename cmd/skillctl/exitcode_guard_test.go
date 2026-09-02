package main

// SPEC-0251 §5 — exit-code single source of truth, cmd side.
//
// The unexported exit consts in cmd/skillctl (signing + guard-path surfaces)
// must stay in lockstep with the exitcode registry. An external _test package
// can't see these unexported consts, so this in-package guard covers them.
// Drift == red CI.

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
)

func TestCmdExitConsts_RegistryParity(t *testing.T) {
	cases := []struct {
		name string
		got  int
		reg  int
	}{
		{"sign_invalid", exitSigInval, exitcode.SignInvalid.Number},
		{"sidechannel_denied", exitSidechannelDenied, exitcode.GuardPathSidechannelDenied.Number},
	}
	for _, c := range cases {
		if c.got != c.reg {
			t.Errorf("cmd exit const %q=%d drifted from exitcode registry=%d", c.name, c.got, c.reg)
		}
	}
}
