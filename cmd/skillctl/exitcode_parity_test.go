package main

// Befund 1.4 (Welle 1): the exit numbers cmd/skillctl allocates as local
// consts are registered in pkg/skillctl/exitcode so TestCodes_NumberTheme
// sees every cross-surface number claim. This guard fails the moment a local
// const and its registry row drift, same pattern as
// TestExitCode_VerifyRegistryParity in the exitcode package.

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
)

func TestExitConsts_RegistryParity(t *testing.T) {
	cases := []struct {
		name  string
		local int // const in cmd/skillctl
		reg   int // exitcode registry Number
	}{
		{"agentid_expired", exitAgentIDExpired, exitcode.AgentIDExpired.Number},
		{"pin need_priv_msg", pinExitNeedPrivMsg, exitcode.PinNeedPrivMsg.Number},
		{"translog not_included", exitTranslogNotIncluded, exitcode.TranslogNotIncluded.Number},
		{"translog split_view", exitTranslogSplitView, exitcode.TranslogSplitView.Number},
		{"translog rewrite", exitTranslogRewrite, exitcode.TranslogRewrite.Number},
	}
	for _, c := range cases {
		if c.local != c.reg {
			t.Errorf("exit-code drift for %q: cmd/skillctl const=%d, exitcode registry=%d: update both", c.name, c.local, c.reg)
		}
	}
}
