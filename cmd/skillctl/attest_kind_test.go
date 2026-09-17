package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// The governance minimum for agents (SPEC-0432 §5.1, AC-11). An agent executes
// where nobody is watching, a skill only instructs, so an agent carries at least
// yellow and the tool refuses rather than leaving it to a human at the desk.

func TestAttestLevelAllowed(t *testing.T) {
	for _, tc := range []struct {
		kind, level string
		wantErr     bool
	}{
		{skillbundle.KindAgent, "green", true}, // the whole point
		{skillbundle.KindAgent, "yellow", false},
		{skillbundle.KindAgent, "red", false}, // red is refused at pull, not here
		{skillbundle.KindSkill, "green", false},
		{"", "green", false}, // no --kind means skill, unchanged behaviour
	} {
		err := attestLevelAllowed(tc.kind, tc.level)
		if (err != nil) != tc.wantErr {
			t.Errorf("attestLevelAllowed(%q, %q) error = %v, want error %v",
				tc.kind, tc.level, err, tc.wantErr)
		}
	}
}

// TestAttestRefusesGreenAgent: the refusal reaches the caller with a non-zero
// code and a message naming both levels, and it happens before any key is read
// (the test passes no key path at all, so reaching the key loader would fail
// with a different message).
func TestAttestRefusesGreenAgent(t *testing.T) {
	var out, errBuf bytes.Buffer
	rc := runPublishAttest(&out, &errBuf, publishAttestArgs{
		name: "release-agent", version: "1.0.0",
		kind: skillbundle.KindAgent, level: "green",
	})
	if rc == 0 {
		t.Fatal("attesting a green agent returned 0")
	}
	msg := errBuf.String()
	for _, want := range []string{"yellow", "green", "nothing attested"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not name %q", msg, want)
		}
	}
	if strings.Contains(msg, "load key") {
		t.Errorf("the refusal ran too late, it already touched the key: %q", msg)
	}
	if out.Len() != 0 {
		t.Errorf("a refusal wrote to stdout: %q", out.String())
	}
}

// TestAttestSkillGreenStillReaches: the counter-probe. A green SKILL must not be
// stopped by the new rule; it fails later for an unrelated reason (no key), and
// that difference is exactly what is asserted.
func TestAttestSkillGreenStillReaches(t *testing.T) {
	var out, errBuf bytes.Buffer
	runPublishAttest(&out, &errBuf, publishAttestArgs{
		name: "some-skill", version: "1.0.0",
		kind: skillbundle.KindSkill, level: "green",
	})
	if strings.Contains(errBuf.String(), "nothing attested") {
		t.Errorf("a green skill was stopped by the agent minimum: %q", errBuf.String())
	}
}
