package seal

import (
	"strings"
	"testing"
)

// TF05-AC6, TF05-R7: MC/DC style table for CheckSelfApproval.
//
// Decision: detected = deviceUnknown || sameDevice || samePerson, where
//
//	deviceUnknown = capture == "" || approver == ""
//	sameDevice    = capture != "" && approver != "" && capture == approver
//	samePerson    = actor != "" && (actor ~ reviewer || actor ~ reviewer_id)
//
// ("~" is equality after trimming, ignoring case) and
// blocked = detected && mode == block. An unknown device is a finding of its
// own: block mode must not pass a check it could not evaluate (fail closed).
// Each row pair below differs in one condition and flips the outcome, which
// shows that condition's independent effect. Detection rows run in warn mode,
// where findings are visible.
func TestCheckSelfApprovalMCDC(t *testing.T) {
	const (
		devA = "device/aaaaaaaaaaaaaaaa"
		devB = "device/bbbbbbbbbbbbbbbb"
	)
	cases := []struct {
		name       string
		capture    string
		approver   string
		actor      string
		reviewer   string
		reviewerID string
		mode       SelfApprovalMode
		wantCodes  string
		wantBlock  bool
	}{
		// Reference row: nothing matches.
		{"none", devA, devB, "carol", "bob", "bob", SelfApprovalWarn, "", false},

		// sameDevice: the three conditions.
		{"device-equal", devA, devA, "carol", "bob", "bob", SelfApprovalWarn, CodeSelfApprovalSameDevice, false},
		{"device-differs", devA, devB, "carol", "bob", "bob", SelfApprovalWarn, "", false},
		{"device-capture-empty", "", devA, "carol", "bob", "bob", SelfApprovalWarn, CodeSelfApprovalDeviceUnknown, false},
		{"device-approver-empty", devA, "", "carol", "bob", "bob", SelfApprovalWarn, CodeSelfApprovalDeviceUnknown, false},
		{"device-both-empty-is-unknown", "", "", "carol", "bob", "bob", SelfApprovalWarn, CodeSelfApprovalDeviceUnknown, false},

		// samePerson: actor present, matches reviewer or reviewer_id.
		{"person-matches-reviewer", devA, devB, "alice", "alice", "bob", SelfApprovalWarn, CodeSelfApprovalSamePerson, false},
		{"person-matches-reviewer-id", devA, devB, "alice", "bob", "alice", SelfApprovalWarn, CodeSelfApprovalSamePerson, false},
		{"person-matches-neither", devA, devB, "alice", "bob", "bob", SelfApprovalWarn, "", false},
		{"person-actor-empty", devA, devB, "", "", "", SelfApprovalWarn, "", false},
		{"person-case-and-space-insensitive", devA, devB, " Alice\t", "alice", "bob", SelfApprovalWarn, CodeSelfApprovalSamePerson, false},
		{"person-prefix-is-no-match", devA, devB, "alice", "alice2", "alice2", SelfApprovalWarn, "", false},

		// OR of the two: both at once gives both findings, device first.
		{"both", devA, devA, "alice", "alice", "alice", SelfApprovalWarn, CodeSelfApprovalSameDevice + "," + CodeSelfApprovalSamePerson, false},

		// Mode: the same detected input under every mode.
		{"mode-allow", devA, devA, "alice", "alice", "alice", SelfApprovalAllow, "", false},
		{"mode-warn", devA, devA, "alice", "bob", "bob", SelfApprovalWarn, CodeSelfApprovalSameDevice, false},
		{"mode-block", devA, devA, "alice", "bob", "bob", SelfApprovalBlock, CodeSelfApprovalSameDevice, true},
		{"mode-block-person", devA, devB, "alice", "alice", "bob", SelfApprovalBlock, CodeSelfApprovalSamePerson, true},
		{"mode-default-is-warn", devA, devA, "alice", "bob", "bob", "", CodeSelfApprovalSameDevice, false},
		{"mode-unknown-fails-closed", devA, devA, "alice", "bob", "bob", "sometimes", CodeSelfApprovalSameDevice, true},

		// Block mode without a detection does not block.
		{"block-mode-independent", devA, devB, "carol", "bob", "bob", SelfApprovalBlock, "", false},

		// Block mode with an unknown device fails closed (TF05-AC6): the
		// same-device check could not be evaluated, so it cannot pass.
		{"block-approver-empty", devA, "", "carol", "bob", "bob", SelfApprovalBlock, CodeSelfApprovalDeviceUnknown, true},
		{"block-capture-empty", "", devB, "carol", "bob", "bob", SelfApprovalBlock, CodeSelfApprovalDeviceUnknown, true},
		{"allow-approver-empty", devA, "", "carol", "bob", "bob", SelfApprovalAllow, "", false},
		{"unknown-and-same-person", devA, "", "alice", "alice", "bob", SelfApprovalWarn, CodeSelfApprovalDeviceUnknown + "," + CodeSelfApprovalSamePerson, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := fixedApproval()
			a.Reviewer = tc.reviewer
			a.Identities.ReviewerID = tc.reviewerID
			a.Identities.CaptureActor = tc.actor
			findings, blocked := CheckSelfApproval(a, tc.capture, tc.approver, tc.mode)
			codes := make([]string, 0, len(findings))
			for _, f := range findings {
				codes = append(codes, f.Code)
				if f.Message == "" {
					t.Fatalf("finding %s without message", f.Code)
				}
			}
			if got := strings.Join(codes, ","); got != tc.wantCodes {
				t.Fatalf("codes = %q, want %q", got, tc.wantCodes)
			}
			if blocked != tc.wantBlock {
				t.Fatalf("blocked = %v, want %v", blocked, tc.wantBlock)
			}
		})
	}
}

// The check is pure: repeated calls give identical results.
func TestCheckSelfApprovalDeterministic(t *testing.T) {
	a := fixedApproval()
	a.Identities.CaptureActor = "bob"
	f1, b1 := CheckSelfApproval(a, "device/aaaaaaaaaaaaaaaa", "device/aaaaaaaaaaaaaaaa", SelfApprovalBlock)
	for i := 0; i < 20; i++ {
		f2, b2 := CheckSelfApproval(a, "device/aaaaaaaaaaaaaaaa", "device/aaaaaaaaaaaaaaaa", SelfApprovalBlock)
		if b1 != b2 || len(f1) != len(f2) || f1[0] != f2[0] || f1[1] != f2[1] {
			t.Fatal("CheckSelfApproval is not deterministic")
		}
	}
}
