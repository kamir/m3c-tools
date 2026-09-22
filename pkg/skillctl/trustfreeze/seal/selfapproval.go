package seal

import "strings"

// Warning is a non-fatal finding of Seal or Verify.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Warning codes.
const (
	// CodeSelfApprovalSameDevice: the approving device is the captured device.
	CodeSelfApprovalSameDevice = "self_approval_same_device"
	// CodeSelfApprovalSamePerson: the reviewer is the capture actor.
	CodeSelfApprovalSamePerson = "self_approval_same_person"
	// CodeCaptureIncomplete: the approved capture has completeness gaps.
	CodeCaptureIncomplete = "capture_incomplete"
	// CodeSelfApprovalDeviceUnknown: the captured or the approving device is
	// unknown, so the same-device check could not be evaluated.
	CodeSelfApprovalDeviceUnknown = "self_approval_device_unknown"
)

// CheckSelfApproval is the deterministic self-approval seam (SPEC-0470
// TF05-R7, TF05-AC6). It is pure: no clock, no IO.
//
// Three conditions are detected:
//
//	device unknown: captureSubjectID or approverSubjectID is empty, so the
//	                same-device check cannot be evaluated. It is a finding
//	                of its own, so block mode fails closed instead of
//	                passing a check it could not run.
//	same device:    captureSubjectID and approverSubjectID are both
//	                non-empty and equal. Both are trustfreeze.SubjectID
//	                values, so the comparison is exact.
//	same person:    a.Identities.CaptureActor is non-empty and equals
//	                a.Reviewer or a.Identities.ReviewerID, compared after
//	                trimming and without regard to letter case.
//
// The mode decides the outcome: allow returns no findings; warn returns the
// findings with blocked false; block returns them with blocked true. The zero
// mode behaves as warn, an unknown mode as block.
func CheckSelfApproval(a Approval, captureSubjectID, approverSubjectID string, mode SelfApprovalMode) (findings []Warning, blocked bool) {
	m := mode.effective()
	if m == SelfApprovalAllow {
		return nil, false
	}
	switch {
	case captureSubjectID == "" || approverSubjectID == "":
		findings = append(findings, Warning{
			Code:    CodeSelfApprovalDeviceUnknown,
			Message: "the same-device check could not be evaluated: the captured or the approving device is unknown",
		})
	case captureSubjectID == approverSubjectID:
		findings = append(findings, Warning{
			Code:    CodeSelfApprovalSameDevice,
			Message: "the approving device is the captured device (" + captureSubjectID + ")",
		})
	}
	if actor := strings.TrimSpace(a.Identities.CaptureActor); actor != "" &&
		(sameIdentity(actor, a.Reviewer) || sameIdentity(actor, a.Identities.ReviewerID)) {
		findings = append(findings, Warning{
			Code:    CodeSelfApprovalSamePerson,
			Message: "the reviewer is the capture actor",
		})
	}
	return findings, m == SelfApprovalBlock && len(findings) > 0
}

func sameIdentity(a, b string) bool {
	b = strings.TrimSpace(b)
	return b != "" && strings.EqualFold(strings.TrimSpace(a), b)
}
