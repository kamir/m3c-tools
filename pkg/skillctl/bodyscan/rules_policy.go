package bodyscan

import "regexp"

// Policy-subversion rules (SPEC-0246 §4.2) — all YELLOW. These detect prose
// that steers the agent around safety/quality gates: disabling tests, skipping
// review, bypassing gates, dependency steering, or destructive ops without
// confirmation.
var (
	// "disable/skip/turn off (the)? tests".
	rePolDisableTests = regexp.MustCompile(`(?i)\b(?:disable|skip|turn\s+off|bypass|ignore|don'?t\s+run|do\s+not\s+run|omit)\s+(?:the\s+|all\s+|any\s+)?tests?\b`)

	// "skip (the)? review" / "skip code review".
	rePolSkipReview = regexp.MustCompile(`(?i)\bskip\s+(?:the\s+)?(?:code\s+)?review\b|\bwithout\s+(?:a\s+|any\s+)?review\b|\bdon'?t\s+(?:wait\s+for|request)\s+(?:a\s+)?review\b`)

	// "bypass the gate" / "bypass the quality gate".
	rePolBypassGate = regexp.MustCompile(`(?i)\bbypass\s+(?:the\s+)?(?:quality\s+|ci\s+|security\s+|release\s+)?gates?\b|\bcircumvent\s+(?:the\s+)?[\w\s]{0,20}?gates?\b`)

	// Dependency steering: "prefer/use (package|library|dependency) X" framed as
	// an override. Conservative: requires the steering verb + a dep noun.
	rePolDepSteer = regexp.MustCompile(`(?i)\b(?:always\s+)?(?:prefer|use|install|switch\s+to|replace\s+\w+\s+with)\s+(?:the\s+)?(?:package|library|dependency|module|npm\s+package|pip\s+package)\b`)

	// Destructive op without confirmation: "rm/delete ... without/no confirm".
	rePolRmNoConfirm = regexp.MustCompile(`(?i)\b(?:rm|delete|remove|wipe|purge|drop)\b[^.\n]{0,60}?\b(?:without|no|skip(?:ping)?|bypass(?:ing)?)\s+(?:any\s+|a\s+)?(?:confirm(?:ation)?|prompt|approval|asking|warning)\b`)

	// "--force" / "--no-verify" / "--yes" / "-f" destructive flag steering.
	rePolForceFlags = regexp.MustCompile(`(?:--force\b|--no-verify\b|--no-confirm\b|--yes\b|--assume-yes\b|\bgit\s+push\s+(?:--force|-f)\b)`)
)

func init() {
	register(
		Rule{
			ID:       "POL-001",
			Category: CategoryPolicySubvert,
			Verdict:  VerdictYellow,
			Pattern:  rePolDisableTests,
			Message:  "policy-subversion: instructs disabling/skipping tests",
		},
		Rule{
			ID:       "POL-002",
			Category: CategoryPolicySubvert,
			Verdict:  VerdictYellow,
			Pattern:  rePolSkipReview,
			Message:  "policy-subversion: instructs skipping code review",
		},
		Rule{
			ID:       "POL-003",
			Category: CategoryPolicySubvert,
			Verdict:  VerdictYellow,
			Pattern:  rePolBypassGate,
			Message:  "policy-subversion: instructs bypassing a quality/CI/security gate",
		},
		Rule{
			ID:       "POL-004",
			Category: CategoryPolicySubvert,
			Verdict:  VerdictYellow,
			Pattern:  rePolDepSteer,
			Message:  "policy-subversion: dependency steering — pushes a specific package/library",
		},
		Rule{
			ID:       "POL-005",
			Category: CategoryPolicySubvert,
			Verdict:  VerdictYellow,
			Pattern:  rePolRmNoConfirm,
			Message:  "policy-subversion: destructive op (rm/delete) without confirmation",
		},
		Rule{
			ID:       "POL-006",
			Category: CategoryPolicySubvert,
			Verdict:  VerdictYellow,
			Pattern:  rePolForceFlags,
			Message:  "policy-subversion: force/no-verify/no-confirm flag bypasses a safety check",
		},
	)
}
