package bodyscan

import "regexp"

// Injection rules (SPEC-0246 §4.2) — all RED. These detect prose that tries to
// override the agent's instructions or terminate its system prompt.
var (
	// "ignore (the|all)? (previous|above) instructions" — tolerates a few
	// filler words ("all of the", "any of your") between the verb and the
	// "previous/above" qualifier, and between the qualifier and the noun, so
	// hard-wrapped or padded variants still trip.
	reInjIgnore = regexp.MustCompile(`(?i)\bignore\b(?:\s+\w+){0,4}?\s+(?:previous|above|prior|preceding|earlier)(?:\s+\w+){0,2}?\s+(?:instructions?|prompts?|directions?|context|guidelines?|rules?)\b`)

	// "disregard (your|the)? system prompt"
	reInjDisregard = regexp.MustCompile(`(?i)\bdisregard\s+(?:your\s+|the\s+|all\s+|any\s+)?(?:system\s+prompt|previous\s+instructions?|above\s+instructions?|prior\s+instructions?|instructions?|guidelines?|rules?)\b`)

	// "forget (everything|all|your) ... instructions/prompt"
	reInjForget = regexp.MustCompile(`(?i)\bforget\s+(?:everything|all|your|the|any|previous)\b[^.\n]{0,40}?\b(?:instructions?|prompt|context|rules?|guidelines?)\b`)

	// "you are now ..." role reset.
	reInjYouAreNow = regexp.MustCompile(`(?i)\byou\s+are\s+now\b`)

	// Role-override: act/behave/pretend as ... admin/root/developer mode.
	reInjRoleOverride = regexp.MustCompile(`(?i)\b(?:act|behave|respond|operate|pretend)\s+(?:as|like)\b[^.\n]{0,40}?\b(?:admin(?:istrator)?|root|developer\s+mode|dev\s+mode|sudo|superuser|jailbreak|DAN|unrestricted)\b`)

	// "enable/enter developer mode" / "developer mode enabled".
	reInjDevMode = regexp.MustCompile(`(?i)\b(?:enable|enter|activate|switch\s+to)\s+(?:the\s+)?(?:developer|dev|god|admin|root|debug)\s+mode\b|\bdeveloper\s+mode\s+(?:enabled|on|activated)\b`)

	// Instruction-termination markers: [/INST], [INST], [SYS], <|im_end|>,
	// "end of system prompt", "### end of instructions".
	reInjTermMarker = regexp.MustCompile(`(?i)\[/?(?:INST|SYS|SYSTEM)\]|<\|?(?:im_start|im_end|endoftext|system)\|?>|\bend\s+of\s+(?:the\s+)?(?:system\s+prompt|system\s+instructions?|instructions?|prompt)\b`)
)

func init() {
	register(
		Rule{
			ID:       "INJ-001",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjIgnore,
			Message:  "instruction-override: tells the agent to ignore previous/above instructions",
		},
		Rule{
			ID:       "INJ-002",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjDisregard,
			Message:  "instruction-override: tells the agent to disregard its system prompt/instructions",
		},
		Rule{
			ID:       "INJ-003",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjForget,
			Message:  "instruction-override: tells the agent to forget its instructions/context",
		},
		Rule{
			ID:       "INJ-004",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjYouAreNow,
			Message:  "role-reset: \"you are now …\" attempts to redefine the agent's identity",
		},
		Rule{
			ID:       "INJ-005",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjRoleOverride,
			Message:  "role-override: instructs the agent to act as admin/root/developer-mode/jailbreak",
		},
		Rule{
			ID:       "INJ-006",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjDevMode,
			Message:  "role-override: requests a privileged developer/god/debug mode",
		},
		Rule{
			ID:       "INJ-007",
			Category: CategoryInjection,
			Verdict:  VerdictRed,
			Pattern:  reInjTermMarker,
			Message:  "instruction-termination: embeds a system/instruction boundary marker to smuggle a new prompt",
		},
	)
}
