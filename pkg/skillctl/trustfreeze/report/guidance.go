package report

// The guidance for the reader of a report page (FR-0472, requirement 4),
// constant per bundle kind and addressed to somebody who does not know
// skillctl. It lives here and not in the projection: a new field would make
// trust-freeze/report/v1 two different documents, and UnmarshalCanonicalFile
// refuses an unknown field, so every strict reader of an older report would
// break on it.
//
// Two rules the texts follow, and every later edit has to follow as well. No
// sentence claims that anything is valid: the page shows what the bundle
// records and names the command that evaluates it. And no sentence names a
// number the renderer does not read out of the bundle.
//
// The check command of a capture takes no --trusted-key on purpose: a capture
// carries no signature, and verify says so of its own accord.

import "github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"

// htmlGuidanceByKind is the guidance per bundle kind.
var htmlGuidanceByKind = map[trustfreeze.Kind]htmlGuidance{
	trustfreeze.KindCapture:  guidanceCapture,
	trustfreeze.KindBaseline: guidanceBaseline,
	trustfreeze.KindDiff:     guidanceDiff,
}

var guidanceCapture = htmlGuidance{
	What: "A record of what one machine looked like at one moment. It was collected by " +
		"reading only: nothing on the host was written, and nothing was elevated to collect it.",
	Answers: "Which programs, accounts, rules, services and network facts this host carried " +
		"at the time named in the header, and, wherever a probe could not read something, why not.",
	DoesNotAnswer: "Whether any of this is acceptable. A capture is evidence, not a verdict. " +
		"It is also not a baseline: nobody has approved it, and it carries no signature. And this page " +
		"does not verify anything; it shows what the bundle says.",
	Next: "If this is the state you want to hold the host to, have it approved by a person " +
		"who is accountable for it:",
	NextCommand: "skillctl trust-freeze baseline approve --capture <bundle> --output <baseline> \\\n" +
		"  --reviewer <who> --change-id <ticket> --reason <why> --key <private key>",
	CheckLabel:   "To check the bundle behind this page (integrity of every file against the manifest):",
	CheckCommand: "skillctl trust-freeze verify --bundle <bundle>",
}

var guidanceBaseline = htmlGuidance{
	What: "An approved state. Somebody named in the header accepted the capture this baseline " +
		"was made from, gave a reason and a change id, and signed the result.",
	Answers: "What was accepted, by whom, when, and for which capture. The capture_digest " +
		"below ties this approval to exactly one capture; no other capture can be substituted for it.",
	DoesNotAnswer: "Whether the signature is valid, and whether the approver was entitled " +
		"to approve. This page shows the signature block as the bundle records it. Validity is a question for " +
		"the verifier, with a key you trust, and this page is not that verifier. Whether the approver was " +
		"entitled is a question for your process.",
	Next:         "Keep it, and compare later captures of the same host against it:",
	NextCommand:  "skillctl trust-freeze diff --baseline <baseline> --current <capture> --trusted-key <public key>",
	CheckLabel:   "To check the bundle behind this page (integrity, signature and trust, offline):",
	CheckCommand: "skillctl trust-freeze verify --bundle <bundle> --trusted-key <public key>",
	Note: "The key must be one you obtained out of band. A signature verifies against the key you hand it; it " +
		"cannot tell you that the key belongs to the right person.",
}

var guidanceDiff = htmlGuidance{
	What: "The difference between an approved baseline and a later capture of the same " +
		"subject, as one deterministic document. The same two bundles always produce the same bytes and the " +
		"same diff_digest.",
	Answers: "What changed, and at which severity the policy named in this document rated each " +
		"change. Entries marked coverage_increased are the opposite of drift: there the later capture could " +
		"see more than the baseline could, so the difference is in the question, not in the host.",
	DoesNotAnswer: "Why something changed, and whether the change was authorised. It also " +
		"does not re-verify the two bundles: both were verified when this diff was produced, and a diff is " +
		"never produced over a baseline that failed verification.",
	Next: "Read the entries at and above the severity your process cares about, decide " +
		"whether the change was intended, and then either act on the host or approve the new state as the new " +
		"baseline. Approving is a deliberate step: there is no automatic baseline update.",
	NextCommand:  "skillctl trust-freeze diff --baseline <baseline> --current <capture> --trusted-key <public key>",
	CheckLabel:   "To reproduce this document from the two bundles it names:",
	CheckCommand: "skillctl trust-freeze diff --baseline <baseline> --current <capture> --trusted-key <public key>",
	Note: "Two runs of that command over unchanged bundles give the same diff_digest as this page. A different " +
		"digest means a different input, not a different mood.",
}
