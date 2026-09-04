package sim

// run.go executes one scenario and compares reality with the prediction.
//
// The comparison has three outcomes on purpose, not two. MATCH and CONFLICT are
// obvious. The third, UNCLAIMED, exists because a benchmark that scores an
// out-of-scope attack as a pass or a fail is lying either way: the honest record
// is "we ran it, here is what happened, and the model never promised anything".

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Execute runs one scenario end to end in its own throwaway world.
func Execute(skillctl, rootDir string, sc Scenario) ScenarioResult {
	res := ScenarioResult{Scenario: sc}

	root, err := os.MkdirTemp(rootDir, "sim-"+sc.ID+"-")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer os.RemoveAll(root)

	w, err := NewWorld(skillctl, root)
	if err != nil {
		res.Err = "world: " + err.Error()
		return res
	}

	// Key layout. The roles are keys, not people: what the trust plane sees is
	// which KEY signed what, and the cast only decides who holds them.
	reviewerKey := "publisher"
	if sc.P.Key != KeyShared {
		reviewerKey = "reviewer"
	}
	for _, k := range []string{"author", "publisher", "reviewer", "attacker"} {
		if err := w.Keygen(k); err != nil {
			res.Err = "keygen " + k + ": " + err.Error()
			return res
		}
	}
	skill := "simskill"
	if err := w.WriteSkill(skill); err != nil {
		res.Err = "skill: " + err.Error()
		return res
	}

	for i, st := range sc.Steps {
		sr := StepResult{Step: st}
		var out string
		var code int
		var aerr error

		switch st.Action.Kind {
		case ActPackSign:
			out, code, aerr = w.PackSign(skill, "author", "id:author@sim")
		case ActVerifySig:
			out, code, aerr = w.VerifySig(skill, "author")
		case ActAdmit:
			out, code, aerr = w.Admit(skill, "publisher", "id:publisher@sim")
		case ActAttest:
			out, code, aerr = w.Attest(skill, reviewerKey, "id:reviewer@sim", st.Action.Params["level"])
		case ActForgeAttest:
			// The forgery claims the reviewer's identity but is signed by a key
			// nobody pinned. Writing it must succeed; counting it must not.
			out, code, aerr = w.Attest(skill, "attacker", "id:reviewer@sim", "green")
		case ActPin:
			signers := map[string]string{}
			if sc.P.Key == KeySeparatePin {
				signers["id:reviewer@sim"] = reviewerKey
			}
			out, code, aerr = w.Pin("publisher", signers)
		case ActPull:
			out, code, aerr = w.Pull(skill)
		case ActVerify:
			out, code, aerr = w.Verify(skill)
		case ActRevoke:
			out, code, aerr = w.Revoke(skill, "publisher", "id:publisher@sim")
		case ActTamperTransit:
			if st.Action.Params["where"] == "registry" {
				aerr = w.TamperStoredBundle(skill)
			} else {
				aerr = w.TamperTransit(skill)
			}
			code = -1
		case ActTamperInstalled:
			aerr = w.TamperInstalled(skill)
			code = -1
		case ActForgeEnvelope:
			aerr = w.ForgeEnvelope(skill)
			code = -1
		case ActStripRevoke:
			aerr = w.StripRevoke(skill)
			code = -1
		case ActRelabelRevoke:
			aerr = w.RelabelRevoke(skill)
			code = -1
		default:
			aerr = fmt.Errorf("unhandled action %s", st.Action.Kind)
		}

		if aerr != nil {
			sr.Stderr = aerr.Error()
			sr.Outcome = Refuse
			res.Steps = append(res.Steps, sr)
			res.Verdicts = append(res.Verdicts, VerdictSkipped)
			continue
		}

		sr.ExitCode = code
		sr.Stdout = out
		sr.Gate = parseGate(out)
		switch {
		case code < 0:
			sr.Outcome = NoEffect // an adversary mutation, not a command
		case code == 0:
			sr.Outcome = Accept
		default:
			sr.Outcome = Refuse
		}
		// A pull that "succeeds" while refusing every bundle is a refusal, not an
		// acceptance. The exit code alone would score this wrong, which is exactly
		// the trap a benchmark must not fall into.
		if st.Action.Kind == ActPull && sr.Outcome == Accept && strings.Contains(out, "NOT installing") {
			sr.Outcome = Refuse
		}

		res.Steps = append(res.Steps, sr)
		res.Verdicts = append(res.Verdicts, judge(st.Expect, sr))
		res.Violations = append(res.Violations, checkInvariants(sc, i, sr, w)...)
	}
	return res
}

// judge compares one prediction with one observation.
func judge(e Expectation, r StepResult) Verdict {
	if !e.Claimed {
		return VerdictUnclaimed
	}
	if e.Outcome != r.Outcome {
		return VerdictConflict
	}
	if e.Exit >= 0 && r.ExitCode >= 0 && e.Exit != r.ExitCode {
		return VerdictConflict
	}
	if e.Gate != "" && !strings.Contains(r.Stdout, e.Gate) {
		return VerdictConflict
	}
	return VerdictMatch
}

// checkInvariants asserts the properties that hold over the whole run. This is
// where the two bugs of 2026-09-04 would have been caught: both produced a
// plausible exit code and an impossible STATE.
func checkInvariants(sc Scenario, i int, r StepResult, w *World) []InvariantViolation {
	var v []InvariantViolation
	b := w.bundles["simskill"]
	if b == nil {
		return nil
	}

	// INV-2: once a revoke is visible, nothing may install that digest again. The
	// strip attack legitimately removes the revoke, so it is excluded: there the
	// registry is no longer showing what was published, and that limit is recorded
	// as UNCLAIMED rather than hidden here.
	if r.Step.Action.Kind == ActPull && b.revoked && sc.P.Adv != AdvStripRevoke && r.Outcome == Accept {
		v = append(v, InvariantViolation{InvRevocation, i,
			"a pull staged a digest that carries a signed revoke"})
	}

	// INV-3: no install without a qualifying attestation from a pinned signer.
	if r.Step.Action.Kind == ActPull && r.Outcome == Accept {
		switch {
		case sc.P.Gov == GovNone:
			v = append(v, InvariantViolation{InvGovernance, i,
				"a pull installed with no attestation at all"})
		case sc.P.Gov == GovYellow:
			v = append(v, InvariantViolation{InvGovernance, i,
				"a pull installed on a yellow attestation against a green floor"})
		case sc.P.Key == KeySeparateOpen:
			v = append(v, InvariantViolation{InvGovernance, i,
				"a pull installed on an attestation whose signer was never pinned"})
		}
	}

	// INV-1: an artifact that no longer hashes to the signed digest must never be
	// installed. A stolen key is excluded: there the signature is genuine and the
	// bytes ARE what the key signed, which is the limit, not a violation.
	if r.Step.Action.Kind == ActPull && sc.P.Adv == AdvStoredBundle && r.Outcome == Accept {
		v = append(v, InvariantViolation{InvIntegrity, i,
			"a pull installed bytes that do not match the signed digest"})
	}

	// INV-4: a refusal has to be legible. A silent non-zero exit is nearly as bad
	// as a wrong one, because the operator cannot act on it.
	if r.Outcome == Refuse && strings.TrimSpace(r.Stdout+r.Stderr) == "" {
		v = append(v, InvariantViolation{InvLoudRefusal, i,
			"the step refused without printing a reason"})
	}
	return v
}

func parseGate(out string) string {
	m := gateLine.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return "gate " + m[1]
}

// WriteTrace dumps a scenario's command log next to the report, so a CONFLICT can
// be reproduced by hand rather than argued about.
func WriteTrace(dir, id string, lines []string) error {
	return os.WriteFile(filepath.Join(dir, id+".trace"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
