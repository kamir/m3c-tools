package main

// scenarios.go — the demo script.
//
// LIVE scenarios (S1, S2A, S5) run the REAL skillctl and assert its REAL exit
// codes. PARTIAL / ROADMAP panels render the story + the closest-built-surface
// note and run NOTHING — per the non-negotiable honesty rule, we never dress a
// simulated output as a real skillctl verdict.
//
// Exit codes below were verified against the skillctl source + observed live:
//   S1  verify --bundle : 0 (clean)      → 10 (digest mismatch after poison)
//   S2A verify-hook     : 0 (gate allows) → 2 (gate BLOCKS the tampered load)
//       verify --all    : per-skill trust verdict 10 (digest mismatch) → quarantined
//   S5  audit cleanup   : 0 (dry-run + token) → 2 (confirm REFUSES on drift)
//       The two-step confirm returns exitUsage (2) when the token fails
//       re-verification (drift/expiry/tamper) — a precondition refusal, matching
//       the G-23 contract in DEMO-skill-trust-scenarios.md (S5).

// Scenario is one card in the demo.
type Scenario struct {
	ID      string
	Title   string
	Tier    string // LIVE | PARTIAL | ROADMAP
	SVG     string
	Story   string
	Without string
	ExitDoc string          // human-readable expected-exit summary shown on the card
	Roadmap string          // closest-built-surface / roadmap note (PARTIAL/ROADMAP only)
	Run     func(d *Driver) `json:"-"` // nil for pure roadmap panels; not serialisable
}

// Scenarios is the ordered demo deck.
func Scenarios() []Scenario {
	return []Scenario{
		{
			ID:      "S1",
			Title:   "Poisoned script → the signature prevents the run",
			Tier:    "LIVE",
			SVG:     "scenario-1-poisoned-script.svg",
			Story:   "A KuP skill ships as a signed .skb bundle. An attacker (tampered mirror / supply-chain) edits the script inside it to exfiltrate ~/.ssh. The victim verifies the bundle offline against a pinned key — no network, no trust in the publisher's server.",
			Without: "curl … | bash, or copy the skill folder in — the poisoned script simply runs. The exfil executes.",
			ExitDoc: "0 (clean) → 10 (digest mismatch)",
			Run:     runS1,
		},
		{
			ID:      "S2A",
			Title:   "Post-install tamper → re-verify catches it",
			Tier:    "LIVE",
			SVG:     "scenario-2-agent-manipulation.svg",
			Story:   "kup-onboarding-greeting is installed and green. An agent (or a compromised author) edits the installed skill on disk to smuggle a prompt-injection. The load-time gate re-runs the trust chain before Claude Code can load it.",
			Without: "The edit is invisible — no digest check, no gate. Claude loads the injected instructions and acts on them.",
			ExitDoc: "verify-hook 0 → 2 (gate BLOCKS); verify --all verdict 10 (digest mismatch) → quarantined",
			Run:     runS2A,
		},
		{
			ID:      "S5",
			Title:   "Reversible governance / no-force (drift refuses)",
			Tier:    "LIVE",
			SVG:     "scenario-5-reversible-governance.svg",
			Story:   "The dangerous ops aren't only the skills — a cache cleanup can itself be weaponised or fat-fingered. skillctl's own destructive op is a G-23 two-step: a signed dry-run plan, then a confirm that RE-CHECKS the live affected-set. If the set drifted, it refuses. There is no --force.",
			Without: "A one-shot `--force delete`: no plan, no re-check, no audit trail, no undo.",
			ExitDoc: "0 (dry-run + signed token) → 2 (confirm REFUSES on drift)",
			Run:     runS5,
		},
		{
			ID:      "S2BC",
			Title:   "Runtime envelope violation + fleet kill (roadmap)",
			Tier:    "ROADMAP",
			SVG:     "scenario-2-agent-manipulation.svg",
			Story:   "A manipulated skill that still loads tries an out-of-envelope egress to attacker.example; after detection it is revoked fleet-wide.",
			ExitDoc: "envelope 32 · revoke 17 (roadmap)",
			Roadmap: "Closest built surface: the capability gateway is BUILT as a Python reference (pkg/skillgate, SPEC-0202) and `skillctl revoke <digest> --reason key-compromise` is a real subcommand (needs a registry, so it is not in this offline demo). The Go-native OS-level cage is FR-0044 (PENDING). We show the block point, we do NOT fake the runtime exit 32.",
		},
		{
			ID:      "S3",
			Title:   "Fleet kill-switch under live compromise",
			Tier:    "PARTIAL",
			SVG:     "scenario-3-fleet-kill-switch.svg",
			Story:   "Hosts A and B run a skill that turns out to be backdoored. A signed revocation HEAD must reach every host — including one with its network cable pulled — and fail closed.",
			Without: "IAM/admin revoke works only online; an offline host silently keeps running the backdoor.",
			ExitDoc: "17 (revoked) / 22 (offline fail-closed)",
			Roadmap: "Closest built surface: `skillctl revoke` runs live against a registry, and the OFFLINE freshness contract IS built — `verify --bundle --revocations/--emergency` returns exit 17 (revoked) and exit 22 (stale + high-risk, fail-closed), proven by the SPEC-0279 tests. The signed-HEAD propagation endpoint (FR-0045 D2/D4) is the remaining sprint work. This offline demo does not stand up a registry, so S3 is shown as the built surface, not run live here.",
		},
		{
			ID:      "S4",
			Title:   "Untrusted internet import → airlock",
			Tier:    "ROADMAP",
			SVG:     "scenario-4-import-airlock.svg",
			Story:   "A developer wants a slick skill from a public hub. It must be SHA-pinned, staged OUTSIDE ~/.claude/skills, statically scanned, capped yellow, and blocked until a human attests.",
			Without: "npx/pip install runs arbitrary install-time code immediately — the public-hub bypass.",
			ExitDoc: "1 (refused on critical-rule hit)",
			Roadmap: "Closest built surface: a static import scanner exists in the codebase (import_public_cmds.go / SPEC-0201) but the airlock flow is not wired for this offline demo, so S4 stays a labelled roadmap panel rather than a live run.",
		},
	}
}

// --- LIVE scenario bodies ---------------------------------------------------

func runS1(d *Driver) {
	d.step("1 · Author + admit (offline): the real KuP skill was packed to a .skb and a signed registry admission was synthesised in-process (demo author + registry keys). Pinned trust-roots hold both public keys.")
	d.wait()

	d.step("2 · Victim verifies the signed bundle offline against the pinned key.")
	d.exec(0, "allowed", "", "verify", "--bundle", d.sb.GoodSkb, "--trust-roots", d.sb.TrustRoots)
	d.wait()

	d.step("3 · Attacker edits scripts/smoke.sh to add an ~/.ssh exfil line and reships the bundle (bytes change).")
	d.wait()

	d.step("4 · Victim verifies the POISONED bundle — one modified byte breaks the signed digest.")
	d.exec(10, "blocked", "", "verify", "--bundle", d.sb.PoisonSkb, "--trust-roots", d.sb.TrustRoots)
	d.note("The signature does not describe the risk — it prevents the run. Nothing is written to ~/.claude/skills/.")
}

func runS2A(d *Driver) {
	if d.prep("Setup: install kup-onboarding-greeting into the sandbox ~/.claude/skills/ (stashed .skb + green provenance).", d.sb.PrepareS2A) != nil {
		return
	}
	d.wait()

	d.step("1 · Load-time gate on the CLEAN skill (the PreToolUse(Skill) hook Claude Code runs before loading a skill).")
	d.exec(0, "allowed", hookEvent(demoSkillName), "verify-hook")
	d.wait()

	d.step("2 · An agent tampers the INSTALLED skill on disk (prompt-injection into SKILL.md).")
	if d.prep("Injecting a prompt-injection line into the installed SKILL.md…", d.sb.TamperInstalled) != nil {
		return
	}
	d.wait()

	d.step("3 · Load-time gate re-runs the trust chain — the tampered body never loads.")
	d.exec(2, "blocked", hookEvent(demoSkillName), "verify-hook")
	d.wait()

	d.step("4 · SessionStart sweep quarantines it out of ~/.claude/skills/. (The sweep's own process code is 0 by design; the enforcing verdict is per-skill.)")
	res := d.exec(0, "allowed", "", "verify", "--all", "--quarantine", "--json")
	if state, code, ok := sweepVerdict(res.Stdout, demoSkillName); ok {
		d.bus.Emit(Event{Kind: "verdict", Text: "sweep verdict for " + demoSkillName + ": state=" + state, Code: code, Expected: 10, Verdict: "blocked", OK: code == 10})
		d.note("Per-skill trust verdict: " + state + " with digest-mismatch code " + itoa(code) + " → moved to quarantine so Claude Code cannot load it.")
	} else {
		d.note("Could not parse the sweep report entry for " + demoSkillName + ".")
	}
}

func runS5(d *Driver) {
	if d.prep("Setup: place two hand-installed, unverified skills under ~/.claude/skills/ (the cleanup targets).", d.sb.PrepareS5) != nil {
		return
	}
	d.wait()

	d.step("1 · Plan the destructive cleanup: dry-run prints the affected set + a signed 5-minute token. No deletion.")
	res := d.exec(0, "allowed", "", "audit", "--cleanup", "--dry-run-cleanup", "--format", "json")
	token := jsonField(res.Stdout, "token")
	if token == "" {
		d.note("Could not read the dry-run token; aborting S5.")
		return
	}
	d.note("Signed token bound to the current affected-set (HMAC over hostname + sorted skill paths + issued-at).")
	d.wait()

	d.step("2 · The affected-set DRIFTS before you confirm (a third unverified skill appears).")
	if d.prep("Adding a third unverified skill…", d.sb.DriftS5) != nil {
		return
	}
	d.wait()

	d.step("3 · Confirm re-checks the LIVE set against the token — it drifted, so the destructive op REFUSES.")
	d.exec(2, "refused", "", "audit", "--cleanup", "--confirm-delete", "--dry-run-cleanup-token", token, "--format", "json")
	d.note("Refused with exit 2 (usage/precondition — the confirm's re-verification failed on drift). No --force exists; both the dry-run and the refusal are auditable.")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
