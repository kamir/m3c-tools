package main

// kata.go — Kata training/onboarding mode (DEMO-TOOL-design.md §6b).
//
// Frame (Toyota Kata): each trust capability is a Kata with a target condition;
// the learner closes the gap with REAL skillctl runs; this tool is the Coach. A
// "pass" (a Beat) is a REAL skillctl exit code — never self-reported, never
// faked. The five Katas reuse the hermetic Sandbox + Runner from the demo:
//
//   K1 Seal & prove      keygen→pack→sign→verify --bundle → exit 0   (3 reps)
//   K2 Detect tamper     tamper installed → verify --all verdict 10  (3 reps)
//   K3 Govern reversibly dry-run token → confirm on drift → exit 2   (3 reps)
//   K4 Trust roots       wrong root (fail) → trust add → verify 0    (3 reps)
//   K5 Revoke/fail-closed signed revocation → verify exit 17         (1 rep + read)
//
// K5 is CONCEPT/ROADMAP: the OFFLINE revocation exit (17, SPEC-0279) is real and
// run; the FLEET propagation of a signed revocation HEAD is roadmap (rendered,
// never faked as a live fleet result).
//
// Separation of concerns for testability: the state machine, the exit→obstacle
// mapping and the beat signature live in kata_progress.go (pure). The rep runner
// (runRep) is stdin-free and takes a kataRunner interface, so it is unit-testable
// with a stubbed runner. Only the interactive Coach loop reads stdin.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// kataRunner is the subset of *Runner the coach needs. *Runner satisfies it;
// tests provide a stub so the coach loop runs offline without real skillctl.
type kataRunner interface {
	Run(emit func(stream, line string), stdin string, args ...string) RunResult
}

// repPlan is the resolved "next experiment" for one rep: the command the learner
// runs as the go-&-see step, plus the artifact fingerprint feeding the signature.
type repPlan struct {
	Args     []string
	Stdin    string
	Cmd      string // human display of the experiment command
	Artifact string // artifact fingerprint (bundle digest / nonce marker)
}

// Kata is one trust capability framed as a Toyota Kata.
type Kata struct {
	ID            string
	Title         string
	Target        string // the target condition the learner drives toward
	Why           string // one-line why-it-matters (board subtitle)
	ExperimentCmd string // human label of the next-step command
	TargetExit    int    // the exit code / per-skill verdict a clean rep must observe
	RequiredReps  int    // distinct clean reps to reach grün (sitzt)
	Concept       bool   // K5 — concept/roadmap; label it, don't fake a live fleet
	Roadmap       string // roadmap/read text (K5)

	// setup runs the prerequisite steps for one rep (sandbox mutation + narrated
	// prerequisite skillctl runs) and returns the experiment plan. It is where the
	// "Actual / Obstacle" coaching steps happen.
	setup func(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error)
	// observe extracts the observed result from the experiment's RunResult: the
	// process exit for most Katas, the per-skill sweep verdict for K2.
	observe func(res RunResult) int
}

// Katas returns the ordered five-Kata curriculum.
func Katas() []*Kata {
	return []*Kata{
		{
			ID:            "K1",
			Title:         "Seal & prove",
			Target:        "a packed skill verifies offline against a pinned key: `verify --bundle` exits 0.",
			Why:           "seal a skill and prove authorship offline (keygen → pack → sign → verify).",
			ExperimentCmd: "skillctl verify --bundle <sealed.skb> --trust-roots <pinned>",
			TargetExit:    0,
			RequiredReps:  3,
			setup:         setupK1,
			observe:       func(res RunResult) int { return res.ExitCode },
		},
		{
			ID:            "K2",
			Title:         "Detect tamper",
			Target:        "a modified installed skill is caught BEFORE it runs: the sweep's per-skill verdict is 10 (digest mismatch).",
			Why:           "catch an on-disk tamper before Claude Code loads the skill.",
			ExperimentCmd: "skillctl verify --all --quarantine --json",
			TargetExit:    10,
			RequiredReps:  3,
			setup:         setupK2,
			observe: func(res RunResult) int {
				if _, code, ok := sweepVerdict(res.Stdout, demoSkillName); ok {
					return code
				}
				return -1
			},
		},
		{
			ID:            "K3",
			Title:         "Govern reversibly",
			Target:        "a destructive op refuses to be forced: the G-23 confirm exits 2 when the affected-set drifted.",
			Why:           "a destructive cleanup that re-checks the live set and refuses on drift (no --force).",
			ExperimentCmd: "skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <token> --format json",
			TargetExit:    2,
			RequiredReps:  3,
			setup:         setupK3,
			observe:       func(res RunResult) int { return res.ExitCode },
		},
		{
			ID:            "K4",
			Title:         "Trust roots & install",
			Target:        "verify only what an admitted registry signed: after pinning the right root, `verify --bundle` exits 0.",
			Why:           "pin a registry and admit only what its key signed.",
			ExperimentCmd: "skillctl trust add … ; skillctl verify --bundle <sealed.skb> --trust-roots <pinned>",
			TargetExit:    0,
			RequiredReps:  3,
			setup:         setupK4,
			observe:       func(res RunResult) int { return res.ExitCode },
		},
		{
			ID:            "K5",
			Title:         "Revoke & fail-closed",
			Target:        "a revoked bundle fails CLOSED offline: `verify --bundle --revocations` exits 17.",
			Why:           "reason about fleet revocation + the offline deny (concept/roadmap).",
			ExperimentCmd: "skillctl verify --bundle <sealed.skb> --trust-roots <pinned> --revocations <signed-list>",
			TargetExit:    17,
			RequiredReps:  1,
			Concept:       true,
			Roadmap: "CONCEPT/ROADMAP: the OFFLINE revocation exit (17) below is real and run here (SPEC-0279). " +
				"Fleet propagation — a signed revocation HEAD reaching every host, including one with its network cable " +
				"pulled, and failing closed — is the remaining sprint work (FR-0045 D2/D4). `skillctl revoke` runs live " +
				"against a registry; this offline demo does not stand up a registry, so the FLEET result is NOT faked.",
			setup:   setupK5,
			observe: func(res RunResult) int { return res.ExitCode },
		},
	}
}

// KataByID returns the Kata with the given (case-insensitive) id, or nil.
func KataByID(id string) *Kata {
	id = strings.ToUpper(strings.TrimSpace(id))
	for _, k := range Katas() {
		if k.ID == id {
			return k
		}
	}
	return nil
}

// --- per-Kata setup bodies (the Actual / Obstacle coaching steps) -----------

func setupK1(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error) {
	skb, digest, err := sb.KataSealBundle(nonce)
	if err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "step", Text: "ACTUAL — a freshly packed skill with NO signed admission envelope. Verify it to see where you are:"})
	narrate(Event{Kind: "cmd", Cmd: "skillctl verify --bundle <sealed.skb> --meta <missing> --trust-roots <pinned>"})
	a := run.Run(linesTo(narrate), "", "verify", "--bundle", skb, "--meta", skb+".unsigned.json", "--trust-roots", sb.TrustRoots)
	narrate(Event{Kind: "note", Text: fmt.Sprintf("OBSTACLE: exit %d — %s", a.ExitCode, obstacleForExit(a.ExitCode))})
	return repPlan{
		Args:     []string{"verify", "--bundle", skb, "--trust-roots", sb.TrustRoots},
		Cmd:      "skillctl verify --bundle <sealed.skb> --trust-roots <pinned>   (the signed sidecar now exists)",
		Artifact: digest,
	}, nil
}

func setupK2(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error) {
	if err := sb.PrepareS2A(); err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "step", Text: "ACTUAL — kup-onboarding-greeting is installed and green. The load-time gate allows it:"})
	narrate(Event{Kind: "cmd", Cmd: "skillctl verify-hook   (PreToolUse(Skill) gate, clean skill)"})
	a := run.Run(linesTo(narrate), hookEvent(demoSkillName), "verify-hook")
	narrate(Event{Kind: "note", Text: fmt.Sprintf("current state: exit %d — clean, currently trusted.", a.ExitCode)})
	narrate(Event{Kind: "prep", Text: "An agent tampers the INSTALLED skill on disk (prompt-injection into SKILL.md)."})
	if err := sb.TamperInstalledNonce(nonce); err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "note", Text: "OBSTACLE ahead: the bytes now differ from the signed .skb → digest mismatch (exit 10)."})
	narrate(Event{Kind: "note", Text: "Note: `verify --all`'s PROCESS exit is 0 by design (it is a sweep); the ENFORCING per-skill trust verdict is what this Kata asserts."})
	return repPlan{
		Args:     []string{"verify", "--all", "--quarantine", "--json"},
		Cmd:      "skillctl verify --all --quarantine --json   (SessionStart sweep; the per-skill verdict is the beat)",
		Artifact: nonce,
	}, nil
}

func setupK3(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error) {
	if err := sb.PrepareS5(); err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "step", Text: "ACTUAL — two hand-installed unverified skills. Plan the destructive cleanup (dry-run yields a signed token):"})
	narrate(Event{Kind: "cmd", Cmd: "skillctl audit --cleanup --dry-run-cleanup --format json"})
	dry := run.Run(linesTo(narrate), "", "audit", "--cleanup", "--dry-run-cleanup", "--format", "json")
	token := jsonField(dry.Stdout, "token")
	if token == "" {
		return repPlan{}, fmt.Errorf("K3: could not read the dry-run token (exit %d)", dry.ExitCode)
	}
	narrate(Event{Kind: "note", Text: fmt.Sprintf("current state: exit %d — a signed token bound to the affected-set.", dry.ExitCode)})
	driftName := "kup-kata-drift-" + nonce
	narrate(Event{Kind: "prep", Text: "The affected-set DRIFTS: a third unverified skill (" + driftName + ") appears before you confirm."})
	if err := sb.PlaceUnverifiedNamed(driftName); err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "note", Text: "OBSTACLE ahead: the confirm re-checks the LIVE set against the token; it drifted → REFUSE (exit 2). No --force exists."})
	return repPlan{
		Args:     []string{"audit", "--cleanup", "--confirm-delete", "--dry-run-cleanup-token", token, "--format", "json"},
		Cmd:      "skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <token> --format json",
		Artifact: driftName,
	}, nil
}

func setupK4(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error) {
	skb, digest, err := sb.KataSealBundle(nonce)
	if err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "step", Text: "ACTUAL — verify a signed bundle against trust-roots that pin the WRONG registry key:"})
	narrate(Event{Kind: "cmd", Cmd: "skillctl verify --bundle <sealed.skb> --trust-roots <wrong-roots>"})
	a := run.Run(linesTo(narrate), "", "verify", "--bundle", skb, "--trust-roots", sb.WrongTrustRoots)
	narrate(Event{Kind: "note", Text: fmt.Sprintf("OBSTACLE: exit %d — %s", a.ExitCode, obstacleForExit(a.ExitCode))})
	narrate(Event{Kind: "prep", Text: "Pin the correct registry key (the admission root):"})
	narrate(Event{Kind: "cmd", Cmd: "skillctl trust add --registry " + demoRegURL + " --pubkey <registry-pubkey.pem>"})
	ta := run.Run(linesTo(narrate), "", "trust", "add", "--registry", demoRegURL, "--pubkey", sb.RegPubPEM)
	pinMsg := "the registry is now pinned."
	if ta.ExitCode != 0 {
		pinMsg = "already pinned from an earlier rep (idempotent) — the experiment below uses the correctly-pinned roots regardless."
	}
	narrate(Event{Kind: "note", Text: fmt.Sprintf("trust add exit %d — %s", ta.ExitCode, pinMsg)})
	return repPlan{
		Args:     []string{"verify", "--bundle", skb, "--trust-roots", sb.TrustRoots},
		Cmd:      "skillctl verify --bundle <sealed.skb> --trust-roots <correctly-pinned>",
		Artifact: digest,
	}, nil
}

func setupK5(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error) {
	skb, digest, err := sb.KataSealBundle(nonce)
	if err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "step", Text: "ACTUAL — the bundle is healthy today. Verify it offline:"})
	narrate(Event{Kind: "cmd", Cmd: "skillctl verify --bundle <sealed.skb> --trust-roots <pinned>"})
	a := run.Run(linesTo(narrate), "", "verify", "--bundle", skb, "--trust-roots", sb.TrustRoots)
	narrate(Event{Kind: "note", Text: fmt.Sprintf("current state: exit %d — healthy. But how do you kill it fleet-wide tomorrow?", a.ExitCode)})
	rev, err := sb.KataRevocations(digest, nonce)
	if err != nil {
		return repPlan{}, err
	}
	narrate(Event{Kind: "prep", Text: "A signed revocation list (signed by the pinned registry key) revokes this digest."})
	narrate(Event{Kind: "note", Text: "OBSTACLE ahead: with the revocation enforced, verification fails CLOSED offline (exit 17)."})
	return repPlan{
		Args:     []string{"verify", "--bundle", skb, "--trust-roots", sb.TrustRoots, "--revocations", rev},
		Cmd:      "skillctl verify --bundle <sealed.skb> --trust-roots <pinned> --revocations <signed-list>",
		Artifact: digest,
	}, nil
}

// linesTo adapts a bus emitter into the Runner's per-line callback.
func linesTo(narrate func(Event)) func(stream, line string) {
	return func(stream, line string) { narrate(Event{Kind: "line", Stream: stream, Text: line}) }
}

// --- the Coach --------------------------------------------------------------

// Coach drives the interactive coaching-Kata loop against the real skillctl.
type Coach struct {
	sb        *Sandbox
	run       kataRunner
	bus       *Bus
	store     *KataStore
	in        *bufio.Reader // stdin reader; nil ⇒ non-interactive (predict = target)
	stallDays int
	eof       bool // set when stdin closed, so the loop stops instead of spinning
}

// NewCoach wires a coach. Pass in=nil for a non-interactive coach.
func NewCoach(sb *Sandbox, run kataRunner, bus *Bus, store *KataStore, in *bufio.Reader, stallDays int) *Coach {
	if stallDays <= 0 {
		stallDays = DefaultStallDays
	}
	return &Coach{sb: sb, run: run, bus: bus, store: store, in: in, stallDays: stallDays}
}

// CoachAll walks every Kata to grün (or until stdin closes).
func (c *Coach) CoachAll() {
	for _, k := range Katas() {
		if c.eof {
			return
		}
		c.Coach(k)
	}
	c.bus.Emit(Event{Kind: "done", Text: "Every beat above is a real skillctl exit code. Board: /kata"})
}

// Coach runs the 5-question coaching loop for one Kata until it is grün.
func (c *Coach) Coach(k *Kata) {
	c.bus.Emit(Event{Kind: "scenario", ID: k.ID, Title: k.Title, Tier: tierFor(k),
		Story: k.Why, ExitDoc: fmt.Sprintf("target exit %d · %d clean reps → sitzt", k.TargetExit, k.RequiredReps)})
	if k.Concept {
		c.bus.Emit(Event{Kind: "note", Text: k.Roadmap})
	}
	for {
		dist := c.store.Distinct(k.ID)
		st, rusted := c.store.State(k.ID, k.RequiredReps, c.stallDays, time.Now())
		if st == StateGruen {
			c.bus.Emit(Event{Kind: "note", Text: fmt.Sprintf("%s is grün (sitzt) — %d/%d distinct clean reps.", k.ID, dist, k.RequiredReps)})
			return
		}
		// Step 1 — Target.
		c.bus.Emit(Event{Kind: "step", Text: fmt.Sprintf("TARGET — %s   (%d/%d clean reps · state %s%s)",
			k.Target, dist, k.RequiredReps, st, rustedTag(rusted))})
		nonce := newNonce()
		if _, _, err := c.runRep(k, nonce, c.predict); err != nil {
			c.bus.Emit(Event{Kind: "note", Text: "rep aborted: " + err.Error()})
			return
		}
		if c.eof {
			c.bus.Emit(Event{Kind: "note", Text: "stdin closed — pausing this Kata (progress saved)."})
			return
		}
	}
}

// runRep executes ONE coaching rep: setup (Actual/Obstacle) → predict (Next
// experiment + expectation) → run + observe + compare (Go & see) → record a Beat
// iff the observed result met the target. It is stdin-free: the prediction is
// supplied by the `predict` callback, so tests drive it with a stub runner and a
// fixed predictor. Returns the beat, whether it counted as a NEW distinct rep,
// and any setup error.
func (c *Coach) runRep(k *Kata, nonce string, predict func(k *Kata) int) (Beat, bool, error) {
	plan, err := k.setup(c.sb, c.run, c.bus.Emit, nonce)
	if err != nil {
		return Beat{}, false, err
	}
	// Step 4 — Next experiment + expectation.
	c.bus.Emit(Event{Kind: "step", Text: "EXPERIMENT — next step: " + plan.Cmd})
	predicted := predict(k)
	// Step 5 — Go & see.
	c.bus.Emit(Event{Kind: "cmd", Cmd: "skillctl " + strings.Join(plan.Args, " ")})
	res := c.run.Run(func(stream, line string) { c.bus.Emit(Event{Kind: "line", Stream: stream, Text: line}) }, plan.Stdin, plan.Args...)
	if res.Err != nil {
		c.bus.Emit(Event{Kind: "note", Text: "exec error: " + res.Err.Error()})
	}
	observed := k.observe(res)
	ok := observed == k.TargetExit
	c.bus.Emit(Event{Kind: "exit", Code: observed, Expected: k.TargetExit, Verdict: verdictFor(k), OK: ok})
	if predicted == observed {
		c.bus.Emit(Event{Kind: "note", Text: fmt.Sprintf("your prediction (%d) matched the real result (%d).", predicted, observed)})
	} else {
		c.bus.Emit(Event{Kind: "note", Text: fmt.Sprintf("you predicted %d; the real result was %d — %s", predicted, observed, obstacleForExit(observed))})
	}

	beat := Beat{Kata: k.ID, Signature: repSignature(k.ID, nonce, plan.Artifact), Observed: observed, Target: k.TargetExit, At: time.Now()}
	if !ok {
		c.bus.Emit(Event{Kind: "note", Text: "no beat recorded — the run did not meet the target (honesty rule)."})
		return beat, false, nil
	}
	added := c.store.Record(beat)
	if err := c.store.Save(); err != nil {
		c.bus.Emit(Event{Kind: "note", Text: "warning: could not persist progress: " + err.Error()})
	}
	dist := c.store.Distinct(k.ID)
	st, rusted := c.store.State(k.ID, k.RequiredReps, c.stallDays, time.Now())
	c.bus.Emit(Event{Kind: "beat", ID: k.ID, Code: observed, Expected: k.TargetExit, OK: true,
		State: string(st), Reps: dist, Required: k.RequiredReps, Rusting: rusted, Added: added,
		Text: beatText(k, dist, st, rusted, added)})
	return beat, added, nil
}

// predict is the interactive prediction reader (step 4). Enter accepts the
// target; a bare EOF sets eof so the loop halts (never hangs on a closed stdin).
func (c *Coach) predict(k *Kata) int {
	if c.in == nil {
		return k.TargetExit
	}
	c.bus.Emit(Event{Kind: "note", Text: "What exit code do you EXPECT? (Enter to accept the target " + strconv.Itoa(k.TargetExit) + ")"})
	fmt.Fprint(os.Stdout, "  expect ▸ ")
	s, err := c.in.ReadString('\n')
	if err != nil && strings.TrimSpace(s) == "" {
		c.eof = true
		return k.TargetExit
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return k.TargetExit
	}
	n, perr := strconv.Atoi(s)
	if perr != nil {
		return -1 // an explicit non-number prediction (a "wrong guess") — still honest
	}
	return n
}

// --- board rendering --------------------------------------------------------

// KataBoardRow is one card on the Kata board (CLI + browser + JSON).
type KataBoardRow struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Why           string `json:"why"`
	State         string `json:"state"` // rot | gelb | gruen
	Rusted        bool   `json:"rusted"`
	Distinct      int    `json:"distinct"`
	Required      int    `json:"required"`
	TargetExit    int    `json:"target_exit"`
	Concept       bool   `json:"concept"`
	Hint          string `json:"hint"`
	ExperimentCmd string `json:"experiment_cmd"`
}

// BoardRows projects the store into one row per Kata at time now.
func BoardRows(store *KataStore, stallDays int, now time.Time) []KataBoardRow {
	rows := make([]KataBoardRow, 0, len(Katas()))
	for _, k := range Katas() {
		dist := store.Distinct(k.ID)
		st, rusted := store.State(k.ID, k.RequiredReps, stallDays, now)
		rows = append(rows, KataBoardRow{
			ID: k.ID, Title: k.Title, Why: k.Why, State: string(st), Rusted: rusted,
			Distinct: dist, Required: k.RequiredReps, TargetExit: k.TargetExit, Concept: k.Concept,
			Hint: boardHint(k, dist, st, rusted, stallDays), ExperimentCmd: k.ExperimentCmd,
		})
	}
	return rows
}

// PrintBoard renders the non-interactive text board (`--kata-list`). It never
// blocks and never runs skillctl — it reflects only the local progress store.
func PrintBoard(w io.Writer, store *KataStore, stallDays int, now time.Time) {
	fmt.Fprintf(w, "\n  Kata board — %s\n", store.Path)
	fmt.Fprintf(w, "  mastery: rot=new · gelb=practicing · gruen=sitzt · rust window %dd (KATA_STALL_DAYS)\n\n", stallDays)
	for _, r := range BoardRows(store, stallDays, now) {
		concept := ""
		if r.Concept {
			concept = "  [concept/roadmap]"
		}
		fmt.Fprintf(w, "  %-3s %-8s %d/%d  %s%s\n", r.ID, "["+r.State+rustedTag(r.Rusted)+"]", r.Distinct, r.Required, r.Title, concept)
		fmt.Fprintf(w, "        %s\n", r.Why)
		fmt.Fprintf(w, "        target exit %d · %s\n", r.TargetExit, r.Hint)
	}
	fmt.Fprintln(w, "\n  Every beat is a real skillctl exit code. Practice: skillctl-demo --mode kata [--kata K1]")
}

func boardHint(k *Kata, dist int, st KataState, rusted bool, stallDays int) string {
	switch {
	case rusted:
		return "rusting — one clean rep refreshes it (stall window " + strconv.Itoa(stallDays) + "d)"
	case st == StateGruen:
		return "sitzt — revisit before it rusts (stall window " + strconv.Itoa(stallDays) + "d)"
	case st == StateRot:
		return "start: " + k.ExperimentCmd
	default:
		rem := k.RequiredReps - dist
		if rem < 1 {
			rem = 1
		}
		return strconv.Itoa(rem) + " more distinct clean rep(s): " + k.ExperimentCmd
	}
}

func beatText(k *Kata, dist int, st KataState, rusted bool, added bool) string {
	suffix := ""
	if !added {
		suffix = " (identical artifact — practiced, no new distinct rep)"
	}
	return fmt.Sprintf("%s beat: exit %d = target · %d/%d · %s%s%s",
		k.ID, k.TargetExit, dist, k.RequiredReps, st, rustedTag(rusted), suffix)
}

func rustedTag(rusted bool) string {
	if rusted {
		return "·rust"
	}
	return ""
}

// tierFor labels the coaching card: LIVE for the runnable Katas, PARTIAL for the
// concept/roadmap Kata (K5) whose fleet-propagation half is roadmap.
func tierFor(k *Kata) string {
	if k.Concept {
		return "PARTIAL"
	}
	return "LIVE"
}

// verdictFor maps a Kata target to the badge verdict word.
func verdictFor(k *Kata) string {
	switch k.TargetExit {
	case 0:
		return "allowed"
	case 2:
		return "refused"
	default:
		return "blocked"
	}
}

// newNonce returns a fresh 8-byte hex nonce for one rep (drives artifact
// distinctness + the rep signature).
func newNonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
