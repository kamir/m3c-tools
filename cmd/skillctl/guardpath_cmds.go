package main

// guardpath_cmds.go — `skillctl guard-path` (SPEC-0317 R-6, P2).
//
// A SIDE-CHANNEL PreToolUse guard for the file-touching tools (Bash / Read /
// Edit / Write). It reads the hook event on stdin, classifies the target
// path(s) against the installed skill directories, and by default AUDITS-ALLOWS
// (records a skill-dir hit, allows the tool). An opt-in enterprise mode DENIES a
// skill-dir access (exit 2, refusal_code `sidechannel_denied`).
//
// HONEST SCOPE (R-6.4 — this guard is DETECTION / BAR-RAISING, NOT a seal):
// it is defeatable by construction (symlinks, $HOME indirection, cd + relative
// paths, base64 pipelines, copies made OUTSIDE the skills dir, content already
// in the model's context, a direct /slash skill load). It is sold ONLY as
// audited-allow detection; `guard-path --explain` prints the coverage gaps
// verbatim rather than hiding them. Because it is not a seal, it fails OPEN: an
// unreadable event, a panic, or an unresolvable path is a silent allow, and this
// hook NEVER overrides another hook's deny (same silent-allow contract as
// verify-hook: an allow emits nothing and exits 0).
//
// THE ONE CANONICALISATION FIXED POINT (R-6.2 — the load-bearing correctness
// point): classification resolves BOTH the access target and the skills root
// through install.CanonicalPath (expand ~, abs+clean, EvalSymlinks) and compares
// the cleaned absolute real paths with filepath.Rel + a no-"../"-escape check. A
// lexical HasPrefix on the skills dir is FORBIDDEN — that dir already contains
// symlinks (browse → gstack/browse, find-skills → ../../.agents/skills), so a
// HasPrefix check both false-negatives (a symlinked-in body) and false-positives.
//
// SELF-EXEMPTION (R-6.3): skillctl's own subprocess reads (compliance inventory,
// the SessionStart sweep) and the harness's legitimate SKILL.md load must never
// be denied. Where the event shape lets us tell (a Bash line that invokes
// skillctl), we exempt; otherwise we DEFAULT TO ALLOW — the audited-allow default
// already never denies, so an ambiguous case cannot become a false block.
//
// VOLUME-BOUNDING (R-6.1): Bash/Read/Edit/Write fire far more than Skill, so an
// event is emitted ONLY on a deny or a skill-dir hit — never on an ordinary file
// op. The telemetry rides a SEPARATE, off-by-default stream (guard-path.jsonl)
// with its own consent basis (R-9); it is NEVER folded into the enforcement
// evidence (invocation-trail.jsonl / the outbox), so SPEC-0276 readAndVerifyTrail
// keeps reading the trail byte-for-byte.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/bodyscan"
	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// exitSidechannelDenied is the numbered refusal code carried in the signed guard
// event on an opt-in deny. The PROCESS still exits exitHookBlock (2) to block the
// PreToolUse call — 27 is carried in the human reason + the signed refusal_code,
// exactly as exitBundleRevoked (17) / exitRevocationStale (22) do for verify-hook.
const exitSidechannelDenied = 27 // = exitcode.GuardPathSidechannelDenied.Number

// guardPathRefusalToken is the stable refusal_code token for a side-channel deny.
const guardPathRefusalToken = "sidechannel_denied"

// guardPathSink is the write seam for the SEPARATE side-channel telemetry stream.
// Tests inject a capturing/failing sink.
var guardPathSink = defaultGuardPathSink

// runGuardPath is the entrypoint for `skillctl guard-path`. It returns the
// process exit code: 0 = allow (audited-allow default OR any non-hit / self-exempt
// / unreadable case), 2 = opt-in deny of a skill-dir access.
func runGuardPath(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	fs := flag.NewFlagSet("guard-path", flag.ContinueOnError)
	fs.SetOutput(stderr)
	explain := fs.Bool("explain", false, "print the honest scope + coverage gaps and exit")
	denyFlag := fs.Bool("deny", false, "opt-in: DENY (exit 2) a skill-dir access instead of audited-allow")
	homeOverride := fs.String("home", "", "home dir override (default: $HOME)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *explain {
		printGuardPathExplain(stdout)
		return exitOK
	}

	// Fail OPEN on panic: a detection side channel must NEVER false-block a tool
	// (R-6.4 — it is not a seal and must not override another hook's decision).
	defer func() {
		if r := recover(); r != nil {
			code = exitOK
		}
	}()

	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return exitOK // nothing to guard → silent allow
	}
	var ev hookEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return exitOK // malformed → silent allow (never block on our own parse fail)
	}

	// Guard only the file-touching tools. Skill is verify-hook's job; anything
	// else is a silent allow so this hook never overrides another.
	switch ev.ToolName {
	case "Bash", "Read", "Edit", "Write", "":
	default:
		return exitOK
	}

	home := *homeOverride
	if home == "" {
		home, _ = userHome()
	}
	canonRoot, ok := canonicalSkillsRoot(home)
	if !ok {
		return exitOK // no resolvable skills root → nothing to classify
	}

	// Self-exemption FIRST (R-6.3): never deny skillctl's own inventory read.
	if guardSelfExempt(ev) {
		return exitOK
	}

	hits := skillDirHits(canonRoot, ev)
	if len(hits) == 0 {
		// R-6.1 volume-bounding: emit NOTHING on a non-hit.
		return exitOK
	}

	obfuscated := commandObfuscated(ev)
	deny := guardDenyMode(*denyFlag)

	if deny {
		reason := fmt.Sprintf(
			"skillctl guard-path: BLOCKED %s access to skill directory %q (side-channel deny, SPEC-0317 R-6.1; refusal_code=%s, code %d). This is opt-in detection, not a seal — clear SKILLCTL_GUARD_PATH / drop --deny if this access is legitimate.",
			toolLabel(ev.ToolName), hits[0], guardPathRefusalToken, exitSidechannelDenied)
		emitGuardEvent(home, canonRoot, ev, hits, "deny", guardPathRefusalToken, exitSidechannelDenied, obfuscated)
		return emitDeny(stdout, stderr, reason)
	}

	// Default disposition: AUDITED-ALLOW — record the hit, allow the tool (exit 0,
	// emit nothing on stdout/stderr).
	emitGuardEvent(home, canonRoot, ev, hits, "audited-allow", "", exitOK, obfuscated)
	return exitOK
}

// toolLabel renders a tool name for a message, defaulting to "file" for the
// empty (matcher-only) case.
func toolLabel(t string) string {
	if t == "" {
		return "file"
	}
	return t
}

// --- classification (the R-6.2 fixed point) -------------------------------

// canonicalSkillsRoot resolves ~/.claude/skills through install.CanonicalPath.
func canonicalSkillsRoot(home string) (string, bool) {
	if home == "" {
		return "", false
	}
	c, err := install.CanonicalPath(filepath.Join(home, ".claude", "skills"))
	if err != nil {
		return "", false
	}
	return c, true
}

// skillDirHits returns the canonical paths of every target that resolves to (or
// under) the skills root. Both the target and the root are canonicalised first
// (R-6.2), so a symlinked-in body is caught and a lexical `..`/symlink trick
// cannot false-negative.
func skillDirHits(canonRoot string, ev hookEvent) []string {
	var hits []string
	seen := map[string]struct{}{}
	for _, p := range targetPaths(ev) {
		ct, err := install.CanonicalPath(p)
		if err != nil {
			continue
		}
		if !underSkills(canonRoot, ct) {
			continue
		}
		if _, dup := seen[ct]; dup {
			continue
		}
		seen[ct] = struct{}{}
		hits = append(hits, ct)
	}
	return hits
}

// underSkills reports whether canonTarget is the skills root itself or inside it,
// using filepath.Rel + a no-"../"-escape check on the two already-canonical
// absolute paths (NOT a lexical HasPrefix — R-6.2).
func underSkills(canonRoot, canonTarget string) bool {
	if canonRoot == "" || canonTarget == "" {
		return false
	}
	if canonTarget == canonRoot {
		return true
	}
	rel, err := filepath.Rel(canonRoot, canonTarget)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// skillNameForPath derives the skill name (the first path segment under the
// skills root) from a canonical target already known to be under canonRoot.
func skillNameForPath(canonRoot, canonTarget string) string {
	rel, err := filepath.Rel(canonRoot, canonTarget)
	if err != nil || rel == "" || rel == "." {
		return ""
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// --- target extraction (R-6.4: read command/file_path) --------------------

// targetPaths pulls the candidate file paths from a hook event: file_path for
// Read/Edit/Write, and shell-word-extracted path-like args for Bash. The empty
// tool name (a matcher-only event) is treated permissively.
func targetPaths(ev hookEvent) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	switch ev.ToolName {
	case "Read", "Edit", "Write":
		add(ev.ToolInput.FilePath)
	case "Bash":
		for _, tok := range shellPathTokens(ev.ToolInput.Command) {
			add(tok)
		}
	default: // "" or anything else that slipped past the tool filter
		add(ev.ToolInput.FilePath)
		for _, tok := range shellPathTokens(ev.ToolInput.Command) {
			add(tok)
		}
	}
	return out
}

// shellPathTokens shell-word-splits a Bash command and returns the path-like
// tokens (best-effort; the coverage gaps are enumerated in --explain).
func shellPathTokens(cmd string) []string {
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	var out []string
	for _, f := range shellSplit(cmd) {
		f = strings.Trim(f, `"'`)
		if f == "" || strings.HasPrefix(f, "-") {
			continue // a flag, not a path
		}
		if looksPathLike(f) {
			out = append(out, f)
		}
	}
	return out
}

// shellSplit is a deliberately minimal tokeniser: it neutralises common shell
// separators (so a piped/compound command still surfaces its path args) and
// splits on whitespace. It is NOT a real shell parser — that limitation is part
// of the honestly-enumerated coverage gap.
func shellSplit(cmd string) []string {
	repl := strings.NewReplacer(
		"|", " ", ";", " ", "&", " ", ">", " ", "<", " ",
		"(", " ", ")", " ", "`", " ", "\n", " ", "\t", " ",
	)
	return strings.Fields(repl.Replace(cmd))
}

// looksPathLike reports whether a token is shaped like a filesystem path.
// Recognises BOTH separators and drive-qualified Windows paths: on windows a
// native path (`C:\Users\...\.claude\skills\x\SKILL.md`) carries no '/', no '~'
// and no leading '.', so a POSIX-only check silently classified it as "not a
// path" and the guard never fired (Trust Surface / windows-latest).
// A false positive here is harmless: the token is only fed to
// install.CanonicalPath, and underSkills() still gates whether it is a real hit.
func looksPathLike(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.HasPrefix(s, "~") || strings.HasPrefix(s, ".") {
		return true
	}
	if strings.ContainsAny(s, `/\`) {
		return true
	}
	// Drive-qualified Windows path with no separator (e.g. `C:file`).
	return len(s) >= 2 && s[1] == ':' && isDriveLetter(s[0])
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// --- self-exemption (R-6.3) -----------------------------------------------

// guardSelfExempt reports whether the event is skillctl's own tool access (the
// compliance inventory read, the SessionStart sweep), which must NEVER be denied.
// When the event shape does not let us tell, it returns false — the audited-allow
// default already never denies, so an ambiguous case cannot become a false block.
//
// R-6.3: the exemption is granted ONLY to a verified SOLE-skillctl command. A
// compound / piped / substituted command forfeits it — otherwise the leading
// `skillctl` word would whitelist a SECOND command chained after it
// (`skillctl x; cat <victim>`), silently allowing the victim read AND blinding the
// audit. commandHasSeparator strips that escape so the chained access still
// surfaces its skill-dir hit (and, under --deny, is blocked).
func guardSelfExempt(ev hookEvent) bool {
	if ev.ToolName != "Bash" {
		return false
	}
	if commandHasSeparator(ev.ToolInput.Command) {
		return false // not a SOLE skillctl command — no exemption
	}
	return commandInvokesSkillctl(ev.ToolInput.Command)
}

// commandHasSeparator reports whether cmd chains or substitutes a second command
// via any shell separator (;, &&, ||, |, &, newline, backtick, or $()). Any of
// these means the command is NOT a verified SOLE-skillctl invocation, so it cannot
// inherit skillctl's self-exemption (R-6.3). `&&`/`||` are covered by the single-
// char scan for `&`/`|`.
func commandHasSeparator(cmd string) bool {
	if strings.ContainsAny(cmd, ";|&\n`") {
		return true
	}
	return strings.Contains(cmd, "$(")
}

// commandInvokesSkillctl reports whether the first real command word is skillctl
// (or the m3c-tools front-end), skipping leading VAR=val assignments and the
// common env/sudo/command wrappers.
func commandInvokesSkillctl(cmd string) bool {
	for _, tok := range shellSplit(cmd) {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "=") && !strings.Contains(tok, "/") {
			continue // VAR=val assignment
		}
		switch tok {
		case "env", "sudo", "command", "exec", "nohup", "time":
			continue // wrapper — look at the next word
		}
		base := filepath.Base(tok)
		return base == "skillctl" || base == "m3c-tools"
	}
	return false
}

// --- obfuscation flag (R-6.4: reuse bodyscan, not ad-hoc regexes) ----------

// commandObfuscated flags a Bash command whose body trips bodyscan's
// obfuscation rules (base64 / pipeline decoding). Advisory only — it annotates
// the guard event; it never changes the allow/deny disposition.
func commandObfuscated(ev hookEvent) bool {
	if ev.ToolName != "Bash" || strings.TrimSpace(ev.ToolInput.Command) == "" {
		return false
	}
	rep := bodyscan.Scan(bodyscan.Input{Body: ev.ToolInput.Command})
	for _, f := range rep.Findings {
		if f.Category == bodyscan.CategoryObfuscation {
			return true
		}
	}
	return false
}

// --- disposition ----------------------------------------------------------

// guardDenyMode reports the opt-in deny disposition: the --deny flag OR the
// SKILLCTL_GUARD_PATH env switch (deny|block). Default is audited-allow. The
// enterprise offline profile reuses the same switch when it wires this guard.
func guardDenyMode(flagDeny bool) bool {
	if flagDeny {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SKILLCTL_GUARD_PATH"))) {
	case "deny", "block":
		return true
	}
	return false
}

// --- emit (SEPARATE, off-by-default stream — R-9) --------------------------

// guardPathLine is one JSONL record in the side-channel stream: the SIGNED
// InvocationRecord (reusing the SPEC-0202 device-signed vocabulary + inv: event
// id — NOT a new event format) embedded, plus the guard-specific advisory fields.
// Embedding keeps the line a strict superset of the signed record, so the
// signature still verifies against the canonical record bytes.
type guardPathLine struct {
	skillgate.InvocationRecord
	Decision   string   `json:"guard_decision"` // audited-allow | deny
	Targets    []string `json:"guard_targets"`  // all skill-dir hits (canonical)
	Obfuscated bool     `json:"guard_obfuscated,omitempty"`
}

// guardPathLogPath is the SEPARATE stream file. It is NEVER invocation-trail.jsonl
// (the enforcement-evidence projection) nor the outbox — R-9 keeps guard-path
// file-access telemetry on its own consent basis.
func guardPathLogPath(home string) string {
	return filepath.Join(verdictDir(home), "guard-path.jsonl")
}

func defaultGuardPathSink(home string, line []byte) error {
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(guardPathLogPath(home), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// emitGuardEvent device-signs one guard record and appends it to the side-channel
// stream. Fire-and-forget + panic-safe: it can NEVER alter the disposition (the
// caller has already decided). A missing device key just skips the write.
func emitGuardEvent(home, canonRoot string, ev hookEvent, hits []string, decision, refusal string, exit int, obfuscated bool) {
	defer func() { _ = recover() }()
	if home == "" || len(hits) == 0 {
		return
	}
	key, err := invocationDeviceKey(home)
	if err != nil || key == nil {
		return
	}
	rec := skillgate.InvocationRecord{
		Schema:      skillgate.InvocationSchema,
		EventID:     newInvocationEventID(),
		EventType:   "path.guard.access",
		SkillName:   skillNameForPath(canonRoot, hits[0]),
		Action:      "file_access",
		Tool:        ev.ToolName,
		SessionID:   ev.SessionID,
		OccurredAt:  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		DeviceKeyID: key.KeyID(),
		ExitCode:    exit,
		RefusalCode: refusal,
	}
	if err := skillgate.SignInvocationRecord(&rec, key.Sign, base64.StdEncoding.EncodeToString); err != nil {
		return
	}
	line, err := json.Marshal(guardPathLine{
		InvocationRecord: rec,
		Decision:         decision,
		Targets:          hits,
		Obfuscated:       obfuscated,
	})
	if err != nil {
		return
	}
	_ = guardPathSink(home, line)
}

// --- --explain (R-6.4: enumerate the honest scope + coverage gaps) ---------

func printGuardPathExplain(w io.Writer) {
	fmt.Fprintln(w, "skillctl guard-path — side-channel PreToolUse guard (SPEC-0317 R-6)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "WHAT IT DOES")
	fmt.Fprintln(w, "  Reads a Bash/Read/Edit/Write PreToolUse hook event on stdin and classifies")
	fmt.Fprintln(w, "  the target path(s) against ~/.claude/skills using a SINGLE realpath fixed")
	fmt.Fprintln(w, "  point (EvalSymlinks on both the target and the skills root — never a lexical")
	fmt.Fprintln(w, "  HasPrefix, because the skills dir itself contains symlinks).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "DISPOSITION")
	fmt.Fprintln(w, "  default: AUDITED-ALLOW — record a skill-dir hit, allow the tool (exit 0).")
	fmt.Fprintln(w, "  opt-in : DENY (--deny or SKILLCTL_GUARD_PATH=deny) — exit 2, refusal_code")
	fmt.Fprintf(w, "           %q (code %d). skillctl's own reads are never denied.\n", guardPathRefusalToken, exitSidechannelDenied)
	fmt.Fprintln(w, "  Emits ONLY on a deny or a skill-dir hit, to a SEPARATE off-by-default stream")
	fmt.Fprintln(w, "  (guard-path.jsonl) — never folded into the enforcement evidence.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "THIS IS DETECTION / BAR-RAISING, NOT A SEAL. Known coverage gaps:")
	fmt.Fprintln(w, "  - copies of a skill body made OUTSIDE ~/.claude/skills are not classified;")
	fmt.Fprintln(w, "  - a skill whose SKILL.md is already in the model's context needs no file op;")
	fmt.Fprintln(w, "  - a direct /slash skill load does not pass through Bash/Read/Edit/Write;")
	fmt.Fprintln(w, "  - a skill symlinked to a body OUTSIDE the skills root resolves outside it;")
	fmt.Fprintln(w, "  - a SOLE leading-skillctl-word Bash command is self-exempt from --deny")
	fmt.Fprintln(w, "    (trusted as skillctl's own read); the exemption is forfeited the moment")
	fmt.Fprintln(w, "    the command chains a second one (;, &&, ||, |, &, backtick, $()), but a")
	fmt.Fprintln(w, "    single skillctl invocation pointed at another skill's path is still trusted;")
	fmt.Fprintln(w, "  - the Bash tokeniser is minimal (no full shell grammar): eval, here-docs,")
	fmt.Fprintln(w, "    variable-built paths, and base64 pipelines can hide a path (bodyscan flags")
	fmt.Fprintln(w, "    obvious base64/pipeline obfuscation, but this is advisory, not exhaustive);")
	fmt.Fprintln(w, "  - it fails OPEN (unreadable event / panic / unresolvable path => allow) so it")
	fmt.Fprintln(w, "    never overrides another hook's decision.")
}
