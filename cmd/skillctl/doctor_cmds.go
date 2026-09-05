package main

// doctor_cmds.go: `skillctl doctor`, the one command that answers "is this
// machine ready, and if not, what do I do next" (SPEC-0406 D1, decided
// 2026-09-05).
//
// WHY IT EXISTS. SPEC-0406 Phase 1 has both parties check their installation
// before anything else, and the two-person handover in SPEC-0246 needs the same
// answer. Before this the answer was assembled from `version`, `trust list`,
// `peer ls` and a look at the filesystem, which is four commands and a habit,
// and a habit is not something you can ask someone to run over the phone.
//
// WHAT IT IS NOT. It is not a gate and it is not a trust decision. It reads,
// reports and exits; it changes nothing. Its exit code says whether anything is
// BROKEN, not whether everything is configured, and that distinction is the
// whole design:
//
//   - An ABSENT trust-roots file on a fresh machine is the expected state. It is
//     reported as a next step, not as a failure. A tool that reports a red error
//     for the normal first-run state teaches people to ignore red errors.
//   - An UNREADABLE or MALFORMED file is a failure: something is there and we
//     cannot tell what it says, which is exactly the case where proceeding is
//     unsafe.
//
// The output follows the SPEC-0406 §5b AC-14 shape on purpose: every line says
// what IS, and where something is missing it says what to do about it. A
// diagnostic that reports a state without a next action leaves the reader
// exactly where they started.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// checkStatus is the three-value verdict of one check. The middle value is the
// one that earns its keep: it separates "not set up yet" from "set up wrong",
// which are the two states a first-run user is most likely to confuse.
type checkStatus int

const (
	statusOK   checkStatus = iota // present and usable
	statusTodo                    // absent, expected on a fresh machine, with a next step
	statusBad                     // present and broken: the only status that fails the command
)

func (s checkStatus) marker() string {
	switch s {
	case statusOK:
		return "ok  "
	case statusTodo:
		return "todo"
	default:
		return "FAIL"
	}
}

// check is one reported line: what was looked at, what was found, and what to do
// about it when there is something to do.
type check struct {
	name   string
	status checkStatus
	detail string
	next   string // the action the reader can take; empty when none is needed.
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	homeOverride := fs.String("home", "", "Override the install root (advanced; defaults to $HOME).")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl doctor [--home <dir>]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Reports whether this machine is ready to pack, sign, verify and install")
		fmt.Fprintln(stderr, "skills, and what to do about anything that is missing. Read-only.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit: 0 nothing is broken (absent-but-expected config is not broken)")
		fmt.Fprintln(stderr, "      1 something is present and unusable")
		fmt.Fprintln(stderr, "      2 usage error")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}

	checks := []check{
		checkVersion(),
		checkHome(*homeOverride),
		checkSkillsDir(*homeOverride),
		checkTrustRoots(),
		checkPeers(),
		checkSigningKey(*homeOverride),
		checkAuditDir(*homeOverride),
	}

	width := 0
	for _, c := range checks {
		if len(c.name) > width {
			width = len(c.name)
		}
	}

	var bad, todo int
	fmt.Fprintln(stdout, "skillctl doctor")
	fmt.Fprintln(stdout, strings.Repeat("-", 62))
	for _, c := range checks {
		fmt.Fprintf(stdout, "%s  %-*s  %s\n", c.status.marker(), width, c.name, c.detail)
		if c.next != "" {
			fmt.Fprintf(stdout, "      %-*s  -> %s\n", width, "", c.next)
		}
		switch c.status {
		case statusBad:
			bad++
		case statusTodo:
			todo++
		}
	}
	fmt.Fprintln(stdout, strings.Repeat("-", 62))

	// The summary states all three things a reader needs and does not conflate
	// them: what works, what is merely not set up, and what is broken.
	switch {
	case bad > 0:
		fmt.Fprintf(stdout, "NOT READY: %d check(s) found something present and unusable.\n", bad)
		fmt.Fprintln(stdout, "Fix those first: an unreadable configuration is not the same as an absent one,")
		fmt.Fprintln(stdout, "and skillctl will not guess what a malformed file was meant to say.")
		return exitGeneric
	case todo > 0:
		fmt.Fprintf(stdout, "USABLE, %d step(s) not done yet. Nothing here is broken.\n", todo)
		fmt.Fprintln(stdout, "Each line above says what to run next. On a fresh machine this is expected.")
		return exitOK
	default:
		fmt.Fprintln(stdout, "READY: environment complete, nothing outstanding.")
		return exitOK
	}
}

func checkVersion() check {
	return check{
		name:   "version",
		status: statusOK,
		// The platform is printed because SPEC-0406 §3.3 requires BOTH parties to
		// run the same build, and "same version" is only half of that answer when
		// one side is on Windows and the other on macOS.
		detail: fmt.Sprintf("skillctl %s (%s/%s, %s)", version, runtime.GOOS, runtime.GOARCH, runtime.Version()),
	}
}

func checkHome(override string) check {
	h := auditHomeOf(override)
	if h == "" {
		return check{
			name:   "home",
			status: statusBad,
			detail: "cannot resolve a home directory",
			next:   "set HOME, or pass --home <dir>",
		}
	}
	src := "$HOME"
	if override != "" {
		src = "--home"
	}
	return check{name: "home", status: statusOK, detail: fmt.Sprintf("%s (%s)", h, src)}
}

func checkSkillsDir(override string) check {
	h := auditHomeOf(override)
	if h == "" {
		return check{name: "skills dir", status: statusBad, detail: "no home to resolve it against"}
	}
	dir := filepath.Join(h, ".claude", "skills")
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Absent is fine: the first install creates it, along with any missing
		// parents. What matters is whether the nearest EXISTING ancestor can be
		// written, because that is the directory a later MkdirAll would start from.
		//
		// The first version probed the immediate parent and reported "not writable"
		// when that parent did not exist either, which is a different fact and a
		// misleading one: it sent the reader to fix permissions on a path that was
		// not there. A diagnostic that misnames the cause is worse than one that
		// stays quiet.
		anc := nearestExistingAncestor(dir)
		if err := writable(anc); err != nil {
			return check{
				name: "skills dir", status: statusBad,
				detail: fmt.Sprintf("%s does not exist and its nearest existing parent %s is not writable: %v", dir, anc, err),
				next:   "fix the permissions on " + anc,
			}
		}
		return check{
			name: "skills dir", status: statusTodo,
			detail: dir + " does not exist yet",
			next:   "it is created by the first `skillctl install`",
		}
	case err != nil:
		return check{name: "skills dir", status: statusBad, detail: err.Error()}
	case !fi.IsDir():
		return check{
			name: "skills dir", status: statusBad,
			detail: dir + " exists but is not a directory",
			next:   "move it aside; skillctl will not replace a file it did not create",
		}
	}
	n := 0
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				n++
			}
		}
	}
	if err := writable(dir); err != nil {
		return check{
			name: "skills dir", status: statusBad,
			detail: fmt.Sprintf("%s is not writable: %v", dir, err),
			next:   "fix the permissions on " + dir,
		}
	}
	return check{name: "skills dir", status: statusOK, detail: fmt.Sprintf("%s (%d installed)", dir, n)}
}

func checkTrustRoots() check {
	path := trustConfigPath()
	tr, err := verify.Load(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return check{
			name: "trust roots", status: statusTodo,
			detail: path + " not present",
			next:   "`skillctl trust add --registry <url> --pubkey <path>`, or receive a pinned roots file out of band",
		}
	case err != nil:
		// The load-bearing distinction: a file we cannot parse is NOT the same as
		// no file. Refusing to guess is the point.
		return check{
			name: "trust roots", status: statusBad,
			detail: fmt.Sprintf("%s is present but unreadable: %v", path, err),
			next:   "repair or remove the file; skillctl will not fall back to a default trust root",
		}
	case len(tr.Roots) == 0:
		return check{
			name: "trust roots", status: statusTodo,
			detail: path + " parses but pins no registry",
			next:   "`skillctl trust add --registry <url> --pubkey <path>`",
		}
	}
	var pinned, fromRegistry int
	for _, r := range tr.Roots {
		if r.IdentityKeysAuthorized == "pinned" {
			pinned++
		} else {
			fromRegistry++
		}
	}
	c := check{
		name: "trust roots", status: statusOK,
		detail: fmt.Sprintf("%s (%d registry/ies, %d pinned, %d from-registry)", path, len(tr.Roots), pinned, fromRegistry),
	}
	if pinned == 0 {
		// Not a failure: a from-registry root is a valid production posture. It is
		// simply not the posture the offline paths need, and saying so here is
		// cheaper than a confusing refusal later.
		c.next = "`install --bundle` and `verify --bundle` need a root with identity_keys_authorized: pinned"
	}
	return c
}

func checkPeers() check {
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		return check{
			name: "peers", status: statusBad,
			detail: fmt.Sprintf("the pinned-peer file is present but unreadable: %v", err),
			next:   "repair or remove it",
		}
	}
	if len(peers.Peers) == 0 {
		return check{
			name: "peers", status: statusTodo,
			detail: "no pinned peers",
			next:   "`skillctl peer add <name> <locator> --pubkey <b64> --pin sha256:<hex>` after checking the fingerprint over a SECOND channel",
		}
	}
	names := make([]string, 0, len(peers.Peers))
	for _, p := range peers.Peers {
		names = append(names, p.Name)
	}
	return check{name: "peers", status: statusOK, detail: fmt.Sprintf("%d pinned (%s)", len(names), strings.Join(names, ", "))}
}

func checkSigningKey(override string) check {
	h := auditHomeOf(override)
	if h == "" {
		return check{name: "signing key", status: statusBad, detail: "no home to resolve it against"}
	}
	path := defaultSelfKeyPath()
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return check{
				name: "signing key", status: statusTodo,
				detail: "none at " + path,
				next:   "`skillctl keygen --out <path>`; only needed to PUBLISH, not to install",
			}
		}
		return check{name: "signing key", status: statusBad, detail: err.Error()}
	}
	return check{name: "signing key", status: statusOK, detail: path}
}

func checkAuditDir(override string) check {
	h := auditHomeOf(override)
	if h == "" {
		return check{name: "audit logs", status: statusBad, detail: "no home to resolve it against"}
	}
	dir := verdictDir(h)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return check{
			name: "audit logs", status: statusTodo,
			detail: dir + " not created yet",
			next:   "created on the first gate decision or install",
		}
	} else if err != nil {
		return check{name: "audit logs", status: statusBad, detail: err.Error()}
	}
	if err := writable(dir); err != nil {
		// This one matters more than it looks: an unwritable audit directory does
		// NOT stop an install (the producers are fire-and-forget by design), so the
		// only way anyone finds out is here. Silence about it would mean silently
		// losing the evidence the whole trust story rests on.
		return check{
			name: "audit logs", status: statusBad,
			detail: fmt.Sprintf("%s is not writable: %v", dir, err),
			next:   "fix the permissions: installs will still work, but they will stop leaving a record",
		}
	}
	var present []string
	for _, f := range []string{"gate-audit.jsonl", "lifecycle-audit.jsonl", "invocation-trail.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			present = append(present, f)
		}
	}
	detail := dir
	if len(present) > 0 {
		detail += " (" + strings.Join(present, ", ") + ")"
	} else {
		detail += " (no records yet)"
	}
	return check{name: "audit logs", status: statusOK, detail: detail}
}

// nearestExistingAncestor walks up from p until it finds a directory that
// exists. It always terminates: filepath.Dir of the root is the root itself, and
// the root exists on every platform this runs on.
func nearestExistingAncestor(p string) string {
	for {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

// writable reports whether this process can create a file in dir. It probes by
// creating and removing one rather than reading the mode bits, because the mode
// bits answer a different question on Windows, where ACLs decide.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".skillctl-doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
