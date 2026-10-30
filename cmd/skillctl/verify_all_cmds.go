package main

// The sweep preserves existing quarantine policy while reporting incomplete checks.
import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

var loadRootsFn = loadAndPickRoot
var sweepVerifyManagedFn = sweepVerifyManaged
var sweepVerifyOfflineFn = sweepVerifyOffline
var sweepClockFn = time.Now

type sweepCtx struct {
	client      *registry.Client
	root        *verify.TrustRoot
	tenant      string
	govMin      string
	home        string
	registryURL string
}

type sweepVerification struct {
	result *verify.VerifyResult
	scope  string
}

// readSweepInventory distinguishes a missing inventory from an obstructed path.
// Windows can report ErrNotExist when ReadDir encounters a regular file, so a
// missing-path decision also requires an existing directory ancestor.
func readSweepInventory(path string) ([]os.DirEntry, error) {
	for probe := path; ; probe = filepath.Dir(probe) {
		_, err := os.Lstat(probe)
		if err == nil {
			// Stat also resolves Windows junctions and mount points, whose
			// Lstat mode need not carry ModeSymlink or ModeDir.
			info, err := os.Stat(probe)
			if err != nil {
				return nil, err
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("inventory path is not a directory: %s", probe)
			}
			if probe != path {
				return []os.DirEntry{}, nil
			}
			return os.ReadDir(path)
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(probe) == probe {
			return nil, err
		}
	}
}

func runVerifyAll(args []string, stdout, stderr io.Writer) (code int) {
	var diagnostic strings.Builder
	stderr = io.MultiWriter(stderr, &diagnostic)
	fs := flag.NewFlagSet("verify --all", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.Bool("all", false, "Sweep every installed skill.")
	quarantine := fs.Bool("quarantine", false, "Move trust-failing skills into quarantine; availability failures stay in place.")
	jsonOut := fs.Bool("json", false, "Emit a versioned sweep result. Put --json first to include flag parsing failures.")
	budget := fs.Duration("budget", 60*time.Second, "Positive wall-clock budget; unreached skills remain incomplete.")
	homeOverride := fs.String("home", "", "Override the install root.")
	registryURL := fs.String("registry", "", "Registry base URL selected from pinned trust roots.")
	governanceMin := fs.String("governance-min", "", "Override the governance minimum (green | yellow).")
	sessionID := fs.String("session-id", "", "Session identifier for verdict cache rows.")
	rep := sweepReport{Entries: []sweepEntry{}}
	defer func() { finishSweep(&rep, *jsonOut, *quarantine, &code, diagnostic.String(), stdout, stderr) }()
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *budget <= 0 || (*governanceMin != "" && *governanceMin != "green" && *governanceMin != "yellow") {
		fmt.Fprintln(stderr, "verify --all: unexpected operands, nonpositive budget or invalid governance minimum")
		return exitUsage
	}
	if *registryURL != "" {
		if _, _, err := registryOrigin(*registryURL); err != nil {
			fmt.Fprintln(stderr, "verify --all: registry URL requires an HTTP(S) host and no userinfo, query or fragment")
			return exitUsage
		}
	}
	home := *homeOverride
	if home == "" {
		var err error
		home, err = userHome()
		if err != nil {
			fmt.Fprintf(stderr, "verify --all: resolve home: %v\n", err)
			return exitGeneric
		}
	}
	skillsDir := filepath.Join(home, ".claude", "skills")
	rep.SkillsDir = skillsDir
	entries, err := readSweepInventory(skillsDir)
	if err != nil {
		fmt.Fprintf(stderr, "verify --all: enumerate skills: %v\n", err)
		return exitGeneric
	}
	// Empty directories require neither registry access nor a revocation refresh.
	if len(entries) == 0 {
		return exitOK
	}
	start := sweepClockFn()
	tr, root, rootErr := loadRootsFn(*registryURL)
	sc := sweepCtx{home: home, root: root, govMin: *governanceMin, registryURL: *registryURL}
	if rootErr == nil {
		sc.client = newRegistryClient(root.RegistryURL, install.HTTPClientOf(verifyHookTimeout))
		sc.tenant = resolveTenant("", tr)
	} else {
		rep.RootsError = rootErr.Error()
		sc.root = nil
	}
	pol := loadGatePolicy()
	gitRefreshed, gitFailures := refreshGitRegistryRevocations(home, skillsDir, sweepClockFn())
	revoked, fetchedOnline, revErr := sweepRevokedFn(home)
	source := sweepRevocationSource(home, fetchedOnline, revErr)
	if revErr != nil {
		gitFailures = append(gitFailures, revErr.Error())
	}
	rep.RevocationUnavailable = strings.Join(gitFailures, "; ")
	gossip := loadGossipedRevoked(home)
	for _, e := range entries {
		name := e.Name()
		if name == install.StagingDirName {
			continue
		}
		dir := filepath.Join(skillsDir, name)
		info, statErr := os.Stat(dir)
		if statErr == nil && !info.IsDir() {
			continue
		}
		entrySource := source
		if side, ok := loadInstalledSidecar(home, name); ok && gitRefreshed[side.Registry] {
			entrySource = "online"
		}
		entry := newSweepEntry(name, entrySource)
		if statErr != nil {
			entry.Reason = "cannot inspect skill: " + statErr.Error()
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		files, readErr := os.ReadDir(dir)
		if readErr != nil {
			entry.Reason = "cannot enumerate skill: " + readErr.Error()
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		var blobs []string
		managedMarker := false
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".skb") {
				blobs = append(blobs, filepath.Join(dir, file.Name()))
			}
			if file.Name() == ".skillctl-offline.json" || file.Name() == registry.ProvenanceSidecarName || file.Name() == registry.AttestationStashName {
				managedMarker = true
			}
		}
		if len(blobs) == 0 && !managedMarker {
			entry.Scope = "unmanaged_policy"
			entry.Status, entry.State = "skipped", "skipped"
			entry.Reason = "unmanaged (no .skb): not skillctl-installed"
			if pol.Unmanaged == "deny" {
				entry = sweepQuarantine(entry, home, *quarantine, "unmanaged (no .skb) and policy unmanaged_skills=deny", exitGeneric)
			}
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		if len(blobs) != 1 {
			entry.Reason = "managed skill requires exactly one stashed .skb"
			entry.Exit = verify.ExitDigestMismatch
			entry = sweepQuarantine(entry, home, *quarantine, entry.Reason, entry.Exit)
			recordVerdict(home, name, *sessionID, entry.Exit, "", sweepClockFn())
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		if revErr == nil && *budget-sweepClockFn().Sub(start) <= 0 {
			entry.Reason = "sweep budget exceeded: left in place"
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		if revErr != nil {
			if actual, _, inspectErr := inspectSweepBundle(blobs[0]); inspectErr == nil {
				entry.Digest, entry.DigestSource = actual, "actual_bundle"
			}
			entry.Scope = "revocation_policy"
			entry = sweepQuarantine(entry, home, *quarantine, "revocation authority unavailable under managed trust roots and no fresh cache (WF-001 H-F1)", exitRevocationStale)
			entry.Complete = false
			setSweepCheck(&entry, "revocation", "unconfirmed")
			recordVerdict(home, name, *sessionID, exitRevocationStale, "", sweepClockFn())
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		digest, manifest, inspectErr := inspectSweepBundle(blobs[0])
		entry.Digest, entry.DigestSource = digest, "actual_bundle"
		if digest == "" {
			entry.DigestSource = ""
		}
		if inspectErr != nil {
			var pathErr *os.PathError
			if errors.As(inspectErr, &pathErr) {
				entry.Exit = exitGeneric
				entry.Reason = "bundle read unavailable: " + inspectErr.Error() + ": left in place"
				rep.Entries = append(rep.Entries, entry)
				continue
			}
			entry = sweepQuarantine(entry, home, *quarantine, "cannot inspect stashed bundle: "+inspectErr.Error(), verify.ExitDigestMismatch)
			recordVerdict(home, name, *sessionID, verify.ExitDigestMismatch, "", sweepClockFn())
			rep.Entries = append(rep.Entries, entry)
			continue
		}

		if _, denied := revoked[digest]; denied {
			entry.Scope = "revocation_policy"
			if _, fromGossip := gossip[digest]; fromGossip {
				entry.RevocationSource = "gossip"
			}
			entry = sweepQuarantine(entry, home, *quarantine, "revoked: a BundleRevokedEvent was published for this bundle digest", exitBundleRevoked)
			setSweepCheck(&entry, "revocation", "fail")
			recordVerdict(home, name, *sessionID, exitBundleRevoked, "", sweepClockFn())
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		remaining := *budget - sweepClockFn().Sub(start)
		if remaining <= 0 {
			entry.Reason = "sweep budget exceeded: left in place"
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		var verdict sweepVerification
		var vErr error
		vCode := exitGeneric
		if rootErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), remaining)
			verdict, vCode, vErr = sweepVerifyManagedFn(ctx, name, sc)
			cancel()
		} else {
			vErr = rootErr
		}
		if vErr != nil && vCode < verify.ExitDigestMismatch {
			if *budget-sweepClockFn().Sub(start) <= 0 {
				entry.Reason = "sweep budget exceeded before offline fallback: left in place"
				rep.Entries = append(rep.Entries, entry)
				continue
			}
			var available bool
			verdict, vCode, vErr, available = sweepVerifyOfflineFn(name, sc, pol)
			if !available {
				entry.Reason = "could not verify: no eligible offline metadata; left in place"
				entry.Exit = vCode
				rep.Entries = append(rep.Entries, entry)
				continue
			}
		}
		if vErr == nil && vCode == exitOK {
			completeSweepVerification(&entry, verdict, manifest)
			cacheCode := exitOK
			if (entry.Scope == "online_trust_chain" || entry.Scope == "offline_trust_chain") && !entry.DigestVerified {
				cacheCode = exitGeneric
			}
			recordVerdict(home, name, *sessionID, cacheCode, entry.Reason, sweepClockFn())
		} else if vCode >= verify.ExitDigestMismatch {
			entry.Scope = verdict.scope
			if entry.Scope == "" {
				entry.Scope = "not_checked"
			}
			entry = sweepQuarantine(entry, home, *quarantine, reasonForExit(vCode, vErr), vCode)
			recordVerdict(home, name, *sessionID, vCode, "", sweepClockFn())
		} else {
			entry.Exit = vCode
			entry.Reason = "verification inconclusive: left in place"
			if vErr != nil {
				entry.Reason += ": " + vErr.Error()
			}
		}
		rep.Entries = append(rep.Entries, entry)
	}
	for _, e := range rep.Entries {
		appendGateEvent(home, gateEvent{Source: "sweep", Skill: e.Skill, Decision: decisionForSweepState(e.State), Reason: e.Reason, ExitCode: e.Exit, SessionID: *sessionID})
	}
	return exitOK
}

func sweepVerifyManaged(ctx context.Context, name string, sc sweepCtx) (sweepVerification, int, error) {
	res, err := install.VerifyInstalled(install.Opts{Name: name, Client: sc.client, TrustRoot: sc.root, HomeDir: sc.home, GovernanceMin: sc.govMin, Tenant: sc.tenant, Ctx: ctx})
	return sweepVerification{result: res, scope: "online_trust_chain"}, verify.ExitCode(err), err
}

func sweepVerifyOffline(name string, sc sweepCtx, pol gatePolicy) (sweepVerification, int, error, bool) {
	opts := install.Opts{Name: name, TrustRoot: sc.root, HomeDir: sc.home, GovernanceMin: sc.govMin, Tenant: sc.tenant, Ctx: context.Background()}
	if opts.GovernanceMin == "" && sc.root == nil {
		opts.GovernanceMin = pol.ManagedMinGovernance
	}
	if sc.root != nil {
		res, err := install.VerifyInstalledOffline(opts)
		if !errors.Is(err, install.ErrNoOfflineMeta) {
			return sweepVerification{result: res, scope: "offline_trust_chain"}, verify.ExitCode(err), err, true
		}
	}
	// An explicitly selected HTTP registry must never fall back to a self/ER1 root.
	if sc.registryURL != "" {
		return sweepVerification{}, exitGeneric, errors.New("selected registry has no eligible offline metadata"), false
	}
	opts.SelfTrustRoots = peerRootsForInstalled(sc.home, name)
	err := install.VerifyInstalledSidecar(opts)
	if errors.Is(err, registry.ErrNoSidecar) {
		return sweepVerification{}, exitGeneric, err, false
	}
	scope := "sidecar_legacy"
	if _, stashErr := registry.ReadAttestationStash(filepath.Join(sc.home, ".claude", "skills", name)); stashErr == nil {
		scope = "sidecar_reanchored"
	}
	return sweepVerification{scope: scope}, verify.ExitCode(err), err, true
}

// quarantineSkill moves ~/.claude/skills/<name>/ to
// ~/.claude/skillctl/quarantine/<name>.<unix-ts>/ and drops a QUARANTINE.md
// recording why. The move is an os.Rename (same filesystem under ~/.claude).
func quarantineSkill(home, name, reason string, code int) (string, error) {
	src := filepath.Join(home, ".claude", "skills", name)
	qbase := filepath.Join(home, ".claude", "skillctl", "quarantine")
	// #nosec G301 -- Klassenentscheidung: nicht geheimes lokales Artefakt. Die enge Form ist im Baum fuer Geheimnisse besetzt (0600/0700).
	if err := os.MkdirAll(qbase, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(qbase, fmt.Sprintf("%s.%d", name, sweepClockFn().Unix()))
	if err := os.Rename(src, dest); err != nil {
		return "", err
	}
	note := fmt.Sprintf(`# QUARANTINED: %s

This skill failed the SPEC-0188 §7 trust chain during a `+"`skillctl verify --all`"+` sweep
and was moved out of ~/.claude/skills/ so Claude Code will not load it.

- reason:    %s
- exit code: %d
- original:  %s
- moved at:  %s

To restore (only after you trust it again): move this directory back to
~/.claude/skills/%s/ and re-run `+"`skillctl verify %s`"+`, or re-install with
`+"`skillctl install %s`"+`.
`, name, reason, code, src, sweepClockFn().UTC().Format(time.RFC3339), name, name, name)
	// Sibling, NOT inside dest: if the quarantined skill was a symlink, writing
	// inside it would land in the shared target (e.g. gstack/browse). The note
	// sits next to the moved item as <name>.<ts>.QUARANTINE.md.
	// #nosec G306 -- Klassenentscheidung: nicht geheimes lokales Artefakt. Die enge Form ist im Baum fuer Geheimnisse besetzt (0600/0700).
	if err := os.WriteFile(dest+".QUARANTINE.md", []byte(note), 0o644); err != nil {
		return dest, fmt.Errorf("skill moved but quarantine note could not be written: %w", err)
	}
	return dest, nil
}

func printSweepHuman(w io.Writer, rep sweepReport, doQuarantine bool) {
	if rep.RootsError != "" {
		fmt.Fprintf(w, "⚠ selected HTTP trust roots unavailable: %s\n  → inspect each skill's offline check scope.\n", rep.RootsError)
	}
	if rep.RevocationUnavailable != "" {
		fmt.Fprintf(w, "⛔ revocation authority unavailable under managed trust roots + no fresh cache: %s\n  → managed skills FAIL CLOSED (WF-001 H-F1); inspect each quarantine disposition.\n", rep.RevocationUnavailable)
	}
	for _, e := range rep.Entries {
		var mark string
		switch e.State {
		case "verified":
			mark = "✓"
		case "quarantined":
			mark = "⛔"
		case "unverified":
			mark = "?"
		default:
			mark = "–"
		}
		if e.Status == "incomplete" {
			mark = "?"
		}
		line := fmt.Sprintf("  %s %-28s %s [%s; %s]", mark, e.Skill, e.State, e.Status, e.Disposition)
		if e.Reason != "" {
			line += ": " + e.Reason
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "\nswept %d skill(s): %d verified · %d invalid · %d actually quarantined · %d quarantine candidates · %d unverified · %d skipped\n",
		rep.Total, rep.Verified, rep.Invalid, rep.Quarantined, rep.QuarantineCandidates, rep.Unverified, rep.Skipped)
}
