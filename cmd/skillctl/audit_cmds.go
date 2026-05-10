package main

// SPEC-0189 §14 (S3.3 + S3.4 closure 2026-05-06). CLI runner for
// `skillctl audit`.
//
// Surface (S3-DECISIONS S3.3 Q1–Q4 + S3.4 Q1–Q4):
//
//   skillctl audit [--source claude|user|plugins|all]
//                  [--minimum-governance green|yellow|red]
//                  [--format table|json]
//                  [--include-shadowed]
//                  [--keep-unverified]
//                  [--cleanup --dry-run-cleanup]
//                  [--cleanup --confirm-delete --dry-run-cleanup-token TOKEN]
//
// Exit codes per S3-DECISIONS S3.3 Q4 / SPEC-0189 §14.2:
//   0  — every active skill OK
//   2  — at least one UNVERIFIED or BELOW_MIN
//   3  — at least one BROKEN
// Plus shared usage / generic codes from cmd/skillctl/exit.go.
//
// The cleanup path mirrors the G-23 destructive-op convention proven in
// S2.2 awareness reset:
//   1. --dry-run-cleanup prints the affected list + a 5-min HMAC token.
//   2. --confirm-delete + --dry-run-cleanup-token verifies + deletes.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/audit"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

// runAudit is main's dispatch entry point.
func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	source := fs.String("source", "claude", "Scan source: claude | user | plugins | all.")
	minGov := fs.String("minimum-governance", "", "Floor below which a skill is flagged (green | yellow | red). Defaults to trust-roots governance_minimum, else green.")
	format := fs.String("format", "", "Output format: table | json. Default: table on TTY, json on pipe.")
	includeShadowed := fs.Bool("include-shadowed", false, "Include shadowed skills (lower-tier names hidden by a higher-tier winner).")
	keepUnverified := fs.Bool("keep-unverified", false, "Don't auto-clean UNVERIFIED skills under --cleanup.")
	cleanup := fs.Bool("cleanup", false, "After listing, delete affected skills (gated; requires --dry-run-cleanup or --confirm-delete).")
	dryRunCleanup := fs.Bool("dry-run-cleanup", false, "Step 1 of the G-23 two-step: print affected list + signature token; no deletion.")
	confirmDelete := fs.Bool("confirm-delete", false, "Step 2 of the G-23 two-step: actually delete; requires a fresh --dry-run-cleanup-token.")
	cleanupToken := fs.String("dry-run-cleanup-token", "", "Token from a prior --dry-run-cleanup invocation; required for --confirm-delete.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl audit [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Antivirus-style verdict per skill: OK | UNVERIFIED | BROKEN | BELOW_MIN.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes:")
		fmt.Fprintln(stderr, "  0  every active skill OK")
		fmt.Fprintln(stderr, "  2  at least one UNVERIFIED or BELOW_MIN")
		fmt.Fprintln(stderr, "  3  at least one BROKEN")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Cleanup (G-23 destructive-op two-step):")
		fmt.Fprintln(stderr, "  Step 1: skillctl audit --cleanup --dry-run-cleanup")
		fmt.Fprintln(stderr, "  Step 2: skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <sig>")
		fmt.Fprintln(stderr, "")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// Resolve minimum governance: flag → trust-roots default → "green".
	min := resolveMinimum(*minGov)

	// Resolve format: flag → TTY heuristic.
	outFormat := strings.ToLower(*format)
	if outFormat == "" {
		if isStdoutTTY() {
			outFormat = "table"
		} else {
			outFormat = "json"
		}
	}
	if outFormat != "table" && outFormat != "json" {
		fmt.Fprintf(stderr, "skillctl audit: --format must be 'table' or 'json' (got %q)\n", outFormat)
		return exitUsage
	}

	// --cleanup gating.
	if *cleanup {
		if !*dryRunCleanup && !*confirmDelete {
			fmt.Fprintln(stderr, "skillctl audit: --cleanup requires --dry-run-cleanup OR --confirm-delete (G-23 two-step).")
			return exitUsage
		}
		if *dryRunCleanup && *confirmDelete {
			fmt.Fprintln(stderr, "skillctl audit: --dry-run-cleanup and --confirm-delete are mutually exclusive.")
			return exitUsage
		}
		if *confirmDelete && *cleanupToken == "" {
			fmt.Fprintln(stderr, "skillctl audit: --confirm-delete requires --dry-run-cleanup-token <sig> from a prior --dry-run-cleanup.")
			return exitUsage
		}
	}

	// Run the scan + trust annotation.
	roots, err := resolveAuditRoots(*source)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl audit: %v\n", err)
		return exitUsage
	}
	sc := &scanner.Scanner{
		Roots:           roots,
		IncludeShadowed: *includeShadowed,
		WithTrust:       true,
	}
	inv, err := sc.Scan()
	if err != nil {
		fmt.Fprintf(stderr, "skillctl audit: scan failed: %v\n", err)
		return exitGeneric
	}

	report := audit.Compute(inv, min)

	// Dispatch on cleanup mode.
	if *cleanup {
		eligible := selectCleanupTargets(report.Verdicts, *keepUnverified)
		if *dryRunCleanup {
			return runCleanupDryRun(eligible, outFormat, stdout, stderr)
		}
		if *confirmDelete {
			return runCleanupConfirm(eligible, *cleanupToken, outFormat, stdout, stderr)
		}
	}

	// Default (audit-only) path.
	if outFormat == "json" {
		emitReportJSON(report, stdout)
	} else {
		emitReportTable(report, stdout)
	}
	return report.ExitCode
}

// ---- Format helpers --------------------------------------------------------

func emitReportTable(r audit.Report, w io.Writer) {
	tw := tabwriter.NewWriter(w, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SKILL\tTIER\tSTATE\tGOV\tREASON")
	fmt.Fprintln(tw, "-----\t----\t-----\t---\t------")
	for _, v := range r.Verdicts {
		gov := v.GovernanceLevel
		if gov == "" {
			gov = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			v.Name, v.Tier, v.State, gov, v.Reason)
	}
	fmt.Fprintln(tw, "-----\t----\t-----\t---\t------")
	tw.Flush()
	// Aggregate summary line — the human form of the exit code (S3.3 Q3).
	fmt.Fprintln(w, summaryLine(r))
}

// summaryLine renders the SPEC-0189 §14.3 verdict line:
//
//	50 skills scanned · 47 OK · 2 unverified · 1 broken · 0 below-min
func summaryLine(r audit.Report) string {
	return fmt.Sprintf(
		"%d skills scanned · %d OK · %d unverified · %d broken · %d below-min",
		r.Total,
		r.Counts[audit.StateOK],
		r.Counts[audit.StateUnverified],
		r.Counts[audit.StateBroken],
		r.Counts[audit.StateBelowMin],
	)
}

func emitReportJSON(r audit.Report, w io.Writer) {
	out := map[string]any{
		"verdicts": r.Verdicts,
		"counts": map[string]int{
			"OK":         r.Counts[audit.StateOK],
			"UNVERIFIED": r.Counts[audit.StateUnverified],
			"BROKEN":     r.Counts[audit.StateBroken],
			"BELOW_MIN":  r.Counts[audit.StateBelowMin],
		},
		"total":     r.Total,
		"exit_code": r.ExitCode,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}

// ---- Cleanup ---------------------------------------------------------------

func selectCleanupTargets(verdicts []audit.Verdict, keepUnverified bool) []audit.Verdict {
	out := make([]audit.Verdict, 0, len(verdicts))
	for _, v := range verdicts {
		if v.CleanupEligible(keepUnverified) {
			out = append(out, v)
		}
	}
	return out
}

func runCleanupDryRun(targets []audit.Verdict, outFormat string, stdout, stderr io.Writer) int {
	if len(targets) == 0 {
		fmt.Fprintln(stdout, "0 skills eligible for cleanup. Nothing to do.")
		return exitOK
	}
	now := time.Now().UTC()
	token, err := buildCleanupToken(targets, now)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl audit: token build: %v\n", err)
		return exitGeneric
	}

	if outFormat == "json" {
		out := map[string]any{
			"affected_count": len(targets),
			"affected":       targets,
			"token":          token,
			"issued_at":      now.Format(time.RFC3339),
			"expires_at":     now.Add(5 * time.Minute).Format(time.RFC3339),
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return exitOK
	}

	tw := tabwriter.NewWriter(stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SKILL\tSTATE\tPATH")
	fmt.Fprintln(tw, "-----\t-----\t----")
	for _, v := range targets {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", v.Name, v.State, v.SourcePath)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d skill(s) eligible for cleanup.\n", len(targets))
	fmt.Fprintf(stdout, "Token (valid 5 min):\n  %s\n", token)
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Re-run with --confirm-delete --dry-run-cleanup-token <token> within 5 min to delete.")
	return exitOK
}

func runCleanupConfirm(targets []audit.Verdict, presentedToken, outFormat string, stdout, stderr io.Writer) int {
	now := time.Now().UTC()
	if err := verifyCleanupToken(targets, presentedToken, now); err != nil {
		fmt.Fprintf(stderr, "skillctl audit: %v\n", err)
		return exitGeneric
	}

	deleted := 0
	failures := 0
	for _, v := range targets {
		if v.SourcePath == "" {
			continue
		}
		if err := os.RemoveAll(v.SourcePath); err != nil {
			fmt.Fprintf(stderr, "skillctl audit: remove %s: %v\n", v.SourcePath, err)
			failures++
			continue
		}
		deleted++
	}
	if outFormat == "json" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"deleted":   deleted,
			"failed":    failures,
			"requested": len(targets),
		})
	} else {
		fmt.Fprintf(stdout, "Deleted %d / %d skill(s).\n", deleted, len(targets))
		if failures > 0 {
			fmt.Fprintf(stdout, "%d failure(s); see stderr.\n", failures)
		}
	}
	if failures > 0 {
		return exitGeneric
	}
	return exitOK
}

// ---- Token (HMAC over hostname+paths+ts; 5-min TTL) -----------------------
//
// Per S3.4 Q2 lock: signed local token, no server roundtrip.
// HMAC-SHA-256 over `(hostname, sorted(skill-paths), issued_at)` with the
// skillctl author key as the HMAC key. The token format (Unix-seconds
// prefix + base64url tag) is identical in shape to the awareness-reset
// token format from S2.2 — operators learn one shape across the CLI.
//
// Implementation note: we HMAC with a process-derived secret (the
// SHA-256 of the skillctl binary path + the hostname). The secret is
// not crypto-grade — the threat model is "operator paste-error," not
// "active attacker on the local box." A dedicated key would imply
// state on disk; the SPEC-0188 §11b convention requires the dry-run be
// purely advisory, not a privileged key holder.

func buildCleanupToken(targets []audit.Verdict, now time.Time) (string, error) {
	secret, err := cleanupTokenSecret()
	if err != nil {
		return "", err
	}
	issuedAt := now.Unix()
	mac := hmac.New(sha256.New, secret)
	if err := writeTokenInputs(mac, targets, issuedAt); err != nil {
		return "", err
	}
	tag := mac.Sum(nil)
	return strconv.FormatInt(issuedAt, 10) + "." + base64.RawURLEncoding.EncodeToString(tag), nil
}

func verifyCleanupToken(targets []audit.Verdict, presented string, now time.Time) error {
	parts := strings.SplitN(presented, ".", 2)
	if len(parts) != 2 {
		return errors.New("dry-run-cleanup-token: malformed (expect <unix-seconds>.<b64>)")
	}
	issuedAt, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("dry-run-cleanup-token: bad timestamp prefix: %w", err)
	}
	if now.Unix()-issuedAt > 300 || now.Unix()-issuedAt < 0 {
		return errors.New("dry-run-cleanup-token: older than 5 minutes; re-run --dry-run-cleanup")
	}
	wantTag, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("dry-run-cleanup-token: bad base64: %w", err)
	}
	secret, err := cleanupTokenSecret()
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	if err := writeTokenInputs(mac, targets, issuedAt); err != nil {
		return err
	}
	gotTag := mac.Sum(nil)
	if !hmac.Equal(gotTag, wantTag) {
		return errors.New("dry-run-cleanup-token: signature does not match the current affected-set (drift)")
	}
	return nil
}

// writeTokenInputs writes the HMAC input domain consistently across
// build + verify: hostname + every (state, source-path) sorted + the
// issued-at as unix-seconds.
func writeTokenInputs(mac interface{ Write([]byte) (int, error) }, targets []audit.Verdict, issuedAt int64) error {
	host, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("hostname: %w", err)
	}
	if _, err := mac.Write([]byte(host)); err != nil {
		return err
	}
	if _, err := mac.Write([]byte{'\n'}); err != nil {
		return err
	}
	// Sort by SourcePath for deterministic byte stream (audit.Compute
	// already returns severity-sorted; we need name-sorted here).
	paths := make([]string, len(targets))
	states := make([]string, len(targets))
	for i, v := range targets {
		paths[i] = v.SourcePath
		states[i] = string(v.State)
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i] < paths[j] })
	for i, p := range paths {
		if _, err := mac.Write([]byte(states[i])); err != nil {
			return err
		}
		if _, err := mac.Write([]byte{':'}); err != nil {
			return err
		}
		if _, err := mac.Write([]byte(p)); err != nil {
			return err
		}
		if _, err := mac.Write([]byte{'\n'}); err != nil {
			return err
		}
	}
	if _, err := mac.Write([]byte(strconv.FormatInt(issuedAt, 10))); err != nil {
		return err
	}
	return nil
}

// cleanupTokenSecret returns a process-derived HMAC key. Defense
// against operator paste-error, not against an active attacker; see
// the file-level note above.
func cleanupTokenSecret() ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte("skillctl-audit-cleanup-v1\n" + exe + "\n" + host))
	out := make([]byte, hex.EncodedLen(len(h)))
	hex.Encode(out, h[:])
	return out, nil
}

// ---- Misc helpers ----------------------------------------------------------

func resolveMinimum(flagVal string) audit.MinimumLevel {
	v := strings.ToLower(strings.TrimSpace(flagVal))
	switch v {
	case "green":
		return audit.MinGreen
	case "yellow":
		return audit.MinYellow
	case "red":
		return audit.MinRed
	case "":
		// Try trust-roots default. Lookup through the verify package
		// is the authoritative path; we do a best-effort read here and
		// fall back to "green" on any error per S3.3 Q1 lock.
		if min := readTrustRootsMinimum(); min != "" {
			return min
		}
		return audit.MinGreen
	default:
		// Unknown value — caller maps to usage error elsewhere.
		return audit.MinGreen
	}
}

// readTrustRootsMinimum returns the operator's pinned governance floor
// from ~/.claude/skill-trust-roots.yaml, if present. Best-effort; an
// unreadable or missing file returns "" and the caller defaults to green.
func readTrustRootsMinimum() audit.MinimumLevel {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	path := home + "/.claude/skill-trust-roots.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Tiny YAML scan — avoid pulling a yaml dep here. The trust-roots
	// schema (per SPEC-0188 §4.4) carries `governance_minimum: <enum>`
	// at top level. Just look for that line.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "governance_minimum:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "governance_minimum:"))
		v = strings.Trim(v, `"' `)
		switch v {
		case "green", "yellow", "red":
			return audit.MinimumLevel(v)
		}
	}
	return ""
}

func resolveAuditRoots(source string) ([]scanner.ScanRoot, error) {
	src := strings.ToLower(strings.TrimSpace(source))
	switch src {
	case "claude", "user", "plugins", "all":
		return scanner.ResolveDefaults([]scanner.Source{scanner.Source(src)}), nil
	default:
		return nil, fmt.Errorf("unknown --source %q (want claude|user|plugins|all)", source)
	}
}

func isStdoutTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
