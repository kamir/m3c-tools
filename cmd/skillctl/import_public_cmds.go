// import_public_cmds.go — `skillctl import-public` (SPEC-0201 P1-P4).
//
// Untrusted Upstream Adapter (Import Airlock) MVP. Stops untrusted upstream
// skills from entering the registry by force-routing them through staging +
// scan + a hand-off to `skillctl propose`.
//
// Flow:
//  1. Parse the upstream reference (pin required → exit 4).
//  2. Load source policy (~/.claude/skill-import-policy.yaml or --policy).
//     Missing → exit 17.
//  3. policy.Evaluate(ref). Block → exit 19; RequireReview → log + continue.
//  4. Fetch the upstream bundle by HTTPS (host's standard release URL).
//     Verify SHA-256 matches the pin.
//  5. Stage to ~/.cache/m3c/imports/<host>/<owner>/<name>/<sha>/.
//  6. Run pre-flight scanner. Refuse → exit 5; warn-only without
//     --accept-yellow → exit 18.
//  7. Print the next-step `skillctl propose` command. Exit 0.
//
// The MVP does NOT auto-run propose; the operator runs it explicitly. This is
// SPEC-0201 D2 (two-step locked).
//
// Pin / fetch URL convention (v1):
//
//	https://<host>/<owner>/<name>/releases/download/sha256-<hex>.skb
//
// If a host needs a different URL pattern in a future phase, this function
// gains a per-host resolver.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/bodyscan"
	skillparser "github.com/kamir/m3c-tools/pkg/skillctl/parser"
	"github.com/kamir/m3c-tools/pkg/skillimport/parser"
	"github.com/kamir/m3c-tools/pkg/skillimport/policy"
	"github.com/kamir/m3c-tools/pkg/skillimport/scanner"
)

// SPEC-0201 §11 exit codes (the five this surface needs).
//
// These numeric codes are the same as the install/pack/awareness-reset codes
// 17/18/19 in pkg/skillctl/verify/errors.go (ExitDataSourceDenied,
// ExitIntentInconsistent, ExitIdentityMismatch). The themes are intentionally
// shared — "17 = data-source / source-policy", "18 = intent contradiction",
// "19 = identity / source-block" — but the import-public surface needs to
// surface SLIGHTLY different reason strings ("no_source_policy", "intent_capped",
// "source_blocked") so the operator gets the airlock-specific message.
//
// Cross-reference: PROJECTS/Skill-Manager/SKILLCTL-MANUAL.md §"Exit-code
// table" enumerates the polysemy per command. Future audit may canonicalize
// to a single ExitCode type — until then, the numeric agreement is the
// cross-command guarantee, and the per-surface labels are the local UX.
const (
	exitImportPinRequired   = 4
	exitImportScannerRefuse = 5

	// exitImportBodyscanRefuse (6) — SPEC-0246 §4.5: the staged SKILL.md body
	// tripped a 🔴 (red) bodyscan finding (prompt injection / exfiltration /
	// tool-escalation / policy-subversion). Distinct from the STRUCTURAL
	// scanner refuse (5, dangerous side-effect declarations in bundle.json):
	// 6 means "the prose itself is hostile." Refused by default; --accept-yellow
	// does NOT lift a red (fail-closed). The bodyscan-report.json sidecar records
	// the findings for the propose hand-off.
	exitImportBodyscanRefuse = 6

	// Numerically equal to verify.ExitDataSourceDenied (17). Surfaces as
	// "no_source_policy" in the airlock; the install/verify path surfaces
	// the same code as "data_source_denied" / "identity_revoked" (SPEC-0198).
	exitImportNoSourcePolicy = 17

	// Numerically equal to verify.ExitIntentInconsistent (18). Surfaces as
	// "intent_capped" in the airlock; pack uses the same code for
	// "intent_inconsistent" cross-field validation refusals.
	exitImportIntentCapped = 18

	// Numerically equal to verify.ExitIdentityMismatch (19). Surfaces as
	// "source_blocked" in the airlock; install uses the same code for
	// "identity_mismatch" and awareness reset uses it for the same theme.
	exitImportSourceBlocked = 19
)

// HTTPClient is the http.Client used for upstream fetches. Overridable in tests.
var HTTPClient = &http.Client{Timeout: 60 * time.Second}

// fetchURLOverride lets tests inject a synthetic URL resolver. nil in production.
var fetchURLOverride func(ref *parser.Reference) string

// printImportPublicUsage prints the help text.
func printImportPublicUsage() {
	fmt.Print(`skillctl import-public — SPEC-0201 untrusted-upstream import airlock

Usage:
  skillctl import-public <reference>
                        [--policy <path>]
                        [--staging <dir>]
                        [--accept-yellow]
                        [--target <prod|stage|local>]

Reference syntax:
  <host>:<owner>/<name>@sha256:<64hex>
  <host>/<owner>/<name>@sha256:<64hex>

Flags:
  --policy <path>    Source policy file (default: ~/.claude/skill-import-policy.yaml)
  --staging <dir>    Staging root (default: ~/.cache/m3c/imports/)
  --accept-yellow    Accept warn-only scan verdicts (still refuses on critical)
  --target <env>     Hand-off target hint for the printed propose command

Exit codes (SPEC-0201 §11 / SPEC-0246 §4.5):
   4   pin_required           — reference missing @sha256:<hex>
   5   scanner_refuse         — staged bundle has critical structural findings
   6   bodyscan_refuse        — staged SKILL.md body has 🔴 behavioural findings
  17   no_source_policy       — policy file missing or wrong path
  18   upstream_intent_capped — warn-only scan / 🟡 bodyscan; needs --accept-yellow
  19   source_blocked         — host or owner blocked by policy

Sample:
  skillctl import-public github.com:anthropics/code-reviewer@sha256:<hex>
  skillctl import-public skillhub.club:myorg/didactic@sha256:<hex> --accept-yellow
`)
}

// runImportPublic is the entrypoint. Returns the OS exit code.
func runImportPublic(args []string) int {
	if len(args) == 0 {
		printImportPublicUsage()
		return 1
	}

	var (
		refArg       string
		policyPath   string
		stagingRoot  string
		acceptYellow bool
		targetHint   string
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help", "help":
			printImportPublicUsage()
			return 0
		case "--policy":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "import-public: --policy requires an argument")
				return 1
			}
			i++
			policyPath = args[i]
		case "--staging":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "import-public: --staging requires an argument")
				return 1
			}
			i++
			stagingRoot = args[i]
		case "--accept-yellow":
			acceptYellow = true
		case "--target":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "import-public: --target requires an argument")
				return 1
			}
			i++
			targetHint = args[i]
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "import-public: unknown flag: %s\n", a)
				return 1
			}
			if refArg != "" {
				fmt.Fprintf(os.Stderr, "import-public: unexpected positional %q (reference already given)\n", a)
				return 1
			}
			refArg = a
		}
	}

	if refArg == "" {
		fmt.Fprintln(os.Stderr, "import-public: reference is required")
		printImportPublicUsage()
		return 1
	}

	// 1. Parse reference.
	ref, err := parser.Parse(refArg)
	if err != nil {
		if errors.Is(err, parser.ErrPinRequired) {
			fmt.Fprintf(os.Stderr, "import-public: pin required: reference must end with @sha256:<64hex>\n")
			return exitImportPinRequired
		}
		fmt.Fprintf(os.Stderr, "import-public: parse reference: %v\n", err)
		return exitImportPinRequired
	}

	// 2. Load source policy.
	if policyPath == "" {
		policyPath = policy.DefaultPath()
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		if errors.Is(err, policy.ErrNoSourcePolicy) {
			fmt.Fprintf(os.Stderr, "import-public: no source policy at %s\n", policyPath)
			fmt.Fprintln(os.Stderr, "  Create one with at least: version: 1, default_deny: true, allowed_hosts: [...].")
			return exitImportNoSourcePolicy
		}
		fmt.Fprintf(os.Stderr, "import-public: load source policy: %v\n", err)
		return exitImportNoSourcePolicy
	}

	// 3. Evaluate policy.
	decision, reason := pol.Evaluate(ref)
	switch decision {
	case policy.Block:
		fmt.Fprintf(os.Stderr, "import-public: source blocked: %s (host=%q, owner=%q)\n", reason, ref.Host, ref.Owner)
		return exitImportSourceBlocked
	case policy.RequireReview:
		fmt.Fprintf(os.Stderr, "import-public: WARNING: host %q not in allowlist (%s); proceeding because default_deny=false\n", ref.Host, reason)
	case policy.Allow:
		fmt.Fprintf(os.Stderr, "import-public: source allowed (host=%q)\n", ref.Host)
	}

	// 4. Resolve staging root.
	if stagingRoot == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			fmt.Fprintf(os.Stderr, "import-public: resolve home dir: %v\n", herr)
			return 1
		}
		stagingRoot = filepath.Join(home, ".cache", "m3c", "imports")
	}
	stagingDir := filepath.Join(stagingRoot, ref.Host, ref.Owner, ref.Name, ref.PinHex())
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "import-public: create staging dir %s: %v\n", stagingDir, err)
		return 1
	}

	// 5. Fetch bundle.
	fetchURL := defaultFetchURL(ref)
	if fetchURLOverride != nil {
		fetchURL = fetchURLOverride(ref)
	}
	if !strings.HasPrefix(fetchURL, "http://") && !strings.HasPrefix(fetchURL, "https://") {
		fmt.Fprintf(os.Stderr, "import-public: unsupported URL scheme %q\n", fetchURL)
		return 1
	}
	fmt.Fprintf(os.Stderr, "import-public: fetching %s\n", fetchURL)
	bundleBytes, err := fetchAndVerify(fetchURL, ref.PinHex())
	if err != nil {
		fmt.Fprintf(os.Stderr, "import-public: fetch: %v\n", err)
		return 1
	}

	// 6. Persist bundle bytes + extract minimal metadata. The MVP staging layout
	//    writes the raw bundle as bundle.skb. A future phase unpacks it into the
	//    staging dir. For P1-P4, we persist the bytes and any inline JSON found
	//    in the bundle archive expansion is left to a follow-up phase.
	//    For the scanner to function on staged dirs that contain bundle.json /
	//    .claude/skill.md / package.json, an unpack step is required when those
	//    are present in the upstream bundle. The MVP performs a simple check:
	//    if the bundle bytes look like a directory tree (bundle.json|skill.md
	//    appear as separate files via untar), the operator unpacks; otherwise
	//    we drop the .skb at the staging root.
	bundlePath := filepath.Join(stagingDir, "bundle.skb")
	if err := os.WriteFile(bundlePath, bundleBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "import-public: write bundle: %v\n", err)
		return 1
	}

	// Operator-friendly: also write a manifest json that records the pin + URL
	// so future tooling can re-resolve without re-fetching.
	if err := writeImportRecord(stagingDir, ref, fetchURL, len(bundleBytes)); err != nil {
		fmt.Fprintf(os.Stderr, "import-public: write import record: %v\n", err)
		return 1
	}

	// 7. Run the scanner over whatever the bundle expanded to. If the staging
	//    dir contains the expected files (bundle.json / skill.md / package.json),
	//    the scanner finds them. If not, the scanner returns clean and the
	//    later `propose` step will gate the bundle on its own checks.
	rep, err := scanner.Scan(stagingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import-public: scan: %v\n", err)
		return 1
	}

	// Persist the scan report for the propose hand-off.
	scanPath := filepath.Join(stagingDir, "scan-report.json")
	scanData, _ := json.MarshalIndent(rep, "", "  ")
	_ = os.WriteFile(scanPath, scanData, 0o644)

	switch rep.Verdict {
	case scanner.VerdictRefuse:
		fmt.Fprintln(os.Stderr, "import-public: scanner REFUSED (critical findings):")
		for _, f := range rep.Findings {
			if f.Severity == scanner.SevCritical {
				fmt.Fprintf(os.Stderr, "  [%s/%s] %s: %s\n", f.Rule, f.Severity, f.Path, f.Message)
			}
		}
		return exitImportScannerRefuse

	case scanner.VerdictWarn:
		fmt.Fprintln(os.Stderr, "import-public: scanner WARN (high-severity findings):")
		for _, f := range rep.Findings {
			fmt.Fprintf(os.Stderr, "  [%s/%s] %s: %s\n", f.Rule, f.Severity, f.Path, f.Message)
		}
		if !acceptYellow {
			fmt.Fprintln(os.Stderr, "import-public: re-run with --accept-yellow to proceed (importer-author intent capped at yellow per SPEC-0201 D3)")
			return exitImportIntentCapped
		}
		fmt.Fprintln(os.Stderr, "import-public: --accept-yellow set; continuing past warn verdict")

	case scanner.VerdictClean:
		fmt.Fprintln(os.Stderr, "import-public: scanner clean")
	}

	// 7b. Behavioural bodyscan over the bundle's SKILL.md body (SPEC-0246 §4.5).
	// The structural scanner above reads declarations (bundle.json side_effects);
	// bodyscan reads the PROSE for prompt-injection / exfiltration / tool-escalation
	// / policy-subversion / obfuscation. A bodyscan-report.json sidecar is written
	// next to scan-report.json so the propose hand-off (and any audit) can inspect
	// it. 🔴 refuses by default (exit 6, fail-closed — --accept-yellow does NOT lift
	// it); 🟡 follows the same --accept-yellow gate as the structural warn. P1b: the
	// airlock UNPACKS the real .skb to scan the body inside; if it cannot introspect
	// a body it REFUSES (fail-closed) rather than silently admit an unscanned bundle.
	if code := runImportBodyscan(stagingDir, bundleBytes, acceptYellow); code != 0 {
		return code
	}

	// 8. Hand-off message. Do NOT auto-run propose.
	fmt.Println()
	fmt.Println("Staged at:", stagingDir)
	fmt.Println("Scan report:", scanPath)
	fmt.Println()
	fmt.Println("Next step:")
	fmt.Printf("  skillctl propose --staging %s --derived-from %s", stagingDir, ref.String())
	if targetHint != "" {
		fmt.Printf(" --target %s", targetHint)
	}
	fmt.Println()
	return 0
}

// runImportBodyscan resolves the bundle's SKILL.md body, runs the SPEC-0246
// bodyscan over it, writes a bodyscan-report.json sidecar, and returns the OS
// exit code the airlock should use: 0 to continue, exitImportBodyscanRefuse (6)
// on a 🔴 verdict (or any case the body could not be scanned), exitImportIntentCapped
// (18) on a 🟡 verdict without --accept-yellow.
//
// P1b fail-closed contract (SPEC-0246 §4.5): the airlock MUST NOT admit a bundle
// whose body it never scanned. It first UNPACKS the real .skb (bundleBytes) and
// looks for a SKILL.md inside; if found it scans that. It also honours an
// already-staged on-disk SKILL.md (the pre-unpacked test/dev layout). If it has
// a bundle but cannot introspect ANY body from it — unpack fails, or the archive
// carries no SKILL.md — it REFUSES (exit 6) rather than silently admitting an
// unscanned RED body at exit 0. An oversized/not-actually-scanned body is also a
// hard refuse (NotScanned), never an --accept-yellow slip-through.
func runImportBodyscan(stagingDir string, bundleBytes []byte, acceptYellow bool) int {
	body, allowedTools, intent, source, err := resolveImportBody(stagingDir, bundleBytes)
	if err != nil {
		// Fail-closed: we have a bundle but cannot introspect a body to scan.
		fmt.Fprintf(os.Stderr, "import-public: bodyscan REFUSED — cannot scan bundle body: %v\n", err)
		fmt.Fprintln(os.Stderr, "import-public: an un-introspectable bundle is refused (fail-closed); the airlock will not admit a body it never scanned.")
		return exitImportBodyscanRefuse
	}
	fmt.Fprintf(os.Stderr, "import-public: bodyscan source: %s\n", source)

	in := bodyscan.Input{Body: body, AllowedTools: allowedTools, Intent: intent}
	bsRep := bodyscan.Scan(in)

	// Persist the sidecar next to scan-report.json regardless of verdict.
	bsPath := filepath.Join(stagingDir, "bodyscan-report.json")
	if data, mErr := json.MarshalIndent(bsRep, "", "  "); mErr == nil {
		_ = os.WriteFile(bsPath, data, 0o644)
	}

	// Fail-closed: an oversized/not-actually-scanned body carries no evidence it
	// is safe — refuse like a 🔴 (a >1 MiB injection must not slip through via
	// --accept-yellow). SPEC-0246 §4.5 P1b.
	if bodyscan.NotScanned(bsRep) {
		fmt.Fprintln(os.Stderr, "import-public: bodyscan REFUSED — body too large to scan (not scanned):")
		for _, f := range bsRep.Findings {
			fmt.Fprintf(os.Stderr, "  [%s/%s] %s\n", f.RuleID, f.Category, f.Message)
		}
		fmt.Fprintf(os.Stderr, "import-public: bodyscan report: %s\n", bsPath)
		fmt.Fprintln(os.Stderr, "import-public: an un-scanned body is refused (fail-closed); --accept-yellow does not lift it.")
		return exitImportBodyscanRefuse
	}

	switch bsRep.Verdict {
	case bodyscan.VerdictRed:
		fmt.Fprintln(os.Stderr, "import-public: bodyscan REFUSED (🔴 behavioural findings in SKILL.md body):")
		for _, f := range bsRep.Findings {
			if f.Verdict == bodyscan.VerdictRed {
				fmt.Fprintf(os.Stderr, "  [%s/%s] line %d: %s\n", f.RuleID, f.Category, f.Span.Line, f.Message)
			}
		}
		fmt.Fprintf(os.Stderr, "import-public: bodyscan report: %s\n", bsPath)
		fmt.Fprintln(os.Stderr, "import-public: a 🔴 bodyscan cannot be accepted (fail-closed); --accept-yellow does not lift it.")
		return exitImportBodyscanRefuse

	case bodyscan.VerdictYellow:
		fmt.Fprintln(os.Stderr, "import-public: bodyscan WARN (🟡 behavioural findings in SKILL.md body):")
		for _, f := range bsRep.Findings {
			fmt.Fprintf(os.Stderr, "  [%s/%s] line %d: %s\n", f.RuleID, f.Category, f.Span.Line, f.Message)
		}
		fmt.Fprintf(os.Stderr, "import-public: bodyscan report: %s\n", bsPath)
		if !acceptYellow {
			fmt.Fprintln(os.Stderr, "import-public: re-run with --accept-yellow to proceed past the 🟡 bodyscan verdict (SPEC-0246 §4.6 requires an explicit rationale at propose time)")
			return exitImportIntentCapped
		}
		fmt.Fprintln(os.Stderr, "import-public: --accept-yellow set; continuing past 🟡 bodyscan verdict")
		return 0

	default: // VerdictGreen
		fmt.Fprintln(os.Stderr, "import-public: bodyscan clean (🟢)")
		return 0
	}
}

// resolveImportBody finds the SKILL.md body to scan, returning the parsed body +
// declared allowed-tools/intent and a human-readable source label. Resolution
// order, fail-closed:
//
//  1. On-disk staged SKILL.md (a pre-unpacked dev/test layout, e.g. .claude/skill.md).
//  2. UNPACK the real .skb (bundleBytes) and read the SKILL.md inside it.
//
// If neither yields a body, returns a non-nil error so the caller REFUSES — the
// airlock must never admit a bundle whose body it could not scan.
func resolveImportBody(stagingDir string, bundleBytes []byte) (body string, allowedTools []string, intent, source string, err error) {
	// 1. Already-staged SKILL.md on disk.
	if skillMD := locateStagedSkillMD(stagingDir); skillMD != "" {
		raw, rErr := os.ReadFile(skillMD)
		if rErr != nil {
			return "", nil, "", "", fmt.Errorf("read staged %s: %w", skillMD, rErr)
		}
		b, at, in := parseSkillBody(raw)
		return b, at, in, "staged " + filepath.Base(skillMD), nil
	}

	// 2. Unpack the real .skb and read the SKILL.md inside.
	if len(bundleBytes) == 0 {
		return "", nil, "", "", errors.New("no SKILL.md staged and no bundle bytes to unpack")
	}
	entries, uErr := skillbundle.Unpack(bundleBytes, skillbundle.UnpackOptions{
		StripWrapper:   true,
		CanonicalizeMD: true,
	})
	if uErr != nil {
		return "", nil, "", "", fmt.Errorf("unpack bundle to locate SKILL.md: %w", uErr)
	}
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		// After CanonicalizeMD a root-level skill.md is renamed to SKILL.md;
		// accept a nested .claude/SKILL.md too (case-insensitive).
		base := strings.ToLower(filepath.Base(e.Rel))
		if base == "skill.md" {
			b, at, in := parseSkillBody(e.Content)
			return b, at, in, "bundle:" + e.Rel, nil
		}
	}
	return "", nil, "", "", errors.New("bundle contains no SKILL.md to scan")
}

// parseSkillBody splits frontmatter from body; on a frontmatter parse error it
// falls back to scanning the whole file as the body (fail-toward-scanning).
func parseSkillBody(raw []byte) (body string, allowedTools []string, intent string) {
	fm, b, perr := skillparser.Parse(raw)
	if perr != nil {
		return string(raw), nil, ""
	}
	if fm != nil {
		return b, fm.AllowedTools, fm.Intent
	}
	return b, nil, ""
}

// locateStagedSkillMD walks stagingDir for an on-disk SKILL.md, preferring
// .claude/SKILL.md, then any root-level SKILL.md (case-insensitive — Linux
// packs ship "skill.md", Claude Code expects "SKILL.md"). It deliberately
// ignores the raw bundle.skb (which is unpacked separately). Returns "" when
// none is found on disk.
func locateStagedSkillMD(stagingDir string) string {
	var preferred, fallback string
	_ = filepath.Walk(stagingDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil //nolint:nilerr // best-effort walk; unreadable entries are skipped
		}
		rel, relErr := filepath.Rel(stagingDir, path)
		if relErr != nil {
			return nil
		}
		if strings.EqualFold(rel, filepath.Join(".claude", "skill.md")) {
			preferred = path
			return nil
		}
		if strings.EqualFold(filepath.Base(rel), "skill.md") && fallback == "" {
			fallback = path
		}
		return nil
	})
	if preferred != "" {
		return preferred
	}
	return fallback
}

// defaultFetchURL is the v1 URL resolver: every host serves the bundle at the
// same `/releases/download/sha256-<hex>.skb` path. Per-host overrides are a
// follow-up.
func defaultFetchURL(ref *parser.Reference) string {
	return fmt.Sprintf("https://%s/%s/%s/releases/download/sha256-%s.skb",
		ref.Host, ref.Owner, ref.Name, ref.PinHex())
}

// fetchAndVerify GETs the URL, hashes the response, and verifies it matches
// expectedHex. Returns the body bytes on success.
func fetchAndVerify(url, expectedHex string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "skillctl-import-public/1")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != expectedHex {
		return nil, fmt.Errorf("digest mismatch: expected sha256:%s, got sha256:%s", expectedHex, got)
	}
	return body, nil
}

// importRecord is the small JSON sidecar written next to the staged bundle.
type importRecord struct {
	Reference string `json:"reference"`
	Host      string `json:"host"`
	Owner     string `json:"owner"`
	Name      string `json:"name"`
	Pin       string `json:"pin"`
	FetchURL  string `json:"fetch_url"`
	FetchedAt string `json:"fetched_at"`
	Bytes     int    `json:"bytes"`
}

func writeImportRecord(dir string, ref *parser.Reference, url string, n int) error {
	rec := importRecord{
		Reference: ref.String(),
		Host:      ref.Host,
		Owner:     ref.Owner,
		Name:      ref.Name,
		Pin:       ref.Pin,
		FetchURL:  url,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Bytes:     n,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "import-record.json"), data, 0o644)
}
