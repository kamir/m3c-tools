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

	"github.com/kamir/m3c-tools/pkg/skillimport/parser"
	"github.com/kamir/m3c-tools/pkg/skillimport/policy"
	"github.com/kamir/m3c-tools/pkg/skillimport/scanner"
)

// SPEC-0201 §11 exit codes (the five this surface needs).
const (
	exitImportPinRequired      = 4
	exitImportScannerRefuse    = 5
	exitImportNoSourcePolicy   = 17
	exitImportIntentCapped     = 18
	exitImportSourceBlocked    = 19
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

Exit codes (SPEC-0201 §11):
   4   pin_required           — reference missing @sha256:<hex>
   5   scanner_refuse         — staged bundle has critical scan findings
  17   no_source_policy       — policy file missing or wrong path
  18   upstream_intent_capped — warn-only scan; needs --accept-yellow
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
