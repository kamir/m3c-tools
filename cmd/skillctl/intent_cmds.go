package main

// Stream S2-M2 (Sprint 2 / Stream M2) — `skillctl intent declare` subcommand.
//
// Closes the post-hoc author-intent declaration path for SPEC-0195 awareness
// admissions. The 50 bundles admitted by `skillctl awareness sync` carry
// `intent.side_effects = ["UNKNOWN"]` (the S2.5 backfill sentinel from
// SPEC-0196 §7); `intent declare` patches a single bundle's intent block
// post-admission via `PATCH /api/skills/bundles/<digest>/intent` (the
// endpoint Stream A builds aims-core-side).
//
// CLI surface (S2.4 Q1=D, locked 2026-05-06):
//
//   skillctl intent declare <skill-name|@digest>
//     [--registry URL]
//     [--side-effects fs:write,llm:call,...]
//     [--destructive true|false]
//     [--network true|false]
//     [--human-review-required true|false]
//     [--subprocess pandoc,git]
//     [--summary "..."]
//     [--data-dep '<json>']    # repeatable; per-dep declarations
//     [--from-yaml FILE]        # alternative: read intent from a YAML file
//     [--dry-run]
//     [--confirm]
//
// Behavior:
//   - Resolve skill: `<name>` (newest admitted) OR `@sha256:...` (digest pin).
//   - Build the `intent` block from flags or --from-yaml.
//   - Refuse without `--confirm` (mirrors `awareness reset`'s explicit-intent
//     policy; S2.4 doesn't yet have an analogue but symmetry helps tests).
//   - PATCH `/api/skills/bundles/<digest>/intent` with the proposed intent.
//   - Server-side cross-rule validation (SPEC-0196 §3.3); failures surface
//     as exit 18 (`ExitIntentInconsistent`).
//
// All non-trivial logic lives here so `cmd/skillctl/intent_cmds_test.go` can
// drive `runIntentDeclareWithClient` directly without spinning a process.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

// stringSliceFlag is a small flag.Value adapter that lets a single flag be
// repeated and accumulates each occurrence. Used for --data-dep so the
// caller can declare multiple dependencies on one command line.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string         { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error     { *s = append(*s, v); return nil }
func (s *stringSliceFlag) Get() any               { return []string(*s) }

// intentDeclareReq is the wire shape of `PATCH /api/skills/bundles/<digest>/intent`.
// The endpoint expects the new (proposed) `intent` block plus an explicit
// `data_dependencies` list — Stream A's PATCH handler re-validates the
// triplet (intent, governance_intent, data_dependencies) using the same
// `_validate_intent_data_cross_rules` helper as `/admit-from-scan`.
type intentDeclareReq struct {
	Intent           map[string]any   `json:"intent"`
	DataDependencies []map[string]any `json:"data_dependencies,omitempty"`
}

// intentDeclareErr is the body shape for a 400 cross-rule violation. The
// endpoint sets `reason: intent_data_inconsistent` plus `failed_rule:
// <rule_name>` so the CLI can surface a precise diagnostic + map to exit 18.
type intentDeclareErr struct {
	Reason     string `json:"reason"`
	FailedRule string `json:"failed_rule"`
	Detail     string `json:"detail,omitempty"`
}

// intentYAMLFile is the structure of `--from-yaml FILE`. Mirrors SPEC-0196
// §3.1+§3.2 (`intent` + optional `data_dependencies`). Top-level fields can
// be specified individually or as a single block.
type intentYAMLFile struct {
	Intent           map[string]any   `yaml:"intent"`
	DataDependencies []map[string]any `yaml:"data_dependencies"`
}

// intentDeclareOpts captures everything runIntentDeclareWithClient needs.
// Built by the flag-parser; tests can construct it directly.
type intentDeclareOpts struct {
	skill          string
	registryURL    string
	dryRun         bool
	confirm        bool
	timeout        time.Duration
	httpClient     *http.Client // injected by tests
	intent         map[string]any
	dataDeps       []map[string]any
	resolveDigest  func(ctx context.Context, c *registry.Client, name string) (string, error) // injected
}

// runIntent is the dispatcher for `skillctl intent <subcommand>`. Today only
// `declare` is implemented; future subcommands (e.g. `intent show`) should
// land in this switch.
func runIntent(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		printIntentUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "declare":
		return runIntentDeclare(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printIntentUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "skillctl intent: unknown subcommand %q\n", args[0])
		printIntentUsage(stderr)
		return exitUsage
	}
}

// runIntentDeclare is the flag-parser + opt-builder. Network calls happen
// in runIntentDeclareWithClient so tests can inject an httptest.Server.
func runIntentDeclare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("intent declare", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry base URL. Required if not pinned in trust-roots.")
	sideEffectsFlag := fs.String("side-effects", "", "Comma-separated side-effect tokens (e.g. fs:write,llm:call). Empty = unset.")
	destructiveFlag := fs.String("destructive", "", "Author claim: skill performs irreversible changes. true|false.")
	networkFlag := fs.String("network", "", "Author claim: skill makes outbound network calls. true|false.")
	hrFlag := fs.String("human-review-required", "", "Author claim: skill requires human review beyond governance attestation. true|false.")
	subprocessFlag := fs.String("subprocess", "", "Comma-separated subprocess allowlist (e.g. pandoc,git).")
	summaryFlag := fs.String("summary", "", "One-line plain-English summary of the skill's intent.")
	var dataDepFlag stringSliceFlag
	fs.Var(&dataDepFlag, "data-dep", "Per-dependency JSON declaration; repeatable.")
	fromYAML := fs.String("from-yaml", "", "Read the entire intent + data_dependencies block from a YAML file (alternative to per-flag declaration).")
	dryRun := fs.Bool("dry-run", false, "Print the proposed PATCH payload and exit 0; no HTTP call.")
	confirm := fs.Bool("confirm", false, "Required to actually issue the PATCH (footgun-resistance).")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout for the PATCH call.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl intent declare <skill-name|@digest> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Patches the `intent` block of a previously-admitted bundle, replacing")
		fmt.Fprintln(stderr, "the awareness sentinel (`side_effects=[\"UNKNOWN\"]`) with a real")
		fmt.Fprintln(stderr, "declaration. SPEC-0195 §7 + SPEC-0196 §3 path.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Resolution:")
		fmt.Fprintln(stderr, "  <skill-name>     Latest admitted bundle of that name.")
		fmt.Fprintln(stderr, "  @sha256:<hex>    Direct digest pin (preferred for scripting).")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes:")
		fmt.Fprintln(stderr, "   0  ok")
		fmt.Fprintln(stderr, "   1  generic / network error")
		fmt.Fprintln(stderr, "   2  usage / flag error")
		fmt.Fprintln(stderr, "  18  intent inconsistent with data_dependencies (SPEC-0196 §3.3)")
		fs.PrintDefaults()
	}

	// Go's stdlib flag package stops at the first non-flag argument. The
	// user-facing CLI puts the skill positional first ("intent declare
	// <skill> --flag ..."), which would otherwise cause every flag after
	// the positional to be ignored. Pull the positional out first so
	// callers can use either ordering. Matches the attest_cmds.go pattern.
	skillArg, flagArgs := extractSkillPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}
	skill := skillArg
	if skill == "" && fs.NArg() == 1 {
		skill = strings.TrimSpace(fs.Arg(0))
	}
	if skill == "" {
		fs.Usage()
		return exitUsage
	}

	// Build the intent block from flags or --from-yaml. The two are
	// mutually exclusive only by convention — if both are passed, the
	// per-flag values win on a key-by-key basis (so a YAML file can
	// provide a base + a flag patches one field).
	intentBlock, dataDeps, err := buildIntentFromInputs(
		*fromYAML,
		*sideEffectsFlag,
		*destructiveFlag,
		*networkFlag,
		*hrFlag,
		*subprocessFlag,
		*summaryFlag,
		dataDepFlag,
	)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: %v\n", err)
		return exitUsage
	}
	if len(intentBlock) == 0 {
		fmt.Fprintln(stderr, "skillctl intent declare: no intent fields supplied; pass at least one of --side-effects/--destructive/--network/--human-review-required/--subprocess/--summary or --from-yaml.")
		return exitUsage
	}

	if !*dryRun && !*confirm {
		fmt.Fprintln(stderr, "skillctl intent declare: refusing to PATCH without --confirm (use --dry-run to preview).")
		return exitUsage
	}

	if *registryURL != "" {
		if err := validateRegistryURL(*registryURL); err != nil {
			fmt.Fprintf(stderr, "skillctl intent declare: %v\n", err)
			return exitUsage
		}
	}

	opts := intentDeclareOpts{
		skill:       skill,
		registryURL: *registryURL,
		dryRun:      *dryRun,
		confirm:     *confirm,
		timeout:     *timeout,
		intent:      intentBlock,
		dataDeps:    dataDeps,
	}
	return runIntentDeclareWithClient(opts, stdout, stderr)
}

// runIntentDeclareWithClient is the test-driven entry point. The opts
// struct carries everything (flag values + injected http.Client + injected
// digest resolver) so tests can stub the network entirely.
func runIntentDeclareWithClient(opts intentDeclareOpts, stdout, stderr io.Writer) int {
	// --dry-run prints the payload + exits 0 BEFORE any network access,
	// even before digest resolution. This keeps `--dry-run` strictly
	// non-side-effecting (no scan, no HTTP) — useful for fixture tests
	// and for preview-in-CI workflows.
	payload := intentDeclareReq{
		Intent:           opts.intent,
		DataDependencies: opts.dataDeps,
	}
	if opts.dryRun {
		out, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "skillctl intent declare: marshal payload: %v\n", err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "skill: %s\n", opts.skill)
		fmt.Fprintln(stdout, "payload:")
		fmt.Fprintln(stdout, string(out))
		return exitOK
	}

	// Real PATCH path. Need a resolved registry URL.
	if opts.registryURL == "" {
		fmt.Fprintln(stderr, "skillctl intent declare: --registry is required (or pin one in trust-roots).")
		return exitUsage
	}

	httpClient := opts.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: opts.timeout}
	}
	c := registry.New(opts.registryURL, httpClient)

	// Resolve digest. `@sha256:...` short-circuits; otherwise call the
	// resolver (default = ResolveByName, picks newest admitted).
	digest, err := resolveSkillDigest(context.Background(), c, opts.skill, opts.resolveDigest)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: %v\n", err)
		return exitGeneric
	}

	// Issue PATCH.
	bodyJSON, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: marshal payload: %v\n", err)
		return exitGeneric
	}
	endpoint := strings.TrimRight(opts.registryURL, "/") + "/bundles/" + url.PathEscape(digest) + "/intent"
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: build request: %v\n", err)
		return exitGeneric
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "skillctl/spec-0195-s2-m2")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: PATCH %s: %v\n", endpoint, err)
		return exitGeneric
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: read response: %v\n", err)
		return exitGeneric
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		fmt.Fprintf(stdout, "intent declared for %s\n", digest)
		fmt.Fprintf(stdout, "registry: %s\n", opts.registryURL)
		return exitOK
	case http.StatusBadRequest:
		// The 400 path is the SPEC-0196 §3.3 cross-rule rejection. Map
		// to ExitIntentInconsistent so CI can branch deterministically.
		var e intentDeclareErr
		if jerr := json.Unmarshal(respBody, &e); jerr == nil && e.Reason == "intent_data_inconsistent" {
			rule := e.FailedRule
			if rule == "" {
				rule = "<unspecified>"
			}
			fmt.Fprintf(stderr, "skillctl intent declare: rejected by registry — failed_rule=%s\n", rule)
			if e.Detail != "" {
				fmt.Fprintf(stderr, "detail: %s\n", e.Detail)
			}
			return verify.ExitCode(fmt.Errorf("rule=%s: %w", rule, verify.ErrIntentInconsistent))
		}
		// Generic 400 — request shape was bad; surface as usage.
		fmt.Fprintf(stderr, "skillctl intent declare: registry returned 400\n")
		if len(respBody) > 0 {
			fmt.Fprintf(stderr, "response body: %s\n", string(respBody))
		}
		return exitUsage
	default:
		fmt.Fprintf(stderr, "skillctl intent declare: registry returned %s\n", resp.Status)
		if len(respBody) > 0 {
			fmt.Fprintf(stderr, "response body: %s\n", string(respBody))
		}
		return exitGeneric
	}
}

// buildIntentFromInputs assembles the (intent, data_dependencies) tuple
// from the per-flag values + the optional --from-yaml file.
//
// Precedence: the YAML file is the base layer; per-flag values override
// individual keys. This lets an operator hand-edit the YAML for the
// repetitive bits (data_dependencies) and use flags for the toggles.
//
// Returns ("", nil) if no input was supplied — the caller treats that as
// a usage error.
func buildIntentFromInputs(
	fromYAML, sideEffects, destructive, network, hr, subprocess, summary string,
	dataDepStrings []string,
) (map[string]any, []map[string]any, error) {
	intentBlock := map[string]any{}
	var dataDeps []map[string]any

	if fromYAML != "" {
		raw, err := os.ReadFile(fromYAML)
		if err != nil {
			return nil, nil, fmt.Errorf("--from-yaml %q: %w", fromYAML, err)
		}
		var doc intentYAMLFile
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, nil, fmt.Errorf("--from-yaml %q: parse: %w", fromYAML, err)
		}
		if doc.Intent != nil {
			intentBlock = doc.Intent
		}
		if doc.DataDependencies != nil {
			dataDeps = doc.DataDependencies
		}
	}

	if sideEffects != "" {
		intentBlock["side_effects"] = splitCommaTrim(sideEffects)
	}
	if destructive != "" {
		b, err := parseBoolFlag(destructive, "--destructive")
		if err != nil {
			return nil, nil, err
		}
		intentBlock["destructive"] = b
	}
	if network != "" {
		b, err := parseBoolFlag(network, "--network")
		if err != nil {
			return nil, nil, err
		}
		intentBlock["network"] = b
	}
	if hr != "" {
		b, err := parseBoolFlag(hr, "--human-review-required")
		if err != nil {
			return nil, nil, err
		}
		intentBlock["human_review_required"] = b
	}
	if subprocess != "" {
		intentBlock["subprocess"] = splitCommaTrim(subprocess)
	}
	if summary != "" {
		intentBlock["summary"] = summary
	}

	for i, raw := range dataDepStrings {
		var dep map[string]any
		if err := json.Unmarshal([]byte(raw), &dep); err != nil {
			return nil, nil, fmt.Errorf("--data-dep[%d]: %w", i, err)
		}
		dataDeps = append(dataDeps, dep)
	}

	return intentBlock, dataDeps, nil
}

// resolveSkillDigest turns a `<name>` or `@sha256:<hex>` into a digest the
// PATCH URL can use.
//
// If `resolver` is non-nil, it is called for the by-name path (used by
// tests to stub out the registry). Otherwise we call ResolveByName and
// pick the newest admitted version.
func resolveSkillDigest(
	ctx context.Context,
	c *registry.Client,
	skill string,
	resolver func(ctx context.Context, c *registry.Client, name string) (string, error),
) (string, error) {
	if strings.HasPrefix(skill, "@") {
		digest := strings.TrimPrefix(skill, "@")
		if !strings.HasPrefix(digest, "sha256:") {
			return "", fmt.Errorf("digest pin %q must be sha256:<hex>", skill)
		}
		return digest, nil
	}
	if resolver != nil {
		return resolver(ctx, c, skill)
	}
	versions, err := c.ResolveByName(ctx, skill)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", skill, err)
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("resolve %q: no admitted bundles", skill)
	}
	// Prefer admitted; fall back to whatever the server returned first.
	for _, v := range versions {
		if v.Status == "" || v.Status == "admitted" {
			if v.Digest != "" {
				return v.Digest, nil
			}
		}
	}
	return "", fmt.Errorf("resolve %q: no usable digest", skill)
}

// parseBoolFlag accepts the case-insensitive set {true, false, 1, 0}. We
// don't reuse strconv.ParseBool because it accepts "T", "F", and other
// shapes that are easy to typo into the wrong meaning.
func parseBoolFlag(v, flagName string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s: expected true|false (got %q)", flagName, v)
	}
}

// splitCommaTrim splits "a, b ,c" into ["a","b","c"] discarding empty
// tokens (so a trailing comma doesn't produce a blank entry).
func splitCommaTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// extractSkillPositional pulls the first non-flag argument out of args
// and returns it alongside the remainder. A "non-flag argument" is any
// token that does NOT start with "-". This means flags-with-values that
// use space-separated form ("--registry URL") survive: the value still
// starts with non-"-" but it follows a token that DOES start with "-",
// so we know to skip the value.
//
// We treat ONLY the first non-flag positional as the skill — everything
// else (a stray second positional) bubbles through to fs.NArg() so the
// usage check can refuse cleanly.
//
// Returns ("", args) if no positional was found; the caller falls back
// to fs.Arg(0) lookup after parsing.
func extractSkillPositional(args []string) (skill string, rest []string) {
	rest = make([]string, 0, len(args))
	picked := false
	skipNextValue := false
	for _, a := range args {
		if skipNextValue {
			rest = append(rest, a)
			skipNextValue = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			// If the flag is "--name" without "=" then the next token
			// is its value (for non-bool flags). We can't easily tell
			// bool from non-bool here, so be conservative: only skip
			// when the flag is a known non-bool name. Safer: just
			// always pass through. The flag parser will then handle
			// "--registry URL" correctly because the URL doesn't start
			// with "-" but it ALSO won't be the first positional —
			// because we only pick the FIRST non-flag-prefixed token,
			// and that's "URL" only if there's no skill positional
			// before it.
			//
			// To distinguish "URL" (a flag value) from "skill-name" (a
			// positional), we mark "skip next value" on common
			// space-separated flags. The list below covers all
			// non-bool flags this command accepts.
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				// "--flag=value" — value is in-line, no skip.
				continue
			}
			switch name {
			case "registry", "side-effects", "destructive", "network",
				"human-review-required", "subprocess", "summary",
				"data-dep", "from-yaml", "timeout":
				skipNextValue = true
			}
			continue
		}
		// Non-flag-prefixed token. The first one is the skill.
		if !picked {
			skill = a
			picked = true
			continue
		}
		rest = append(rest, a)
	}
	return skill, rest
}

// printIntentUsage is the help text for `skillctl intent`. Kept short —
// the per-subcommand `--help` carries the detailed flag table.
func printIntentUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl intent <subcommand> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  declare    Patch a previously-admitted bundle's intent block.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run any subcommand with --help for its flags.")
}

// _ keeps go vet happy if the errors package import becomes unused after
// future refactoring; remove if redundant.
var _ = errors.Is
