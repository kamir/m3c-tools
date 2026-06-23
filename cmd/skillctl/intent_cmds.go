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

	"github.com/kamir/m3c-tools/pkg/skillctl/datascope"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

// stringSliceFlag is a small flag.Value adapter that lets a single flag be
// repeated and accumulates each occurrence. Used for --data-dep so the
// caller can declare multiple dependencies on one command line.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }
func (s *stringSliceFlag) Get() any           { return []string(*s) }

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
	skill         string
	registryURL   string
	dryRun        bool
	confirm       bool
	timeout       time.Duration
	httpClient    *http.Client // injected by tests
	intent        map[string]any
	dataDeps      []map[string]any
	governance    string                                                                     // governance_intent for the §3.3 destructive_green client check
	resolveDigest func(ctx context.Context, c *registry.Client, name string) (string, error) // injected
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
	case "show":
		return runIntentShow(args[1:], stdout, stderr)
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
	governanceFlag := fs.String("governance-intent", "", "Bundle governance intent (green|yellow|red) — checked against the §3.3 destructive_green cross-rule.")
	var dataScopeFlag stringSliceFlag
	fs.Var(&dataScopeFlag, "data-scopes", "Typed SPEC-0196 data-scope JSON declaration; repeatable. Validated client-side through pkg/skillctl/datascope before the PATCH.")
	var dataDepFlag stringSliceFlag
	fs.Var(&dataDepFlag, "data-dep", "DEPRECATED alias for --data-scopes (same JSON shape, same validation). Prefer --data-scopes.")
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

	// --data-scopes is the typed first-class flag; --data-dep is the
	// deprecated alias. They share the exact JSON shape and the exact
	// validator, so we concatenate them (scopes first) and warn once if the
	// alias was used.
	depStrings := append([]string(nil), dataScopeFlag...)
	if len(dataDepFlag) > 0 {
		fmt.Fprintln(stderr, "skillctl intent declare: NOTE --data-dep is deprecated; use --data-scopes (same JSON shape, same validation).")
		depStrings = append(depStrings, dataDepFlag...)
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
		depStrings,
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
		governance:  strings.TrimSpace(*governanceFlag),
	}
	return runIntentDeclareWithClient(opts, stdout, stderr)
}

// runIntentDeclareWithClient is the test-driven entry point. The opts
// struct carries everything (flag values + injected http.Client + injected
// digest resolver) so tests can stub the network entirely.
func runIntentDeclareWithClient(opts intentDeclareOpts, stdout, stderr io.Writer) int {
	// CLIENT-SIDE data-scope validation (SPEC-0196 §3 + §3.3), fail-closed.
	// This runs BEFORE the dry-run print and BEFORE any network access, so an
	// inconsistent declaration is rejected locally — without ever leaking a
	// half-baked PATCH to the registry. A §3.3 cross-rule failure maps to the
	// SAME exit 18 the server returns, so CI cannot tell client refusal from
	// server refusal (the red-team relies on this: the binding cannot be
	// bypassed by declaring offline).
	if code, ok := validateDeclarationLocally(opts, stderr); !ok {
		return code
	}

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

// runIntentShow implements `skillctl intent show <skill-name|@digest>`. It
// resolves the bundle, fetches its registry meta, and prints the declared
// intent + data_dependencies (the SPEC-0196 §3 fields). Read-only — no PATCH,
// no --confirm. Useful for the CISO to read what a skill says it does before
// authorizing a data dependency (SPEC-0196 §8).
func runIntentShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("intent show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registryURL := fs.String("registry", "", "Registry base URL (required).")
	asJSON := fs.Bool("json", false, "Emit the declared intent + data_dependencies as JSON.")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl intent show <skill-name|@digest> --registry URL [--json]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Prints the declared SPEC-0196 intent + data_dependencies for a bundle.")
		fs.PrintDefaults()
	}

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
	if *registryURL == "" {
		fmt.Fprintln(stderr, "skillctl intent show: --registry is required.")
		return exitUsage
	}
	if err := validateRegistryURL(*registryURL); err != nil {
		fmt.Fprintf(stderr, "skillctl intent show: %v\n", err)
		return exitUsage
	}

	httpClient := &http.Client{Timeout: *timeout}
	c := registry.New(*registryURL, httpClient)
	ctx := context.Background()
	digest, err := resolveSkillDigest(ctx, c, skill, nil)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent show: %v\n", err)
		return exitGeneric
	}
	meta, err := c.GetBundleMeta(ctx, digest)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent show: fetch meta for %s: %v\n", digest, err)
		return exitGeneric
	}

	intentBlock, dataDeps := extractDeclaredIntent(meta)

	if *asJSON {
		out := map[string]any{
			"digest":            digest,
			"governance":        meta.CurrentGovernance,
			"intent":            intentBlock,
			"data_dependencies": dataDeps,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return exitOK
	}

	fmt.Fprintf(stdout, "digest:     %s\n", digest)
	fmt.Fprintf(stdout, "governance: %s\n", dashOrValue(meta.CurrentGovernance))
	if intentBlock == nil {
		fmt.Fprintln(stdout, "intent:     (none declared)")
	} else {
		fmt.Fprintln(stdout, "intent:")
		if b, err := json.MarshalIndent(intentBlock, "  ", "  "); err == nil {
			fmt.Fprintf(stdout, "  %s\n", string(b))
		}
	}
	if len(dataDeps) == 0 {
		fmt.Fprintln(stdout, "data_dependencies: (none declared)")
	} else {
		fmt.Fprintf(stdout, "data_dependencies (%d):\n", len(dataDeps))
		for _, d := range dataDeps {
			if b, err := json.Marshal(d); err == nil {
				fmt.Fprintf(stdout, "  - %s\n", string(b))
			}
		}
	}
	return exitOK
}

// extractDeclaredIntent pulls the declared intent + data_dependencies out of a
// BundleMeta. The post-hoc `intent declare` PATCH writes them onto the registry
// row (BundleMeta.Bundle); a pack-time binding writes them into bundle.json
// (BundleMeta.Manifest). We prefer the row (it is the post-admission source of
// truth) and fall back to the manifest.
func extractDeclaredIntent(meta *registry.BundleMeta) (map[string]any, []map[string]any) {
	pick := func(src map[string]any) (map[string]any, []map[string]any, bool) {
		if src == nil {
			return nil, nil, false
		}
		in, _ := src["intent"].(map[string]any)
		var deps []map[string]any
		if raw, ok := src["data_dependencies"].([]any); ok {
			for _, item := range raw {
				if m, ok := item.(map[string]any); ok {
					deps = append(deps, m)
				}
			}
		}
		if in != nil || len(deps) > 0 {
			return in, deps, true
		}
		return nil, nil, false
	}
	if in, deps, ok := pick(meta.Bundle); ok {
		return in, deps
	}
	in, deps, _ := pick(meta.Manifest)
	return in, deps
}

func dashOrValue(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unknown)"
	}
	return s
}

// validateDeclarationLocally runs the typed SPEC-0196 validator over the
// proposed declaration. It returns (exitCode, ok): on ok=true the caller
// proceeds; on ok=false the caller returns exitCode.
//
//   - A §3.3 cross-rule failure → exit 18 (verify.ExitIntentInconsistent),
//     matching the server PATCH's 422→18 mapping (the failed_rule is printed).
//   - A structural failure (bad kind/scope/id, out-of-vocabulary side effect)
//     → exit 2 (usage): the declaration is malformed, not merely inconsistent.
//
// The dependency maps the CLI carries are decoded into typed datascope.DataScope
// values first; a decode error is a usage error.
func validateDeclarationLocally(opts intentDeclareOpts, stderr io.Writer) (int, bool) {
	scopes, err := datascope.FromMaps(opts.dataDeps)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl intent declare: %v\n", err)
		return exitUsage, false
	}
	in := datascope.IntentFromMap(opts.intent)
	if verr := datascope.Validate(in, scopes, opts.governance); verr != nil {
		var ve *datascope.ValidationError
		if errors.As(verr, &ve) && ve.FailedRule != "" {
			// A real §3.3 cross-rule fired → exit 18, same as the server.
			fmt.Fprintf(stderr, "skillctl intent declare: rejected locally — failed_rule=%s\n", ve.FailedRule)
			fmt.Fprintf(stderr, "detail: %s\n", ve.Detail)
			return verify.ExitCode(fmt.Errorf("rule=%s: %w", ve.FailedRule, verify.ErrIntentInconsistent)), false
		}
		// Structural / vocabulary failure → usage error.
		fmt.Fprintf(stderr, "skillctl intent declare: invalid declaration: %v\n", verr)
		return exitUsage, false
	}
	return exitOK, true
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
	fmt.Fprintln(w, "             Typed data-scope via --data-scopes (repeatable JSON, SPEC-0196).")
	fmt.Fprintln(w, "  show       Print the declared intent + data_dependencies for a bundle.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run any subcommand with --help for its flags.")
}

// _ keeps go vet happy if the errors package import becomes unused after
// future refactoring; remove if redundant.
var _ = errors.Is
