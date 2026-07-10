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
	bundleFlag := fs.String("bundle", "", "Path to the local .skb. When given, the bundle's AUTHOR SIGNATURE is verified against the pinned trust-roots (full verify.Verify chain). Its bundle.json scope is shown as signed-manifest / AUTHORITATIVE ONLY when that verification succeeds; otherwise it is digest-matched / UNVERIFIED. WITHOUT --bundle, only the UNVERIFIED registry view is shown.")
	metaFlag := fs.String("meta", "", "Path to a BundleMeta envelope JSON for --bundle (carries the author/registry signatures). Default: fetch the meta from --registry. Use a sidecar to verify fully offline.")
	trustRootsPath := fs.String("trust-roots", "", "Path to a trust-roots YAML to use instead of the default (~/.claude/skill-trust-roots.yaml). The pinned author key is what gates the AUTHORITATIVE label for --bundle.")
	governanceMin := fs.String("governance-min", "", "Override the trust-root's governance_minimum (green | yellow) for the --bundle author-sig verification.")
	allowYellow := fs.Bool("allow-yellow", false, "Permit a yellow bundle against a green-required trust root during --bundle verification.")
	tenantFlag := fs.String("tenant", "", "Pin the --bundle verification to a tenant scope (SPEC-0188 §7 step 5.5).")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl intent show <skill-name|@digest> --registry URL [--bundle file.skb [--trust-roots f] [--meta f]] [--json]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Prints the declared SPEC-0196 intent + data_dependencies for a bundle.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Provenance (SECURITY): a scope is shown as signed-manifest / AUTHORITATIVE")
		fmt.Fprintln(stderr, "ONLY when the local .skb's AUTHOR SIGNATURE is cryptographically verified")
		fmt.Fprintln(stderr, "against a PINNED trust-root author key (the full `skillctl verify` chain).")
		fmt.Fprintln(stderr, "A bare digest match against the registry-advertised digest is NOT enough —")
		fmt.Fprintln(stderr, "that field is unsigned and registry-supplied, so a malicious registry could")
		fmt.Fprintln(stderr, "serve its own .skb + digest. Without a verifiable author signature the scope")
		fmt.Fprintln(stderr, "is digest-matched / UNVERIFIED. The registry's own scope view is always")
		fmt.Fprintln(stderr, "registry-reported / UNVERIFIED.")
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

	// The registry response is UNTRUSTED — its parsed manifest and bundle row are
	// labeled registry-reported / bundle-row, NEVER author-signed.
	view := extractDeclaredView(meta)

	// AUTHORITATIVE path (P2b re-challenge fix): a scope is signed-manifest /
	// AUTHORITATIVE ONLY when the bundle's AUTHOR SIGNATURE verifies against a
	// PINNED trust-root author key — i.e. the full verify.Verify chain (digest
	// recompute + stepVerifyAuthor ed25519 + registry sig + governance + tenant)
	// succeeds. A bare digest match against the registry-advertised, UNSIGNED
	// `bundle.bundle_digest` is NOT author-signature verification: a malicious
	// registry can serve ITS OWN .skb, advertise ITS digest, and the bytes match
	// without any pinned author having signed them (Attack-d). On any verify
	// failure (no trust-roots, from-registry root with no pinned author, author sig
	// invalid, digest mismatch, governance/revocation failure) we DOWNGRADE to
	// digest-matched / UNVERIFIED — we never print AUTHORITATIVE and never fail the
	// whole command, so the CISO still sees the (untrusted) scope with the right
	// label. The signed bundle.json bytes are always read from the digest-verified
	// .skb path (verify.ReadDigestVerifiedManifest), never from the registry copy.
	if *bundleFlag != "" {
		verifyBundleAuthorScope(bundleScopeParams{
			bundlePath:     *bundleFlag,
			metaPath:       *metaFlag,
			trustRootsPath: *trustRootsPath,
			registryURL:    *registryURL,
			governanceMin:  *governanceMin,
			allowYellow:    *allowYellow,
			tenantFlag:     *tenantFlag,
		}, meta, digest, c, ctx, &view, stderr)
	}

	authIntent, authDeps, authProv := view.authoritativeIntent()

	if *asJSON {
		// Emit the strongest-available declaration flat (back-compat) PLUS a
		// provenance-tagged breakdown of ALL sources so a CISO tool can tell
		// signed-manifest (authoritative) from digest-matched/registry-reported
		// (UNVERIFIED) and bundle-row (advisory) without scraping text.
		// `authoritative` is true ONLY when the author signature was cryptographically
		// verified against a pinned trust-root key (provSignedManifest).
		digestTrust := "UNVERIFIED (digest matched the advertised digest, but author signature NOT verified — configure trust-roots or run `skillctl verify --bundle`)"
		if view.digestDetail != "" {
			digestTrust = "UNVERIFIED (author signature NOT verified: " + view.digestDetail + ")"
		}
		out := map[string]any{
			"digest":                 digest,
			"governance":             meta.CurrentGovernance,
			"intent":                 authIntent,
			"data_dependencies":      authDeps,
			"declaration_provenance": authProv,
			"authoritative":          authProv == provSignedManifest,
			"sources": map[string]any{
				provSignedManifest: map[string]any{
					"intent":            view.signedIntent,
					"data_dependencies": view.signedDeps,
					"trust":             "AUTHORITATIVE (author signature verified against a pinned trust-root key)",
				},
				provDigestMatched: map[string]any{
					"intent":            view.digestIntent,
					"data_dependencies": view.digestDeps,
					"trust":             digestTrust,
				},
				provRegistryReported: map[string]any{
					"intent":            view.regIntent,
					"data_dependencies": view.regDeps,
					"trust":             "UNVERIFIED (registry-reported; run `intent show --bundle` with pinned trust-roots for authoritative)",
				},
				provBundleRow: map[string]any{
					"intent":            view.rowIntent,
					"data_dependencies": view.rowDeps,
					"trust":             "ADVISORY (mutable post-admit PATCH; NOT author-signed)",
				},
			},
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return exitOK
	}

	fmt.Fprintf(stdout, "digest:     %s\n", digest)
	fmt.Fprintf(stdout, "governance: %s\n", dashOrValue(meta.CurrentGovernance))
	switch authProv {
	case provSignedManifest:
		fmt.Fprintln(stdout, "provenance: signed-manifest (AUTHORITATIVE — author signature verified against a pinned trust-root key)")
	case provDigestMatched:
		fmt.Fprintln(stdout, "provenance: digest-matched (author signature NOT verified — configure trust-roots or run `skillctl verify --bundle`)")
		if view.digestDetail != "" {
			fmt.Fprintf(stdout, "            reason: %s\n", view.digestDetail)
		}
	case provRegistryReported:
		fmt.Fprintln(stdout, "provenance: registry-reported (UNVERIFIED — run `intent show --bundle <file.skb>` with pinned trust-roots for authoritative)")
	case provBundleRow:
		fmt.Fprintln(stdout, "provenance: bundle-row (ADVISORY — mutable post-admit PATCH, NOT author-signed)")
	default:
		fmt.Fprintln(stdout, "provenance: (none declared)")
	}
	if !view.hasSigned() && (view.hasDigestMatched() || view.hasRegistry() || view.hasRow()) {
		fmt.Fprintln(stdout, "warning:    NO author-signature-verified scope shown — the displayed scope is UNTRUSTED.")
		fmt.Fprintln(stdout, "            Pass --bundle <file.skb> with pinned trust-roots to verify the author signature cryptographically.")
	}

	printIntentSource(stdout, provSignedManifest, "AUTHORITATIVE", view.signedIntent, view.signedDeps)
	printIntentSource(stdout, provDigestMatched, "UNVERIFIED", view.digestIntent, view.digestDeps)
	printIntentSource(stdout, provRegistryReported, "UNVERIFIED", view.regIntent, view.regDeps)
	printIntentSource(stdout, provBundleRow, "ADVISORY", view.rowIntent, view.rowDeps)
	if !view.hasSigned() && !view.hasDigestMatched() && !view.hasRegistry() && !view.hasRow() {
		fmt.Fprintln(stdout, "intent:     (none declared)")
		fmt.Fprintln(stdout, "data_dependencies: (none declared)")
	}
	fmt.Fprintln(stdout, "(authoritative signed-binding verification: `skillctl verify --bundle <file.skb>`)")
	return exitOK
}

// bundleScopeParams carries the resolved flags the --bundle author-sig
// verification needs. Grouped so verifyBundleAuthorScope stays a single call.
type bundleScopeParams struct {
	bundlePath     string
	metaPath       string // optional sidecar override; "" → use the registry-fetched meta
	trustRootsPath string
	registryURL    string
	governanceMin  string
	allowYellow    bool
	tenantFlag     string
}

// verifyBundleAuthorScope runs the FULL author-signature verification for the
// `intent show --bundle` path and overlays the resulting scope onto view with the
// correct trust label (P2b re-challenge fix).
//
// It gates AUTHORITATIVE on verify.Verify success — the SAME §7 chain
// (stepRecomputeDigest + stepCompareDigest + stepVerifyAuthor ed25519 against the
// PINNED trust-root author key + registry sig + governance + tenant) the rest of
// the CLI runs. The registry-supplied `bundle.bundle_digest` alone is never
// sufficient: it is plain, unsigned and could be lied about by a malicious
// registry (Attack-d).
//
// Outcomes:
//   - verify.Verify SUCCEEDS → read bundle.json from the digest-verified .skb and
//     overlay it as provSignedManifest / AUTHORITATIVE (overlaySignedScope).
//   - meta lacks an advertised digest, trust-roots not configured/match, root is
//     from-registry with no pinned author, author sig invalid, digest mismatch, or
//     any other verify failure → if the .skb STILL digest-matches the advertised
//     value, overlay it as provDigestMatched / UNVERIFIED with an actionable
//     reason; otherwise surface nothing signed (the registry-reported view stands).
//
// It NEVER aborts the command and NEVER prints AUTHORITATIVE without a verified
// author signature.
func verifyBundleAuthorScope(p bundleScopeParams, meta *registry.BundleMeta, digest string, c *registry.Client, ctx context.Context, view *declaredView, stderr io.Writer) {
	advertised := advertisedDigest(meta, digest)

	// Read the bundle.json from the DIGEST-VERIFIED .skb up front. This both (a)
	// confirms the on-disk bytes reproduce the advertised digest and (b) gives us
	// the scope to surface regardless of the author-sig outcome. If the digest does
	// NOT match, the bundle is not the one the registry described — surface nothing
	// signed and let the registry-reported view stand (it is already UNVERIFIED).
	signedManifest, derr := verify.ReadDigestVerifiedManifest(p.bundlePath, advertised)
	if derr != nil {
		fmt.Fprintf(stderr, "skillctl intent show: --bundle %s did not digest-match the advertised digest %s: %v\n", p.bundlePath, advertised, derr)
		fmt.Fprintln(stderr, "            (showing the registry view as UNVERIFIED; no signed scope)")
		return
	}
	bundleIntent, bundleDeps := pickDeclared(signedManifest)

	// Now attempt FULL author-signature verification. Any failure → UNVERIFIED.
	if reason, ok := verifyBundleAuthor(p, meta, c, ctx); ok {
		// Author signature verified against a pinned trust-root key → AUTHORITATIVE.
		view.overlaySignedScope(bundleIntent, bundleDeps)
		return
	} else {
		// Digest matched but author sig NOT verified → digest-matched / UNVERIFIED.
		fmt.Fprintf(stderr, "skillctl intent show: --bundle digest matched but author signature NOT verified: %s\n", reason)
		view.overlayDigestMatchedScope(bundleIntent, bundleDeps, reason)
	}
}

// verifyBundleAuthor loads the pinned trust-roots + BundleMeta envelope and runs
// the full verify.Verify chain. It returns (reason, true) ONLY when verification
// succeeds (author signature is valid against a pinned trust-root key); otherwise
// (reason, false) with an actionable, CISO-facing explanation of why the bundle is
// not author-signature-verified. It never aborts.
func verifyBundleAuthor(p bundleScopeParams, regMeta *registry.BundleMeta, c *registry.Client, ctx context.Context) (string, bool) {
	// 1. The BundleMeta envelope carrying the author/registry signatures. Default
	//    to the registry-fetched meta; a --meta sidecar lets a CISO verify fully
	//    offline against signatures they obtained out-of-band.
	meta := regMeta
	if p.metaPath != "" {
		m, err := loadBundleMetaSidecar(p.metaPath)
		if err != nil {
			return fmt.Sprintf("could not read --meta envelope: %v", err), false
		}
		meta = m
	}
	if meta == nil {
		return "no BundleMeta envelope (signatures) available", false
	}

	// 2. The PINNED trust-roots — this is where the author key comes from. With no
	//    pinned author key there is nothing to verify the author signature against,
	//    so the bundle is UNVERIFIED (configure trust-roots).
	tr, root, err := loadAndPickRootFromPath(p.trustRootsPath, p.registryURL)
	if err != nil {
		return fmt.Sprintf("trust-roots not usable (%v); configure with `skillctl trust add`", err), false
	}

	// 3. Identity fetcher: a from-registry root resolves the author key via the
	//    registry client; a pinned root needs none (fully offline). We deliberately
	//    do NOT pass a fetcher for pinned roots so the author key MUST come from the
	//    local pin, not the (untrusted) registry.
	var fetcher interface {
		GetIdentity(ctx context.Context, id string) (*registry.Identity, error)
	}
	if root.IdentityKeysAuthorized != "pinned" {
		fetcher = c
	}

	res, verr := verify.Verify(verify.VerifyOpts{
		BundlePath:      p.bundlePath,
		BundleMeta:      meta,
		TrustRoot:       root,
		IdentityFetcher: fetcher,
		GovernanceMin:   p.governanceMin,
		AllowYellow:     p.allowYellow,
		Tenant:          resolveTenant(p.tenantFlag, tr),
		Ctx:             ctx,
	})
	if verr != nil {
		return fmt.Sprintf("author-signature chain failed: %v", verr), false
	}
	return "author signature verified, author=" + res.AuthorIdentity, true
}

// advertisedDigest returns the digest to compare a local .skb against in the
// --bundle path: the registry-advertised `bundle.bundle_digest` (the value the
// author signature covers). Falls back to the digest the caller resolved (e.g. an
// @sha256 pin) when the registry row omits it. Either way the comparison is
// against a value the bundle.json bytes must reproduce — a malicious registry that
// lies about the digest can only cause a fail-closed mismatch, never an
// authoritative display of an unsigned scope.
func advertisedDigest(meta *registry.BundleMeta, resolved string) string {
	if meta != nil && meta.Bundle != nil {
		if d, ok := meta.Bundle["bundle_digest"].(string); ok && strings.TrimSpace(d) != "" {
			return d
		}
	}
	return resolved
}

// printIntentSource renders one provenance source's intent + data_dependencies,
// each line tagged with the provenance label so a CISO sees which declaration is
// author-signed vs post-admit. Prints nothing when the source is empty.
func printIntentSource(stdout io.Writer, provenance, marker string, intentBlock map[string]any, deps []map[string]any) {
	if intentBlock == nil && len(deps) == 0 {
		return
	}
	fmt.Fprintf(stdout, "[%s] %s:\n", provenance, marker)
	if intentBlock != nil {
		if b, err := json.MarshalIndent(intentBlock, "    ", "  "); err == nil {
			fmt.Fprintf(stdout, "  intent: %s\n", string(b))
		}
	}
	if len(deps) > 0 {
		fmt.Fprintf(stdout, "  data_dependencies (%d):\n", len(deps))
		for _, d := range deps {
			if b, err := json.Marshal(d); err == nil {
				fmt.Fprintf(stdout, "    - %s\n", string(b))
			}
		}
	}
}

// scopeProvenance labels WHERE a declared scope came from, so a CISO can tell at
// a glance whether today's declaration is author-signed or merely reported by an
// untrusted registry (SPEC-0196 §12 Q1 / P2b).
//
// SECURITY INVARIANT (P2b re-challenge fix): a scope may be labeled
// provSignedManifest / AUTHORITATIVE *only* when the bundle's AUTHOR SIGNATURE was
// cryptographically verified against a PINNED trust-root author key — i.e. the
// full `verify.Verify` chain (digest recompute + stepVerifyAuthor ed25519 +
// registry sig + governance + revocation) succeeded. A bare digest match against
// the registry-advertised `bundle.bundle_digest` is NOT author-signature
// verification: that field is plain, unsigned, registry-supplied, so a malicious
// registry can serve ITS OWN .skb, advertise ITS digest, and the bytes "match"
// without any pinned author having signed them (red-team Attack-d).
//
// When the .skb digest-matches the advertised digest but the author signature
// could NOT be verified (no trust-roots, from-registry root with no pinned
// author, author sig invalid, governance/revocation failure, or any verify
// error), the scope is labeled provDigestMatched / UNVERIFIED — NEVER
// AUTHORITATIVE. The registry's parsed `manifest` copy (meta.Manifest) is
// provRegistryReported / UNVERIFIED and the mutable post-admit PATCH row
// (meta.Bundle) is provBundleRow / advisory. Mirrors verify.ScopeProvenance for
// the signed case.
const (
	provSignedManifest   = "signed-manifest"   // author-signature VERIFIED against a pinned trust-root key (AUTHORITATIVE)
	provDigestMatched    = "digest-matched"    // local .skb digest matched advertised digest, but author sig NOT verified (UNVERIFIED)
	provRegistryReported = "registry-reported" // from the registry's untrusted parsed manifest copy (UNVERIFIED)
	provBundleRow        = "bundle-row"        // from the mutable post-admit PATCH row (advisory)
)

// declaredView is the provenance-tagged result of reading a bundle's declared
// intent + data_dependencies from up to four sources, in DECREASING trust:
//
//   - signed:   read from a local .skb whose AUTHOR SIGNATURE was cryptographically
//     verified against a pinned trust-root key (full verify.Verify chain succeeded).
//     AUTHORITATIVE — author-signature-covered. Populated ONLY when
//     `intent show --bundle <file.skb>` ran the real verify chain to success.
//     NEVER populated from a bare digest match or the registry response.
//   - digestMatched: read from a local .skb whose digest matched the advertised
//     digest, but whose author signature could NOT be verified (no trust-roots,
//     from-registry root with no pinned author, author sig invalid, or any verify
//     failure). UNVERIFIED — a digest match against a registry-supplied, unsigned
//     `bundle_digest` is NOT author-signature verification (Attack-d).
//   - registry: read from the registry's parsed `manifest` copy (meta.Manifest).
//     UNVERIFIED — plain HTTP, no digest recompute, no signature check. A
//     malicious registry can put anything here, so it is NOT authoritative.
//   - row:      read from the mutable post-admit PATCH row (meta.Bundle). Advisory.
//
// ALL present sources are surfaced — a CISO must see what is author-signed vs what
// the registry merely claims, not just the winning one.
type declaredView struct {
	signedIntent map[string]any
	signedDeps   []map[string]any
	digestIntent map[string]any
	digestDeps   []map[string]any
	digestDetail string // why the author sig could not be verified (for the UNVERIFIED label)
	regIntent    map[string]any
	regDeps      []map[string]any
	rowIntent    map[string]any
	rowDeps      []map[string]any
}

// hasSigned reports whether an AUTHOR-SIGNATURE-VERIFIED declaration is present.
func (v declaredView) hasSigned() bool {
	return v.signedIntent != nil || len(v.signedDeps) > 0
}

// hasDigestMatched reports whether a digest-matched-but-UNVERIFIED declaration is
// present (the .skb bytes reproduced the advertised digest, but no pinned author
// signature was verified over them).
func (v declaredView) hasDigestMatched() bool {
	return v.digestIntent != nil || len(v.digestDeps) > 0
}

// hasRegistry reports whether the untrusted registry-manifest copy carried a
// declaration. Present ≠ authoritative — see provRegistryReported.
func (v declaredView) hasRegistry() bool {
	return v.regIntent != nil || len(v.regDeps) > 0
}

// hasRow reports whether any mutable bundle-row declaration is present.
func (v declaredView) hasRow() bool {
	return v.rowIntent != nil || len(v.rowDeps) > 0
}

// authoritativeIntent returns the declaration a consumer should treat as the
// strongest available, plus its provenance. The ONLY authoritative source is the
// AUTHOR-SIGNATURE-VERIFIED local bundle (provSignedManifest). A digest-matched
// bundle whose author signature was NOT verified (provDigestMatched), the
// registry-manifest copy (provRegistryReported) and the bundle row (provBundleRow)
// are all UNVERIFIED / advisory and are NEVER labeled author-signed.
func (v declaredView) authoritativeIntent() (map[string]any, []map[string]any, string) {
	if v.hasSigned() {
		return v.signedIntent, v.signedDeps, provSignedManifest
	}
	if v.hasDigestMatched() {
		return v.digestIntent, v.digestDeps, provDigestMatched
	}
	if v.hasRegistry() {
		return v.regIntent, v.regDeps, provRegistryReported
	}
	if v.hasRow() {
		return v.rowIntent, v.rowDeps, provBundleRow
	}
	return nil, nil, ""
}

// pickDeclared pulls (intent, data_dependencies) out of a raw map (a registry
// envelope source, or a digest-verified bundle.json). Tolerates absence and
// non-object entries.
func pickDeclared(src map[string]any) (map[string]any, []map[string]any) {
	if src == nil {
		return nil, nil
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
	return in, deps
}

// extractDeclaredView pulls the declared intent + data_dependencies out of the
// UNTRUSTED registry response. CRITICAL P2b invariant: this reads only the
// registry's representation, so NOTHING it returns is authoritative. The registry
// `manifest` copy (meta.Manifest) is tagged registry-reported / UNVERIFIED and the
// post-admit PATCH row (meta.Bundle) is tagged bundle-row / advisory. The
// author-signed scope is populated SEPARATELY, only from a digest-verified local
// .skb via overlaySignedScope — see runIntentShow's `--bundle` path. This is the
// SAME trust boundary `verify` enforces (verify.go collectDeclaredScopes:
// "deliberately do NOT read scope from meta.Manifest").
func extractDeclaredView(meta *registry.BundleMeta) declaredView {
	var v declaredView
	v.regIntent, v.regDeps = pickDeclared(meta.Manifest)
	v.rowIntent, v.rowDeps = pickDeclared(meta.Bundle)
	return v
}

// overlaySignedScope populates the AUTHORITATIVE signed source of a declaredView
// from a local .skb whose AUTHOR SIGNATURE was cryptographically verified against a
// pinned trust-root key (the full verify.Verify chain succeeded). This is the ONLY
// path that may set provSignedManifest. The caller MUST have run verify.Verify to
// success before calling this — a bare digest match is NOT sufficient.
func (v *declaredView) overlaySignedScope(signedIntent map[string]any, signedDeps []map[string]any) {
	v.signedIntent = signedIntent
	v.signedDeps = signedDeps
}

// overlayDigestMatchedScope populates the UNVERIFIED digest-matched source from a
// local .skb whose digest matched the advertised digest but whose author signature
// could NOT be verified. detail explains why (no trust-roots, invalid sig, etc.) so
// the CISO-facing label is actionable. This NEVER yields provSignedManifest.
func (v *declaredView) overlayDigestMatchedScope(intent map[string]any, deps []map[string]any, detail string) {
	v.digestIntent = intent
	v.digestDeps = deps
	v.digestDetail = detail
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
				"data-dep", "data-scopes", "from-yaml", "timeout",
				"bundle", "governance-intent", "meta", "trust-roots",
				"governance-min", "tenant":
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
