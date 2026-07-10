package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/datascope"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// cmdPack implements `skillctl pack` per SPEC-0188 §3 — produce a deterministic
// `.skb` archive from a local skill directory.
//
// SPEC-0196 §12 Q1 / P2b: `--data-scopes` binds a typed, validated data-scope
// declaration INTO the signed `bundle.json` (manifest.Intent + manifest.
// DataDependencies) BEFORE the digest is computed and the author signs — so the
// declaration is covered by the author signature, not the mutable post-admit
// PATCH row. The validation is fail-closed at pack time: an invalid or §3.3-
// contradictory scope is rejected before any bundle is produced, with the SAME
// `failed_rule` + exit 18 the client/server `intent declare` path returns.
//
// cmdPack is the os.Exit wrapper; runPack is the testable core (returns an exit
// code, prints to the injected writers) so the challenge gate can drive the
// pack-time binding without spawning a process.
func cmdPack(args []string) {
	os.Exit(runPack(args, os.Stdout, os.Stderr))
}

// packInputs holds the parsed flag set. Separated from runPack so the parser is
// unit-testable and the runner stays a straight build → validate → pack flow.
type packInputs struct {
	skillDir  string
	outFile   string
	manifest  skillbundle.BundleManifest
	dependsOn []string

	// SPEC-0196 P2b data-scope inputs.
	dataScopeJSON []string // repeated --data-scopes / --data-dep JSON blobs (datascope wire shape)
	usedDataDep   bool     // true if the deprecated --data-dep alias was used (warn once)

	// SPEC-0196 §3.1 intent toggles — only the fields the §3.3 cross-rules read
	// are first-class flags; the rest of the intent block stays advisory.
	sideEffects string // comma-separated §5 side-effect tokens
	destructive string // "" | true | false (pointer-ish: "" = unset)
	network     string // "" | true | false
}

// runPack parses, validates, and emits. Returns a SPEC-0188 §11 numeric exit
// code. A §3.3 cross-rule failure returns exit 18 (verify.ExitIntentInconsistent),
// matching `intent declare`; a malformed scope returns exit 2 (usage).
func runPack(args []string, stdout, stderr io.Writer) int {
	in, code, ok := parsePackArgs(args, stderr)
	if !ok {
		return code
	}

	if in.skillDir == "" || in.outFile == "" || in.manifest.Name == "" || in.manifest.Version == "" {
		fmt.Fprintln(stderr, "Error: --skill, --output, --name, and --version are required.")
		printPackUsage(stderr)
		return exitUsage
	}

	deps, err := parseDependencies(in.dependsOn)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitGeneric
	}
	in.manifest.DependsOn = deps

	// SPEC-0196 §12 Q1 / P2b — bind the validated data-scope into the manifest
	// BEFORE Pack computes the digest. Fail-closed: an invalid declaration aborts
	// the pack so no bundle is ever produced with an unvalidated scope.
	if code, ok := bindDataScope(&in, stderr); !ok {
		return code
	}

	digest, err := skillbundle.Pack(in.skillDir, in.outFile, skillbundle.PackOptions{
		Manifest: in.manifest,
		BuiltBy:  fmt.Sprintf("skillctl/%s", in.manifest.Version),
	})
	if err != nil {
		fmt.Fprintf(stderr, "pack failed: %v\n", err)
		return exitGeneric
	}

	fmt.Fprintf(stdout, "bundle_digest: %s\n", digest)
	fmt.Fprintf(stdout, "output:        %s\n", in.outFile)
	if len(in.manifest.DataDependencies) > 0 {
		fmt.Fprintf(stdout, "data_scopes:   %d declared (author-signed, in bundle.json)\n", len(in.manifest.DataDependencies))
	}
	return exitOK
}

// parsePackArgs walks os.Args-style flags. Returns (inputs, exitCode, ok); on
// ok=false the caller returns exitCode. Keeps the existing manual-parse style
// (no cobra) so it matches the rest of the skillctl CLI.
func parsePackArgs(args []string, stderr io.Writer) (packInputs, int, bool) {
	var in packInputs

	take := func(i int, flag string) (string, bool) {
		if i >= len(args) {
			fmt.Fprintf(stderr, "Error: %s requires a value\n", flag)
			return "", false
		}
		return args[i], true
	}

	for i := 0; i < len(args); i++ {
		var v string
		var ok bool
		switch args[i] {
		case "--skill":
			i++
			if v, ok = take(i, "--skill"); !ok {
				return in, exitUsage, false
			}
			in.skillDir = v
		case "-o", "--output":
			i++
			if v, ok = take(i, "--output"); !ok {
				return in, exitUsage, false
			}
			in.outFile = v
		case "--name":
			i++
			if v, ok = take(i, "--name"); !ok {
				return in, exitUsage, false
			}
			in.manifest.Name = v
		case "--version":
			i++
			if v, ok = take(i, "--version"); !ok {
				return in, exitUsage, false
			}
			in.manifest.Version = v
		case "--summary":
			i++
			if v, ok = take(i, "--summary"); !ok {
				return in, exitUsage, false
			}
			in.manifest.Summary = v
		case "--source-repo":
			i++
			if v, ok = take(i, "--source-repo"); !ok {
				return in, exitUsage, false
			}
			in.manifest.SourceRepo = v
		case "--source-commit":
			i++
			if v, ok = take(i, "--source-commit"); !ok {
				return in, exitUsage, false
			}
			in.manifest.SourceCommit = v
		case "--source-path":
			i++
			if v, ok = take(i, "--source-path"); !ok {
				return in, exitUsage, false
			}
			in.manifest.SourcePath = v
		case "--author-intent":
			i++
			if v, ok = take(i, "--author-intent"); !ok {
				return in, exitUsage, false
			}
			in.manifest.AuthorGovernanceIntent = v
		case "--author-intent-rationale":
			i++
			if v, ok = take(i, "--author-intent-rationale"); !ok {
				return in, exitUsage, false
			}
			in.manifest.AuthorGovernanceRationale = v
		case "--compatibility":
			i++
			if v, ok = take(i, "--compatibility"); !ok {
				return in, exitUsage, false
			}
			in.manifest.Compatibility = v
		case "--depends-on":
			i++
			if v, ok = take(i, "--depends-on"); !ok {
				return in, exitUsage, false
			}
			in.dependsOn = append(in.dependsOn, v)
		case "--data-scopes":
			i++
			if v, ok = take(i, "--data-scopes"); !ok {
				return in, exitUsage, false
			}
			in.dataScopeJSON = append(in.dataScopeJSON, v)
		case "--data-dep":
			// Deprecated alias for --data-scopes (same JSON shape, same
			// validation) — kept symmetric with `intent declare`.
			i++
			if v, ok = take(i, "--data-dep"); !ok {
				return in, exitUsage, false
			}
			in.dataScopeJSON = append(in.dataScopeJSON, v)
			in.usedDataDep = true
		case "--side-effects":
			i++
			if v, ok = take(i, "--side-effects"); !ok {
				return in, exitUsage, false
			}
			in.sideEffects = v
		case "--destructive":
			i++
			if v, ok = take(i, "--destructive"); !ok {
				return in, exitUsage, false
			}
			in.destructive = v
		case "--network":
			i++
			if v, ok = take(i, "--network"); !ok {
				return in, exitUsage, false
			}
			in.network = v
		default:
			fmt.Fprintf(stderr, "Unknown flag: %s\n", args[i])
			printPackUsage(stderr)
			return in, exitUsage, false
		}
	}
	return in, exitOK, true
}

// bindDataScope decodes the --data-scopes JSON blobs, runs them through the
// shared SPEC-0196 validator (per-scope + §5 side-effects + §3.3 cross-rules)
// FAIL-CLOSED against the bundle's --author-intent governance Ampel, and writes
// the validated typed scope into in.manifest.Intent + in.manifest.DataDependencies
// so the binding is covered by the author signature.
//
// Returns (exitCode, ok). When ok=false the caller aborts before Pack — no
// bundle is produced. Exit-code policy mirrors `intent declare`:
//   - §3.3 cross-rule fired   → exit 18 (verify.ExitIntentInconsistent), failed_rule printed
//   - malformed scope/json    → exit 2  (usage)
//
// When no --data-scopes were passed, this is a no-op (scope absent → unchanged
// behavior; bundles packed without the flag verify exactly as before).
func bindDataScope(in *packInputs, stderr io.Writer) (int, bool) {
	// Parse intent toggles into the typed cross-rule projection. These are only
	// needed to feed the §3.3 cross-rules; we ALSO mirror them into the signed
	// manifest.Intent so the declared intent is itself author-signed.
	intent, code, ok := buildPackIntent(in, stderr)
	if !ok {
		return code, false
	}

	if len(in.dataScopeJSON) == 0 {
		// No data-scopes declared. Still mirror any intent toggles that were set
		// (so `pack --destructive true` alone is signed), but skip validation
		// that requires scopes. An intent with no scopes still gets the §3.3
		// destructive↔green check via the shared validator below.
		if intent != nil {
			in.manifest.Intent = intent
		}
		if intent != nil {
			if verr := datascope.Validate(typedIntent(intent), nil, in.manifest.AuthorGovernanceIntent); verr != nil {
				return reportScopeValidationError(verr, stderr)
			}
		}
		return exitOK, true
	}

	if in.usedDataDep {
		fmt.Fprintln(stderr, "skillctl pack: NOTE --data-dep is deprecated; use --data-scopes (same JSON shape, same validation).")
	}

	// Decode each JSON blob to a raw map, then to a typed DataScope. A decode
	// error is a usage error (malformed input), distinct from a semantic
	// validation failure.
	rawMaps := make([]map[string]any, 0, len(in.dataScopeJSON))
	for i, raw := range in.dataScopeJSON {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			fmt.Fprintf(stderr, "skillctl pack: --data-scopes[%d]: invalid JSON: %v\n", i, err)
			return exitUsage, false
		}
		rawMaps = append(rawMaps, m)
	}
	scopes, err := datascope.FromMaps(rawMaps)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl pack: %v\n", err)
		return exitUsage, false
	}

	// FAIL-CLOSED validation: the full SPEC-0196 check (per-scope + §5 vocab +
	// §3.3 cross-rules) against the bundle's governance Ampel. This is the SAME
	// shared validator the client/server `intent declare` path uses, so the
	// pack-time refusal is byte-for-byte the same diagnostic.
	if verr := datascope.Validate(typedIntent(intent), scopes, in.manifest.AuthorGovernanceIntent); verr != nil {
		return reportScopeValidationError(verr, stderr)
	}

	// Bind the validated scope into the signed manifest. Marshal each typed
	// DataScope through its JSON tags into the manifest's DataDependency — the
	// tags are identical (SPEC-0196 §3.2 wire shape), so this is a lossless
	// round-trip and the bytes that land in bundle.json match the declaration.
	deps, err := scopesToManifestDeps(scopes)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl pack: bind data-scope: %v\n", err)
		return exitGeneric, false
	}
	in.manifest.DataDependencies = deps
	if intent != nil {
		in.manifest.Intent = intent
	}
	return exitOK, true
}

// buildPackIntent assembles the signed-manifest *skillbundle.Intent from the
// intent toggle flags. Returns nil when no intent flag was supplied (the
// common case — most skills declare scopes without overriding intent). A
// malformed bool flag is a usage error.
func buildPackIntent(in *packInputs, stderr io.Writer) (*skillbundle.Intent, int, bool) {
	if in.sideEffects == "" && in.destructive == "" && in.network == "" {
		return nil, exitOK, true
	}
	intent := &skillbundle.Intent{}
	if in.sideEffects != "" {
		intent.SideEffects = splitCommaTrim(in.sideEffects)
	}
	if in.destructive != "" {
		b, err := parseBoolFlag(in.destructive, "--destructive")
		if err != nil {
			fmt.Fprintf(stderr, "skillctl pack: %v\n", err)
			return nil, exitUsage, false
		}
		intent.Destructive = b
	}
	if in.network != "" {
		b, err := parseBoolFlag(in.network, "--network")
		if err != nil {
			fmt.Fprintf(stderr, "skillctl pack: %v\n", err)
			return nil, exitUsage, false
		}
		intent.Network = &b
	}
	return intent, exitOK, true
}

// typedIntent projects a signed-manifest *skillbundle.Intent onto the datascope
// validator's typed Intent (only the §3.3 cross-rule fields). A nil manifest
// intent yields the zero datascope.Intent (all-absent), which the cross-rules
// treat as "nothing declared" — the safe default.
func typedIntent(m *skillbundle.Intent) datascope.Intent {
	if m == nil {
		return datascope.Intent{}
	}
	var dest *bool
	// skillbundle.Intent.Destructive is a plain bool; project true/false through
	// a pointer so the §3.3 write_access_non_destructive rule (which only fires
	// when destructive is explicitly false) behaves identically to the CLI path.
	d := m.Destructive
	dest = &d
	return datascope.Intent{
		SideEffects: m.SideEffects,
		Destructive: dest,
		Network:     m.Network,
	}
}

// scopesToManifestDeps round-trips each typed DataScope through its JSON tags
// into a manifest DataDependency. The tags match exactly (SPEC-0196 §3.2), so
// the bytes are conserved — the verifier reads back the identical declaration.
func scopesToManifestDeps(scopes []datascope.DataScope) ([]skillbundle.DataDependency, error) {
	deps := make([]skillbundle.DataDependency, 0, len(scopes))
	for i, s := range scopes {
		b, err := json.Marshal(s)
		if err != nil {
			return nil, fmt.Errorf("data_dependencies[%d]: marshal: %w", i, err)
		}
		var d skillbundle.DataDependency
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("data_dependencies[%d]: decode: %w", i, err)
		}
		deps = append(deps, d)
	}
	return deps, nil
}

// reportScopeValidationError maps a datascope.ValidationError to the same exit
// codes the `intent declare` path uses: a fired §3.3 cross-rule → exit 18 with
// the stable failed_rule; a structural/vocabulary failure → exit 2 (usage).
func reportScopeValidationError(verr error, stderr io.Writer) (int, bool) {
	var ve *datascope.ValidationError
	if errors.As(verr, &ve) && ve.FailedRule != "" {
		fmt.Fprintf(stderr, "skillctl pack: rejected at pack time — failed_rule=%s\n", ve.FailedRule)
		fmt.Fprintf(stderr, "detail: %s\n", ve.Detail)
		return verify.ExitCode(fmt.Errorf("rule=%s: %w", ve.FailedRule, verify.ErrIntentInconsistent)), false
	}
	fmt.Fprintf(stderr, "skillctl pack: invalid data-scope declaration: %v\n", verr)
	return exitUsage, false
}

// parseDependencies parses repeated `--depends-on kind:name:constraint` flags.
// The constraint can itself contain colons (`>=2.31`), so we split on the first
// two only.
func parseDependencies(specs []string) ([]skillbundle.Dependency, error) {
	out := make([]skillbundle.Dependency, 0, len(specs))
	for _, raw := range specs {
		first := strings.Index(raw, ":")
		if first < 0 {
			return nil, fmt.Errorf("invalid --depends-on %q: want kind:name:constraint", raw)
		}
		rest := raw[first+1:]
		second := strings.Index(rest, ":")
		if second < 0 {
			return nil, fmt.Errorf("invalid --depends-on %q: want kind:name:constraint", raw)
		}
		out = append(out, skillbundle.Dependency{
			Kind:       raw[:first],
			Name:       rest[:second],
			Constraint: rest[second+1:],
		})
	}
	return out, nil
}

func printPackUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  skillctl pack --skill <dir> -o <out.skb> --name <n> --version <v> [options]

Required:
  --skill <dir>            Skill directory containing SKILL.md
  -o, --output <path>      Output .skb file
  --name <s>               Skill name (manifest field)
  --version <s>            Skill version (manifest field)

Optional manifest fields:
  --summary <s>
  --source-repo <s>        e.g. kamir/m3c-tools-maintenance
  --source-commit <sha>
  --source-path <s>
  --author-intent <s>      green | yellow | red (advisory only — verifier ignores; signed attestations bind)
  --author-intent-rationale <s>
  --compatibility <s>
  --depends-on kind:name:constraint   Repeatable, e.g. python:requests:>=2.31

SPEC-0196 §12 Q1 / P2b — author-signed declared data-scope (bound INTO bundle.json):
  --data-scopes <json>     Typed SPEC-0196 data-scope (repeatable). Validated fail-closed
                           at pack time through pkg/skillctl/datascope (per-kind scope,
                           §5 side-effect vocab, §3.3 cross-rules) BEFORE the digest is
                           computed, so the author signature covers it. Example:
                           --data-scopes '{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/decks/**","reason":"write deck"}'
  --data-dep <json>        DEPRECATED alias for --data-scopes (same JSON shape, same validation).
  --side-effects <list>    Comma-separated §5 side-effect tokens (signed into intent).
  --destructive true|false Author claim: irreversible changes (§3.3 cross-rule input).
  --network true|false     Author claim: outbound network (§3.3 cross-rule input).`)
}
