package main

// `skillctl pull` — SPEC-0225 P2.2.
//
// Query ER1 for `m3c-skill-bundle,skill-registry:self,skill-event:admitted`
// items, run the 5-gate verification gauntlet (envelope sig → digest →
// bundle sigs → governance floor → not-revoked), and stage verified bundles
// under ~/.cache/m3c/skill-bundles/<digest>/. No install yet — that's P3.
//
// Usage:
//   skillctl pull [--registry self] [--skill <name>] [--digest sha256:...]
//                 [--er1-target prod|stage|local] [--er1-context <ctx>]
//                 [--trust-roots <path>] [--since <RFC3339>]
//                 [--verbose]
//
// Exits non-zero (1) when any bundle fails a gate, after listing all
// per-bundle reasons. Exits 0 when everything passes (or when no admit
// items match the query, which is also a success).

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func runPull(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		registryName = fs.String("registry", "self", "Registry spec. Only `self` / `er1://…` are handled here; HTTP registries route through `skillctl install`.")
		skillName    = fs.String("skill", "", "Filter: only this skill name.")
		digestArg    = fs.String("digest", "", "Filter: only this exact bundle digest (sha256:<hex>).")
		er1Target    = fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target: prod | stage | local.")
		er1Context   = fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context to query.")
		trustPath    = fs.String("trust-roots", envOr("M3C_TRUST_ROOTS", ""), "Path to the SPEC-0225 trust-roots YAML. Default: ~/.claude/trust-roots.yaml.")
		since        = fs.String("since", "", "Best-effort lower bound on occurred_at (RFC3339).")
		verbose      = fs.Bool("verbose", false, "Print one line per per-gate decision.")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl pull [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !registry.IsER1Registry(*registryName) {
		fmt.Fprintf(stderr, "pull: only ER1 registries (\"self\" / \"er1://…\") are supported here; got %q\n", *registryName)
		return 2
	}

	tr, err := registry.LoadSelfTrustRoots(*trustPath)
	if err != nil {
		fmt.Fprintf(stderr, "pull: load trust-roots: %v\n", err)
		fmt.Fprintln(stderr, "       Carry ~/.claude/trust-roots.yaml from machine 1 (10-keygen-and-trustroots.sh).")
		return 2
	}

	cfg, err := resolveER1Config(*er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "pull: %v\n", err)
		return 1
	}

	res, err := registry.PullBundles(cfg, *er1Context, tr, registry.PullOpts{
		OnlySkill:  *skillName,
		OnlyDigest: *digestArg,
		Since:      *since,
	})
	if err != nil {
		fmt.Fprintf(stderr, "pull: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "==> pull (registry=%s, target=%s, context=%s, gov-min=%s)\n", "self", *er1Target, *er1Context, tr.GovernanceMinimum)
	fmt.Fprintf(stdout, "    trust-roots: %s  fp=%s\n", tr.Path, tr.Fingerprint)
	fmt.Fprintln(stdout)

	for _, s := range res.Staged {
		fmt.Fprintf(stdout, "    ✅ %s@%s  digest=%s  gov=%s  →  %s\n", s.Name, s.Version, s.Digest, s.Governance, s.StagedSkbPath)
	}
	for _, k := range res.Skipped {
		gateName := "?"
		if k.Gate != nil {
			gateName = k.Gate.Error()
		}
		fmt.Fprintf(stdout, "    ❌ %s@%s  digest=%s  [%s] %s\n", strOr(k.Name, "?"), strOr(k.Version, "?"), k.Digest, gateName, k.Detail)
	}
	fmt.Fprintf(stdout, "\n==> done. staged=%d  skipped=%d\n", len(res.Staged), len(res.Skipped))

	if _ = verbose; len(res.Skipped) > 0 {
		// Even one skip is a hard fail — the operator must see it before
		// proceeding to --install (P3).
		return 1
	}
	_ = errors.Is // keep the import
	return 0
}

func strOr(s, fb string) string {
	if s == "" {
		return fb
	}
	return s
}
