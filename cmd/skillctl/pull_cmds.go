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
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
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

		// P3 — install (G-23 two-step + provenance + --emit-installed)
		install          = fs.Bool("install", false, "Install verified bundles into ~/.claude/skills/<name>/ with a provenance sidecar.")
		trustMode        = fs.Bool("trust-mode", false, "Required for --install: re-affirm that you want the trust-mode path (writes a .m3c-provenance.json sidecar).")
		dryRunInstall    = fs.Bool("dry-run-install", false, "G-23 step 1: print the create/overwrite plan + a token; do NOT write.")
		confirmInstall   = fs.Bool("confirm-install", false, "G-23 step 2: consume --dry-run-install-token and write.")
		installToken     = fs.String("dry-run-install-token", "", "Token returned by --dry-run-install; required if any skill would be overwritten.")
		allowDowngrade   = fs.Bool("allow-downgrade", false, "Allow installing an older version over a newer one.")
		emitInstalled    = fs.Bool("emit-installed", false, "After install, POST a BundleInstalledEvent so the other machine sees the install.")
		installSkillsDir = fs.String("skills-dir", "", "Where to install skills. Default: ~/.claude/skills.")
		keyPath          = fs.String("key", defaultSelfKeyPath(), "[--emit-installed] Signing key for the BundleInstalledEvent envelope.")
		identity         = fs.String("identity", "id:kamir@m3c", "[--emit-installed] Author/registry identity stamped into the install event.")
		noCheckpoint     = fs.Bool("no-checkpoint", false, "Do not append a SPEC-0213 session checkpoint after install.")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl pull [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
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

	_ = verbose
	if len(res.Skipped) > 0 {
		// Even one skip is a hard fail. If the operator asked to install, say
		// plainly WHY nothing was installed and HOW to proceed.
		if *install || *dryRunInstall || *confirmInstall {
			fmt.Fprintf(stderr, "\npull: NOT installing — %d bundle(s) were skipped (the ❌ rows above).\n", len(res.Skipped))
			fmt.Fprintln(stderr, "  why: a skip means a bundle failed a gate (bad signature, revoked, governance below minimum, or unmet depends_on).")
			fmt.Fprintln(stderr, "       install aborts on ANY skip so a broken or revoked bundle can't ride in next to the good ones.")
			fmt.Fprintln(stderr, "  fix: install a known-good subset with --skill <name> or --digest <sha256:…>, or remove/replace the skipped bundles.")
		}
		return 1
	}

	// ── P3 install path ──────────────────────────────────────────────────
	if !*install && !*dryRunInstall && !*confirmInstall {
		return 0
	}
	if *install && !*trustMode {
		fmt.Fprintln(stderr, "pull --install: requires --trust-mode (the only install mode for the `self` registry)")
		return 2
	}
	if len(res.Staged) == 0 {
		fmt.Fprintln(stdout, "    (nothing to install)")
		return 0
	}

	plan, err := registry.PlanInstall(res.Staged, *installSkillsDir)
	if err != nil {
		fmt.Fprintf(stderr, "pull: plan install: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "\n==> install plan: %d create, %d overwrite\n", len(plan.Creates), len(plan.Overwrites))
	for _, r := range plan.Creates {
		fmt.Fprintf(stdout, "    + %s@%s  →  %s   (digest %s)\n", r.Name, r.Version, r.SkillPath, r.NewDigest)
	}
	for _, r := range plan.Overwrites {
		fmt.Fprintf(stdout, "    ! %s@%s  →  %s   %s → %s\n", r.Name, r.Version, r.SkillPath, strOr(r.OldDigest, "(untracked)"), r.NewDigest)
	}

	if *dryRunInstall {
		// Emit the token for the operator to feed back via --confirm-install.
		fmt.Fprintf(stdout, "\n==> dry-run-install token (5-minute TTL): %s\n", plan.Token)
		fmt.Fprintln(stdout, "    re-run with: --confirm-install --dry-run-install-token <above>")
		return 0
	}

	// Confirm-install OR a --install with zero overwrites: actually write.
	results, err := registry.ConfirmInstall(res.Staged, *installToken, registry.InstallOpts{
		SkillsDir:             *installSkillsDir,
		TrustRootsFingerprint: tr.Fingerprint,
		ContextID:             *er1Context,
		AllowDowngrade:        *allowDowngrade,
	})
	if err != nil {
		// Per-class diagnostics: every token failure states WHY and the exact FIX.
		switch {
		case errors.Is(err, registry.ErrTokenRequired):
			fmt.Fprintln(stderr, "pull --install: BLOCKED — installing would overwrite an existing skill and no install token was given.")
			fmt.Fprintln(stderr, "  why: the G-23 two-step stops you clobbering a skill without first reviewing the plan.")
			fmt.Fprintln(stderr, "  fix: 1) re-run with --dry-run-install  → prints the create/overwrite plan + a token (5-min TTL)")
			fmt.Fprintln(stderr, "       2) re-run with --confirm-install --dry-run-install-token <that exact token>")
			return 2
		case errors.Is(err, registry.ErrTokenExpired):
			fmt.Fprintf(stderr, "pull --install: BLOCKED — the --dry-run-install-token has EXPIRED (tokens live %s).\n", registry.TokenTTL)
			fmt.Fprintln(stderr, "  why: a stale token could confirm a plan that no longer matches what's on disk.")
			fmt.Fprintln(stderr, "  fix: re-run --dry-run-install for a fresh token, then run --confirm-install right away.")
			return 2
		case errors.Is(err, registry.ErrTokenInvalid):
			fmt.Fprintln(stderr, "pull --install: BLOCKED — the --dry-run-install-token is MALFORMED.")
			fmt.Fprintf(stderr, "  detail: %v\n", err)
			fmt.Fprintln(stderr, "  why: a valid token looks like <unix-seconds>.<base64url-signature>, exactly as printed by --dry-run-install.")
			fmt.Fprintln(stderr, "  fix: re-run --dry-run-install and paste the WHOLE token verbatim — no added/removed characters, no line breaks.")
			return 2
		case errors.Is(err, registry.ErrPlanDrift):
			fmt.Fprintln(stderr, "pull --install: BLOCKED — the token does NOT match this install plan (forged/tampered, or the plan changed since the dry-run).")
			fmt.Fprintln(stderr, "  why: the token is an HMAC over the exact create/overwrite set; any mismatch fails closed.")
			fmt.Fprintln(stderr, "  fix: re-run --dry-run-install to see the CURRENT plan + a fresh token, then --confirm-install with THAT token.")
			return 2
		case errors.Is(err, registry.ErrUnsafeBundleName):
			fmt.Fprintf(stderr, "pull --install: REFUSED — a staged bundle has an unsafe name.\n  detail: %v\n", err)
			return 2
		default:
			fmt.Fprintf(stderr, "pull --install: %v\n", err)
			return 1
		}
	}
	for _, r := range results {
		marker := "+"
		if r.OverwroteOld {
			marker = "↻"
		}
		fmt.Fprintf(stdout, "    %s  installed at %s  (provenance: %s)\n", marker, r.SkillPath, r.ProvenancePath)
	}

	if *emitInstalled {
		emitInstalledEvents(stdout, stderr, results, res.Staged, *keyPath, *identity, *er1Target, *er1Context, tr.Fingerprint)
	}
	maybeCheckpoint(stdout, *noCheckpoint, *er1Target, *er1Context, fmt.Sprintf("installed %d bundle(s) under %s (trust-mode)", len(results), strOr(*installSkillsDir, "~/.claude/skills")))
	return 0
}

// emitInstalledEvents posts one BundleInstalledEvent per installed bundle so
// the OTHER machine sees the install (the cross-machine visibility hook §10).
func emitInstalledEvents(stdout, stderr io.Writer, results []*registry.InstallResult, staged []*registry.StagedBundle, keyPath, identity, er1Target, er1Context, trustRootsFP string) {
	priv, err := signing.LoadPrivateKey(keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "    (emit-installed skipped: load key: %v)\n", err)
		return
	}
	defer wipe(priv)
	host := shortHostname()
	cfg, err := resolveER1Config(er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "    (emit-installed skipped: %v)\n", err)
		return
	}
	for _, b := range staged {
		ev, err := registry.BuildBundleInstalledEvent(registry.InstalledEventInput{
			BundleDigest:          b.Digest,
			Name:                  b.Name,
			Version:               b.Version,
			InstalledOnHost:       host,
			InstalledAt:           time.Now().UTC(),
			TrustRootsFingerprint: trustRootsFP,
			Registry:              "self",
		})
		if err != nil {
			fmt.Fprintf(stderr, "    (emit-installed %s: build event: %v)\n", b.Name, err)
			continue
		}
		if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
			fmt.Fprintf(stderr, "    (emit-installed %s: sign envelope: %v)\n", b.Name, err)
			continue
		}
		docID, err := registry.PublishInstalled(registry.PublishInstalledOpts{
			ER1Cfg:    cfg,
			ContextID: er1Context,
			Event:     ev,
			Skill: registry.SkillMeta{
				Name:           b.Name,
				Version:        b.Version,
				BundleDigest:   b.Digest,
				AuthorIdentity: identity,
			},
			InstalledOnHost: host,
		})
		if err != nil {
			fmt.Fprintf(stderr, "    (emit-installed %s: %v)\n", b.Name, err)
			continue
		}
		fmt.Fprintf(stdout, "    ✉ emitted installed event: %s@%s on host=%s doc=%s\n", b.Name, b.Version, host, docID)
	}
	_ = results // referenced for symmetry; not directly used here
}

func strOr(s, fb string) string {
	if s == "" {
		return fb
	}
	return s
}
