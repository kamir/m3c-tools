package main

// `skillctl pull`: SPEC-0225 P2.2.
//
// Query ER1 for `m3c-skill-bundle,skill-registry:self,skill-event:admitted`
// items, run the 5-gate verification gauntlet (envelope sig → digest →
// bundle sigs → governance floor → not-revoked), and stage verified bundles
// under ~/.cache/m3c/skill-bundles/<digest>/. No install yet: that's P3.
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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
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

		// P3: install (G-23 two-step + provenance + --emit-installed)
		install          = fs.Bool("install", false, "Install verified bundles into ~/.claude/skills/<name>/ with a provenance sidecar.")
		trustMode        = fs.Bool("trust-mode", false, "Required for --install: re-affirm that you want the trust-mode path (writes a .m3c-provenance.json sidecar).")
		dryRunInstall    = fs.Bool("dry-run-install", false, "G-23 step 1: print the create/overwrite plan + a token; do NOT write.")
		confirmInstall   = fs.Bool("confirm-install", false, "G-23 step 2: consume --dry-run-install-token and write.")
		installToken     = fs.String("dry-run-install-token", "", "Token returned by --dry-run-install; required if any skill would be overwritten.")
		allowDowngrade   = fs.Bool("allow-downgrade", false, "Allow installing an older version over a newer one.")
		emitInstalled    = fs.Bool("emit-installed", false, "After install, POST a BundleInstalledEvent so the other machine sees the install.")
		installSkillsDir = fs.String("skills-dir", "", "Where to install skills. Default: ~/.claude/skills.")
		keyPath          = fs.String("key", defaultSelfKeyPath(), "[--emit-installed] Signing key for the BundleInstalledEvent envelope.")
		identity         = fs.String("identity", "id:bob@m3c", "[--emit-installed] Author/registry identity stamped into the install event.")
		noCheckpoint     = fs.Bool("no-checkpoint", false, "Do not append a SPEC-0213 session checkpoint after install.")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl pull [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if !registry.IsER1Registry(*registryName) && !artifact.Registered(*registryName) {
		fmt.Fprintf(stderr, "pull: unsupported registry %q: use \"self\"/\"er1://…\" or \"gitlab://host/group/proj\"; HTTP admission registries route through `skillctl install`\n", *registryName)
		return 2
	}

	tr, peerName, err := resolvePullTrustRoots(*registryName, *trustPath)
	if err != nil {
		fmt.Fprintf(stderr, "pull: load trust-roots: %v\n", err)
		fmt.Fprintln(stderr, "       Carry ~/.claude/trust-roots.yaml from machine 1 (10-keygen-and-trustroots.sh), or pin the peer with `skillctl peer add`.")
		return 2
	}

	// Get the VERIFIED staging result from the selected carrier. The §7 gauntlet,
	// the cache/staging layout, StagedBundle, and the whole install path below are
	// identical for ER1 and git, only the SOURCE of the signed events + the .skb
	// bytes differs (SPEC-0356). A git registry requires a signed attestation ≥
	// governance_minimum per digest, exactly like the ER1 self tenant.
	var res *registry.PullResult
	if artifact.SchemeOf(*registryName) != "er1" {
		be, oerr := artifact.Open(*registryName, artifact.OpenOptions{Creds: artifactauth.New()})
		if oerr != nil {
			fmt.Fprintf(stderr, "pull: open %s: %v\n", *registryName, oerr)
			return 1
		}
		defer be.Close()
		res, err = registry.PullBundlesFromBackend(context.Background(), be, tr, registry.PullOpts{
			OnlySkill: *skillName, OnlyDigest: *digestArg, Since: *since,
		})
	} else {
		cfg, cerr := resolveER1Config(*er1Target)
		if cerr != nil {
			fmt.Fprintf(stderr, "pull: %v\n", cerr)
			return 1
		}
		// FR-0090 IS-RS-01: resolve the signed revoke-HEAD source (the SAME
		// verify.TrustRoot the SessionStart quarantine sweep uses for the HEAD) and
		// carry it into the gauntlet so Gate 5 can catch a revoke that tag discovery
		// missed. Best-effort / never-brick: a self-ER1 host with no verify.TrustRoot
		// configured leaves the URL empty (HEAD not consulted); a MANAGED enterprise
		// root additionally REQUIRES the HEAD (fail closed if unreachable) AND, via
		// the resolved epoch floor + max_staleness, rejects a replayed OLD or STALE
		// signed HEAD (SPEC-0279 R1 rollback + R3 freshness: mirror IS-T5).
		headURL, headTenant, headRequired, headFloor, headStaleness := resolveRevokeHeadSource()
		res, err = registry.PullBundles(cfg, *er1Context, tr, registry.PullOpts{
			OnlySkill: *skillName, OnlyDigest: *digestArg, Since: *since,
			RevocationHeadURL:          headURL,
			RevocationHeadTenant:       headTenant,
			RequireRevocationHead:      headRequired,
			RevocationHeadFloorEpoch:   headFloor,
			RevocationHeadMaxStaleness: headStaleness,
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "pull: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "==> pull (registry=%s, gov-min=%s)\n", *registryName, tr.GovernanceMinimum)
	fmt.Fprintf(stdout, "    trust-roots: %s  fp=%s\n", tr.Path, tr.Fingerprint)
	if peerName != "" {
		fmt.Fprintf(stdout, "    peer:        %s (pinned key)\n", peerName)
	}
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
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "    ⚠️  %s\n", w)
	}
	fmt.Fprintf(stdout, "\n==> done. staged=%d  skipped=%d\n", len(res.Staged), len(res.Skipped))

	_ = verbose
	if len(res.Skipped) > 0 {
		// Even one skip is a hard fail. If the operator asked to install, say
		// plainly WHY nothing was installed and HOW to proceed.
		if *install || *dryRunInstall || *confirmInstall {
			fmt.Fprintf(stderr, "\npull: NOT installing: %d bundle(s) were skipped (the ❌ rows above).\n", len(res.Skipped))
			fmt.Fprintln(stderr, "  why: a skip means a bundle failed a gate (bad signature, revoked, governance below minimum, or unmet depends_on).")
			fmt.Fprintln(stderr, "       install aborts on ANY skip so a broken or revoked bundle can't ride in next to the good ones.")
			fmt.Fprintln(stderr, "  fix: install a known-good subset with --skill <name> or --digest <sha256:…>, or remove/replace the skipped bundles.")
		}
		return skipExitCode(res.Skipped, stderr)
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
		RegistrySpec:          *registryName,
	})
	if err != nil {
		// Per-class diagnostics: every token failure states WHY and the exact FIX.
		switch {
		case errors.Is(err, registry.ErrTokenRequired):
			fmt.Fprintln(stderr, "pull --install: BLOCKED: installing would overwrite an existing skill and no install token was given.")
			fmt.Fprintln(stderr, "  why: the G-23 two-step stops you clobbering a skill without first reviewing the plan.")
			fmt.Fprintln(stderr, "  fix: 1) re-run with --dry-run-install  → prints the create/overwrite plan + a token (5-min TTL)")
			fmt.Fprintln(stderr, "       2) re-run with --confirm-install --dry-run-install-token <that exact token>")
			return 2
		case errors.Is(err, registry.ErrTokenExpired):
			fmt.Fprintf(stderr, "pull --install: BLOCKED: the --dry-run-install-token has EXPIRED (tokens live %s).\n", registry.TokenTTL)
			fmt.Fprintln(stderr, "  why: a stale token could confirm a plan that no longer matches what's on disk.")
			fmt.Fprintln(stderr, "  fix: re-run --dry-run-install for a fresh token, then run --confirm-install right away.")
			return 2
		case errors.Is(err, registry.ErrTokenInvalid):
			fmt.Fprintln(stderr, "pull --install: BLOCKED: the --dry-run-install-token is MALFORMED.")
			fmt.Fprintf(stderr, "  detail: %v\n", err)
			fmt.Fprintln(stderr, "  why: a valid token looks like <unix-seconds>.<base64url-signature>, exactly as printed by --dry-run-install.")
			fmt.Fprintln(stderr, "  fix: re-run --dry-run-install and paste the WHOLE token verbatim, no added/removed characters, no line breaks.")
			return 2
		case errors.Is(err, registry.ErrPlanDrift):
			fmt.Fprintln(stderr, "pull --install: BLOCKED, the token does NOT match this install plan (forged/tampered, or the plan changed since the dry-run).")
			fmt.Fprintln(stderr, "  why: the token is an HMAC over the exact create/overwrite set; any mismatch fails closed.")
			fmt.Fprintln(stderr, "  fix: re-run --dry-run-install to see the CURRENT plan + a fresh token, then --confirm-install with THAT token.")
			return 2
		case errors.Is(err, registry.ErrUnsafeBundleName):
			fmt.Fprintf(stderr, "pull --install: REFUSED: a staged bundle has an unsafe name.\n  detail: %v\n", err)
			return 2
		case errors.Is(err, skillbundle.ErrChecksumMismatch):
			// SPEC-0188 §7 step 8. The chain verified and the bytes are the signed
			// ones; the bundle's own manifest no longer describes them, which is an
			// integrity failure and reported as one. Leaving it at a bare 1 would
			// have reintroduced FR-0122 at the last step of the very path that
			// motivated it: one refusal a caller still could not attribute.
			fmt.Fprintf(stderr, "pull --install: REFUSED: the bundle's CHECKSUMS manifest does not describe its contents.\n  detail: %v\n", err)
			fmt.Fprintln(stderr, "  why: SPEC-0188 §7 step 8 verifies the manifest after extraction; any failure in steps 3 to 8 means no write.")
			fmt.Fprintln(stderr, "  fix: this is not a transport problem and retrying will not help. Ask the publisher to repack and re-sign.")
			return exitcode.VerifyDigestMismatch.Number
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
		if artifact.SchemeOf(*registryName) != "er1" {
			// Route the BundleInstalledEvent to the ACTIVE backend (git/GitLab),
			// not silently into ER1: cross-machine install visibility on the same
			// carrier the bundle came from.
			emitInstalledEventsViaBackend(stdout, stderr, res.Staged, *registryName, *keyPath, *identity, tr.Fingerprint)
		} else {
			emitInstalledEvents(stdout, stderr, results, res.Staged, *keyPath, *identity, *er1Target, *er1Context, tr.Fingerprint)
		}
	}
	maybeCheckpoint(stdout, *noCheckpoint, *er1Target, *er1Context, fmt.Sprintf("installed %d bundle(s) under %s (trust-mode)", len(results), strOr(*installSkillsDir, "~/.claude/skills")))
	return 0
}

// emitInstalledEventsViaBackend is the git/GitLab peer of emitInstalledEvents:
// it builds + signs the SAME BundleInstalledEvent and appends it to the active
// artifact backend via Publish(KindInstall): ZERO signing changes, the git
// backend commits it under events/<digesthex>/. Failures are non-fatal (the
// install already succeeded); each is reported and the loop continues.
func emitInstalledEventsViaBackend(stdout, stderr io.Writer, staged []*registry.StagedBundle, spec, keyPath, identity, trustRootsFP string) {
	priv, err := signing.LoadPrivateKey(keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "    (emit-installed skipped: load key: %v)\n", err)
		return
	}
	defer wipe(priv)
	be, err := artifact.Open(spec, artifact.OpenOptions{Creds: artifactauth.New()})
	if err != nil {
		fmt.Fprintf(stderr, "    (emit-installed skipped: open %s: %v)\n", spec, err)
		return
	}
	defer be.Close()
	host := shortHostname()
	ctx := context.Background()
	for _, b := range staged {
		ev, err := registry.BuildBundleInstalledEvent(registry.InstalledEventInput{
			BundleDigest:          b.Digest,
			Name:                  b.Name,
			Version:               b.Version,
			InstalledOnHost:       host,
			InstalledAt:           time.Now().UTC(),
			TrustRootsFingerprint: trustRootsFP,
			Registry:              spec,
		})
		if err != nil {
			fmt.Fprintf(stderr, "    (emit-installed %s: build event: %v)\n", b.Name, err)
			continue
		}
		if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
			fmt.Fprintf(stderr, "    (emit-installed %s: sign envelope: %v)\n", b.Name, err)
			continue
		}
		res, err := be.Publish(ctx, artifact.PublishRequest{
			Kind:  artifact.KindInstall,
			Event: ev,
			Meta:  artifact.ArtifactMeta{Name: b.Name, Version: b.Version, Digest: b.Digest, AuthorIdentity: identity},
		})
		if err != nil {
			fmt.Fprintf(stderr, "    (emit-installed %s: %v)\n", b.Name, err)
			continue
		}
		fmt.Fprintf(stdout, "    ✉ emitted installed event: %s@%s on host=%s ref=%s\n", b.Name, b.Version, host, res.NativeID)
	}
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

// resolveRevokeHeadSource resolves the signed revoke-HEAD source for the ER1 pull
// gauntlet (FR-0090 IS-RS-01). It reuses loadRootsFn, the SAME verify.TrustRoot
// resolver the quarantine sweep's fetchRevocationHeadOnline uses, so the HEAD
// endpoint + freshness posture are configured in one place. Never-brick: any
// failure (no verify.TrustRoot, multiple registries pinned, …) yields an empty
// URL, so a default self-ER1 / air-gapped host consults no HEAD and behaves as
// before. A MANAGED enterprise root REQUIRES the HEAD (fail closed if it is
// unreachable/unverifiable), mirroring the IS-T5 managed-root freshness contract.
func resolveRevokeHeadSource() (url, tenant string, required bool, floorEpoch int, maxStaleness time.Duration) {
	roots, root, err := loadRootsFn("")
	if err != nil || root == nil {
		return "", "", false, 0, 0
	}
	if roots != nil {
		tenant = roots.TenantScope
	}
	// Epoch floor for SPEC-0279 R1 rollback protection = the higher of the pinned
	// minimum and the persisted adopted epoch (the sweep's floor). Either alone
	// defeats a replay of an older signed HEAD; together they cover a fresh host
	// (pinned min) and a previously-synced host (persisted).
	floorEpoch = root.MinRevocationEpoch
	if home, herr := userHome(); herr == nil {
		if he, _ := readRevokedCacheHead(home); he > floorEpoch {
			floorEpoch = he
		}
	}
	if d, perr := time.ParseDuration(strings.TrimSpace(root.MaxStaleness)); perr == nil && d > 0 {
		maxStaleness = d
	}
	return root.RegistryURL, tenant, root.IsManaged(), floorEpoch, maxStaleness
}

// resolvePullTrustRoots picks the verification key for a pull (SPEC-0359 D2). For
// self / er1:// / empty it loads the self trust-roots VERBATIM (byte-identical to
// pre-D2: the no-regression guarantee). For any other locator it consults the
// peer store: a PINNED peer verifies against THAT peer's pinned key; an unpinned
// locator falls through to the self roots (unchanged: a gitlab:// mirror of your
// OWN skills still verifies against your own key). Returns the peer name when a
// pin was used ("" otherwise).
func resolvePullTrustRoots(registryName, trustPath string) (*registry.SelfTrustRoots, string, error) {
	if registryName == "" || registry.IsER1Registry(registryName) {
		tr, err := registry.LoadSelfTrustRoots(trustPath)
		return tr, "", err
	}
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		return nil, "", err
	}
	if pe, ok := peers.FindPeerByLocator(registryName); ok {
		tr, aerr := pe.AsTrustRoots()
		if aerr != nil {
			return nil, "", aerr
		}
		tr.Path = strOr(peersConfigPath, registry.DefaultPeersPath())
		return tr, pe.Name, nil
	}
	tr, lerr := registry.LoadSelfTrustRoots(trustPath)
	return tr, "", lerr
}

// skipExitCode turns the gates that refused into a process exit code (FR-0122).
//
// The path used to return a bare 1 for every refusal. A caller, an audit record
// and any automated policy see the SIGNAL, not the cause, so a revoked bundle and
// an unsigned one were the same event to everything downstream. That matters most
// for the case it matters most in: a revocation is never retried, and a transient
// fetch failure always is.
//
// Four gates map onto the numbers SPEC-0188 §11 already assigns. The fifth had no
// number at all: the specification named 15 for bundle_revoked, but 15 has meant
// blob_missing in every shipped build (BUG-0216). The first FR-0122 cut gave
// revocation the 20 on the claim "20 is free"; true against the exitcode
// register, false against the exit surfaces outside it (verify.ExitSelfAttested,
// SPEC-0246 §5.2, has shipped 20 for weeks). Befund 1.4: the one-day-old,
// unreleased side yields. Revocation is exitcode.RevokedBundle (6), the
// specification is corrected, and 15 keeps the meaning callers have.
//
// MIXED refusals stay 1, deliberately. One number cannot describe two causes, and
// picking the "worst" would invent a ranking nothing else in this tool uses. The
// caller is told, in words, that the rows differ and that the codes are per-gate.
func skipExitCode(skipped []*registry.PullSkip, stderr io.Writer) int {
	codes := map[int]bool{}
	for _, k := range skipped {
		codes[gateExit(k.Gate)] = true
	}
	if len(codes) == 1 {
		for c := range codes {
			return c
		}
	}
	fmt.Fprintf(stderr, "\npull: %d bundle(s) were skipped for DIFFERENT reasons, so no single exit code describes the run.\n", len(skipped))
	fmt.Fprintln(stderr, "  exit 1 here means \"more than one cause\"; the per-bundle gate is on each ❌ row above.")
	return 1
}

// gateExit maps one gate to its code. An unrecognised or absent gate is 1: a
// refusal whose cause this function does not know must not borrow a number that
// promises a specific one.
func gateExit(gate error) int {
	switch {
	case gate == nil:
		return 1
	case errors.Is(gate, registry.ErrGateEnvelope):
		return exitcode.VerifyRegistryNotTrusted.Number
	case errors.Is(gate, registry.ErrGateDigest):
		return exitcode.VerifyDigestMismatch.Number
	case errors.Is(gate, registry.ErrGateBundleSigs):
		return exitcode.VerifyAuthorSigInvalid.Number
	case errors.Is(gate, registry.ErrGateGovernance):
		return exitcode.VerifyGovernanceBelowMin.Number
	case errors.Is(gate, registry.ErrGateRevoked):
		return exitcode.RevokedBundle.Number
	default:
		return 1
	}
}
