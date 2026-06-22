package main

// Stream S8 (SPEC-0188 Phase 4) CLI runners for the install + verify
// subcommands. Mirrors S1/S7/S9-cli pattern: pure runner functions that
// take args + io.Writers + return numeric exit codes.
//
// All non-trivial logic lives in pkg/skillctl/install (composes
// pkg/skillctl/registry + pkg/skillctl/verify). This file is flag
// plumbing, trust-roots resolution, and exit-code translation.
//
// Subcommands:
//
//	skillctl install <name>[@<version>]
//	skillctl verify  <name>
//
// Both surface the SPEC-0188 §11 numbered exit codes verbatim through
// verify.ExitCode(err), so CI can branch deterministically.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// runInstall implements `skillctl install <name>[@<version>] [flags]`.
//
// Resolves the trust-root (either by --registry exact-match or, if the
// trust-roots file pins exactly one registry, by single-pin shortcut),
// builds the registry client, and runs install.Install.
//
// Returns the SPEC-0188 §11 numeric exit code on failure; 0 on success.
func runInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry base URL. Required only when trust-roots has multiple registries pinned.")
	governanceMin := fs.String("governance-min", "", "Override the trust-root's governance_minimum (green | yellow). Empty = use trust-root.")
	allowYellow := fs.Bool("allow-yellow", false, "Lower the gate from green to yellow for this install (audited).")
	ignoreDeps := fs.Bool("ignore-deps", false, "Skip depends_on resolution (audited).")
	tenantFlag := fs.String("tenant", "", "Pin this install to a tenant scope (SPEC-0188 §7 step 5.5). Overrides trust-roots tenant_scope. Empty = use trust-roots value or run untenanted.")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout for registry calls.")
	verboseFlag := fs.Bool("verbose", false, "Print structured per-step log lines to stderr.")
	homeOverride := fs.String("home", "", "Override the install root (advanced; defaults to $HOME).")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl install <name>[@<version>] [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Pulls a skill bundle from the registry, runs the SPEC-0188 §7 verifier,")
		fmt.Fprintln(stderr, "and atomically installs it under ~/.claude/skills/<name>/. Refuses if any")
		fmt.Fprintln(stderr, "trust-chain step fails.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "<version> may be a human version string (e.g. 1.0.0) or a digest pin")
		fmt.Fprintln(stderr, "(sha256:<hex>). Omit to install the newest admitted version.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Numbered exit codes (SPEC-0188 §11):")
		fmt.Fprintln(stderr, "   0  ok")
		fmt.Fprintln(stderr, "   1  generic error")
		fmt.Fprintln(stderr, "   2  usage / flag error")
		fmt.Fprintln(stderr, "  10  digest mismatch")
		fmt.Fprintln(stderr, "  11  author signature invalid")
		fmt.Fprintln(stderr, "  12  registry not in trust roots")
		fmt.Fprintln(stderr, "  13  governance below minimum")
		fmt.Fprintln(stderr, "  14  depends_on unsatisfied")
		fmt.Fprintln(stderr, "  15  blob missing")
		fmt.Fprintln(stderr, "  16  tenant blocked (CISO console verdict)")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}

	name, version, err := parseNameAtVersion(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	tr, root, err := loadAndPickRoot(*registryURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Tenant resolution (SPEC-0188 §7 step 5.5, G-18 closure 2026-05-06):
	// the CLI flag wins over the trust-roots `tenant_scope:` value. Empty
	// after this resolution = untenanted; the verifier's step 5.5 is a
	// no-op.
	tenant := resolveTenant(*tenantFlag, tr)

	// Build a registry HTTP client targeting the matched trust root.
	httpClient := install.HTTPClientOf(*timeout)
	c := registry.New(root.RegistryURL, httpClient)

	// Audit poster targets the same registry. The CLI does NOT carry a
	// separate audit URL — keeping the configuration surface narrow.
	auditPoster := install.HTTPAuditPoster(httpClient, root.RegistryURL)

	var logger io.Writer
	if *verboseFlag {
		logger = stderr
	}

	res, err := install.Install(install.Opts{
		Name:          name,
		Version:       version,
		Client:        c,
		TrustRoot:     root,
		HomeDir:       *homeOverride,
		GovernanceMin: *governanceMin,
		AllowYellow:   *allowYellow,
		IgnoreDeps:    *ignoreDeps,
		Tenant:        tenant,
		AuditPoster:   auditPoster,
		Logger:        logger,
		Now:           time.Now,
		Ctx:           context.Background(),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return verify.ExitCode(err)
	}

	// One-line chain summary on success, plus the install path so the
	// user can find what just landed.
	fmt.Fprintln(stdout, res.Verify.ChainSummary)
	fmt.Fprintf(stdout, "installed: %s\n", res.InstalledPath)
	if res.ArchivedPath != "" {
		fmt.Fprintf(stdout, "archived prior install: %s\n", res.ArchivedPath)
	}
	return exitOK
}

// runVerify implements `skillctl verify <name> [flags]`.
//
// Re-runs the §7 algorithm against an already-installed skill. Reads the
// stashed .skb from ~/.claude/skills/<name>/, fetches fresh metadata
// from the registry, and validates. No filesystem mutation.
//
// `--all` switches to the SPEC-0247 P0.2 sweep (runVerifyAll): verify every
// installed skill, optionally quarantining trust-failures. Detected before
// flag parsing because the sweep takes a different flag set.
func runVerify(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "--all" || a == "-all" {
			return runVerifyAll(args, stdout, stderr)
		}
	}

	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry base URL. Required only when trust-roots has multiple registries pinned.")
	governanceMin := fs.String("governance-min", "", "Override the trust-root's governance_minimum (green | yellow).")
	allowYellow := fs.Bool("allow-yellow", false, "Permit yellow result against a green-required trust root (does NOT re-audit; --allow-yellow is per-install).")
	tenantFlag := fs.String("tenant", "", "Pin this verify to a tenant scope (SPEC-0188 §7 step 5.5). Overrides trust-roots tenant_scope.")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout for registry calls.")
	verboseFlag := fs.Bool("verbose", false, "Print structured per-step log lines to stderr.")
	homeOverride := fs.String("home", "", "Override the install root.")
	offline := fs.Bool("offline", false, "Network-free verify: use the stashed metadata + bind the extracted on-disk content to the signed .skb. No registry calls (revocations posted after install are not seen).")
	bundlePath := fs.String("bundle", "", "Verify a standalone .skb FILE (not an installed skill), fully offline against pinned trust-roots (SPEC-0276 R4.2). Requires a sidecar <file>.skbmeta.json (or --meta).")
	metaPath := fs.String("meta", "", "Path to the BundleMeta envelope JSON for --bundle (default: the .skbmeta.json sidecar next to the .skb).")
	trustRootsPath := fs.String("trust-roots", "", "Path to a trust-roots YAML to use instead of the default (~/.claude/skill-trust-roots.yaml). Pair with --bundle for a portable verification kit.")
	revocationsPath := fs.String("revocations", "", "Path to a signed revocation list (JSON) to enforce offline for --bundle. A revoked digest → exit 17; an untrusted/forged list → exit 12.")
	jsonOut := fs.Bool("json", false, "Emit the verification result as JSON (--bundle mode).")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl verify <name> [flags]")
		fmt.Fprintln(stderr, "   or: skillctl verify --all [--quarantine]")
		fmt.Fprintln(stderr, "   or: skillctl verify --bundle <file.skb> [--trust-roots <file>] [--json]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Re-runs the SPEC-0188 §7 trust-chain check against an already-installed")
		fmt.Fprintln(stderr, "skill (~/.claude/skills/<name>/). Useful for catching post-install registry")
		fmt.Fprintln(stderr, "revocations or trust-root rotations. --offline skips the registry.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "--bundle verifies a standalone .skb FILE with NO install state and NO network,")
		fmt.Fprintln(stderr, "against locally pinned trust-roots — the trustless third-party path.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes are the same as `install` (see SPEC-0188 §11).")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// --bundle: standalone, fully-offline verification of a .skb FILE against
	// pinned trust-roots (SPEC-0276 R4.2). No install state, no network — the
	// path a third party runs to reproduce our verdict without trusting us.
	if *bundlePath != "" {
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, "skillctl verify --bundle <file.skb>: do not also pass a <name> positional arg.")
			return exitUsage
		}
		return runVerifyBundle(verifyBundleParams{
			bundlePath:      *bundlePath,
			metaPath:        *metaPath,
			trustRootsPath:  *trustRootsPath,
			revocationsPath: *revocationsPath,
			registryURL:     *registryURL,
			governanceMin:   *governanceMin,
			allowYellow:     *allowYellow,
			tenantFlag:      *tenantFlag,
			jsonOut:         *jsonOut,
			verbose:         *verboseFlag,
		}, stdout, stderr)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}

	name := fs.Arg(0)
	if strings.Contains(name, "@") {
		fmt.Fprintln(stderr, "skillctl verify: <name> must not contain @<version> (verify checks whatever is installed).")
		return exitUsage
	}

	tr, root, err := loadAndPickRoot(*registryURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Same precedence as runInstall: --tenant wins over trust-roots
	// tenant_scope; empty = untenanted (step 5.5 no-op).
	tenant := resolveTenant(*tenantFlag, tr)

	var logger io.Writer
	if *verboseFlag {
		logger = stderr
	}

	// --offline: network-free §7 + extracted-content binding (SPEC-0247).
	if *offline {
		res, err := install.VerifyInstalledOffline(install.Opts{
			Name:          name,
			TrustRoot:     root,
			HomeDir:       *homeOverride,
			GovernanceMin: *governanceMin,
			AllowYellow:   *allowYellow,
			Tenant:        tenant,
			Logger:        logger,
			Ctx:           context.Background(),
		})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return verify.ExitCode(err)
		}
		fmt.Fprintln(stdout, res.ChainSummary+" (offline)")
		return exitOK
	}

	httpClient := install.HTTPClientOf(*timeout)
	c := registry.New(root.RegistryURL, httpClient)

	res, err := install.VerifyInstalled(install.Opts{
		Name:          name,
		Client:        c,
		TrustRoot:     root,
		HomeDir:       *homeOverride,
		GovernanceMin: *governanceMin,
		AllowYellow:   *allowYellow,
		Tenant:        tenant,
		Logger:        logger,
		Ctx:           context.Background(),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return verify.ExitCode(err)
	}
	fmt.Fprintln(stdout, res.ChainSummary)
	return exitOK
}

// parseNameAtVersion splits "name@version" or "name@sha256:..." or just
// "name". Returns (name, version, err). version is "" when no @ is given;
// install.Install treats that as "newest admitted".
func parseNameAtVersion(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("install: <name> is required")
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		name := s[:i]
		version := s[i+1:]
		if name == "" {
			return "", "", fmt.Errorf("install: %q has empty name before @", s)
		}
		if version == "" {
			return "", "", fmt.Errorf("install: %q has empty version after @", s)
		}
		return name, version, nil
	}
	return s, "", nil
}

// loadAndPickRoot reads the trust-roots file and selects which entry to
// use. Logic:
//
//   - If --registry is given, exact-match it. No match → error.
//   - Else if exactly one registry is pinned, use that one (the common
//     home-lab / single-tenant case).
//   - Else, error: ambiguous, ask the user to pass --registry.
func loadAndPickRoot(registryFlag string) (*verify.TrustRoots, *verify.TrustRoot, error) {
	return loadAndPickRootFromPath("", registryFlag)
}

// loadAndPickRootFromPath is loadAndPickRoot with an explicit trust-roots file
// path. An empty path resolves to the default (~/.claude/skill-trust-roots.yaml).
// The `--trust-roots <file>` override lets a portable verification kit
// (SPEC-0276 R4.3) carry its own pinned-author trust-roots next to the .skb, so
// a third party can verify with no access to our machine's config.
func loadAndPickRootFromPath(trustRootsPath, registryFlag string) (*verify.TrustRoots, *verify.TrustRoot, error) {
	path := trustRootsPath
	if path == "" {
		p, err := verify.DefaultPath()
		if err != nil {
			return nil, nil, err
		}
		path = p
	}
	tr, err := verify.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("trust roots not configured; run `skillctl trust add --registry <url> --pubkey <path>` first (file: %s)", path)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(tr.Roots) == 0 {
		return nil, nil, fmt.Errorf("trust roots file %s has no entries; run `skillctl trust add ...`", tr.Path)
	}
	if registryFlag != "" {
		root := tr.FindRegistry(registryFlag)
		if root == nil {
			return nil, nil, fmt.Errorf("registry %q is not in trust roots (file: %s); add it with `skillctl trust add`", registryFlag, tr.Path)
		}
		return tr, root, nil
	}
	if len(tr.Roots) == 1 {
		return tr, &tr.Roots[0], nil
	}
	return nil, nil, fmt.Errorf("trust roots file %s pins multiple registries; pass --registry <url> to disambiguate", tr.Path)
}

// resolveTenant implements the SPEC-0188 §7 step 5.5 precedence rule:
// `--tenant <id>` (cliFlag) wins over the trust-roots `tenant_scope:`
// value (G-18 closure, 2026-05-06). Both empty → empty result, which the
// verifier treats as "untenanted" and skips the tenant-block check.
//
// Whitespace is trimmed on both sides so a stray space in the YAML or on
// the command line doesn't surprise an operator.
func resolveTenant(cliFlag string, tr *verify.TrustRoots) string {
	cliFlag = strings.TrimSpace(cliFlag)
	if cliFlag != "" {
		return cliFlag
	}
	if tr == nil {
		return ""
	}
	return strings.TrimSpace(tr.TenantScope)
}
