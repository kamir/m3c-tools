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
	_ = tr // tr is the parent struct; we only need the matched root below

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
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry base URL. Required only when trust-roots has multiple registries pinned.")
	governanceMin := fs.String("governance-min", "", "Override the trust-root's governance_minimum (green | yellow).")
	allowYellow := fs.Bool("allow-yellow", false, "Permit yellow result against a green-required trust root (does NOT re-audit; --allow-yellow is per-install).")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout for registry calls.")
	verboseFlag := fs.Bool("verbose", false, "Print structured per-step log lines to stderr.")
	homeOverride := fs.String("home", "", "Override the install root.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl verify <name> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Re-runs the SPEC-0188 §7 trust-chain check against an already-installed")
		fmt.Fprintln(stderr, "skill (~/.claude/skills/<name>/). Useful for catching post-install registry")
		fmt.Fprintln(stderr, "revocations or trust-root rotations.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes are the same as `install` (see SPEC-0188 §11).")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
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
	_ = tr

	httpClient := install.HTTPClientOf(*timeout)
	c := registry.New(root.RegistryURL, httpClient)

	var logger io.Writer
	if *verboseFlag {
		logger = stderr
	}

	res, err := install.VerifyInstalled(install.Opts{
		Name:          name,
		Client:        c,
		TrustRoot:     root,
		HomeDir:       *homeOverride,
		GovernanceMin: *governanceMin,
		AllowYellow:   *allowYellow,
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
	path, err := verify.DefaultPath()
	if err != nil {
		return nil, nil, err
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
