package main

// export_bundle_cmds.go: `skillctl export-bundle`, the command that produces a
// sendable artifact (SPEC-0406 Phase 2, decided 2026-09-06).
//
// THE GAP IT CLOSES. SPEC-0406 has Eric hand Mirko a .skb over an untrusted
// transport, and `install --bundle` / `verify --bundle` both need the BundleMeta
// envelope beside it. Nothing shipped produced that envelope. A search of the
// whole tree found exactly three places that construct one, and all three are
// demo or evaluation scaffolding: cmd/skillctl-demo, evaluation/scripts and
// evaluation/internal/synth. So the sender could not make a sendable thing, and
// the acceptance test could not run its own Phase 2.
//
// WHY IT READS FROM A REGISTRY RATHER THAN SIGNING ONE LOCALLY. The envelope
// carries three signature roles: author, registry and governance. An author
// alone cannot produce a valid one, and if we let them, the separation between
// authoring and admitting would quietly disappear at exactly the point where
// SPEC-0406 B2 promises it (a reviewer who is not the steward). So the sender
// publishes to their OWN registry, has it attested, and exports the result. The
// registry is the sender's; the TRANSPORT is still untrusted, which is the claim
// the acceptance test actually makes.
//
// WHY IT VERIFIES BEFORE WRITING. Exporting an artifact that does not pass its
// own chain would hand someone a kit that fails on arrival, and they would have
// no way to tell a transport problem from a packaging one. The check here is the
// same verify.Verify the recipient runs, so a kit that leaves this command is
// one that verified at least once, on the sender's machine, against the sender's
// roots.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func runExportBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry base URL. Required only when trust-roots has multiple registries pinned.")
	outDir := fs.String("out", ".", "Directory to write <name>@<version>.skb and its .skbmeta.json into.")
	governanceMin := fs.String("governance-min", "", "Override the trust-root's governance_minimum (green | yellow).")
	allowYellow := fs.Bool("allow-yellow", false, "Permit a yellow verdict against a green-required trust root.")
	tenantFlag := fs.String("tenant", "", "Pin this export to a tenant scope.")
	timeout := fs.Duration("timeout", registry.DefaultTimeout, "HTTP timeout for registry calls.")
	verboseFlag := fs.Bool("verbose", false, "Print structured per-step log lines to stderr.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl export-bundle <name>[@<version>] --out <dir> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Writes a SENDABLE pair into <dir>:")
		fmt.Fprintln(stderr, "  <name>@<version>.skb           the artifact")
		fmt.Fprintln(stderr, "  <name>@<version>.skbmeta.json  the BundleMeta envelope beside it")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "The pair is what `verify --bundle` and `install --bundle` consume. Send it by")
		fmt.Fprintln(stderr, "any means: e-mail, chat, a shared folder, a USB stick. The transport is not")
		fmt.Fprintln(stderr, "part of the recipient's trust decision; the pinned author key is.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "The chain is verified BEFORE anything is written, so a kit that leaves this")
		fmt.Fprintln(stderr, "command verified at least once here.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes are the same as `install` (SPEC-0188 §11).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	name, wantVersion, err := parseNameAtVersion(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	tr, root, err := loadAndPickRoot(*registryURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	var logger io.Writer
	if *verboseFlag {
		logger = stderr
	}

	ctx := context.Background()
	c := registry.New(root.RegistryURL, install.HTTPClientOf(*timeout))

	digest, resolvedVersion, err := resolveExportDigest(ctx, c, name, wantVersion)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return verify.ExitCode(err)
	}

	blob, err := c.GetBundle(ctx, digest)
	if err != nil {
		fmt.Fprintf(stderr, "export-bundle: fetch artifact %s: %v\n", digest, err)
		return verify.ExitCode(err)
	}
	meta, err := c.GetBundleMeta(ctx, digest)
	if err != nil {
		fmt.Fprintf(stderr, "export-bundle: fetch envelope %s: %v\n", digest, err)
		return verify.ExitCode(err)
	}

	// Stage the artifact where the verifier can hash it from disk. The verifier
	// reads a PATH, not bytes, because recomputing from the file is the check.
	staging, err := os.MkdirTemp("", "skillctl-export-*")
	if err != nil {
		fmt.Fprintf(stderr, "export-bundle: staging dir: %v\n", err)
		return exitGeneric
	}
	defer func() { _ = os.RemoveAll(staging) }()

	base := fmt.Sprintf("%s@%s", name, resolvedVersion)
	stagedSkb := filepath.Join(staging, base+".skb")
	if err := os.WriteFile(stagedSkb, blob, 0o600); err != nil {
		fmt.Fprintf(stderr, "export-bundle: stage artifact: %v\n", err)
		return exitGeneric
	}

	if _, err := verify.Verify(verify.VerifyOpts{
		BundlePath:      stagedSkb,
		BundleMeta:      meta,
		TrustRoot:       root,
		IdentityFetcher: c,
		Ctx:             ctx,
		GovernanceMin:   *governanceMin,
		AllowYellow:     *allowYellow,
		Tenant:          resolveTenant(*tenantFlag, tr),
		Logger:          logger,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, "export-bundle: refusing to export an artifact that does not pass its own chain.")
		fmt.Fprintln(stderr, "  why: a kit that fails on arrival is indistinguishable from a transport problem,")
		fmt.Fprintln(stderr, "       and the recipient would spend their time on the wrong question.")
		return verify.ExitCode(err)
	}

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "export-bundle: mkdir %s: %v\n", *outDir, err)
		return exitGeneric
	}
	skbOut := filepath.Join(*outDir, base+".skb")
	metaOut := defaultMetaSidecar(skbOut)

	if err := os.WriteFile(skbOut, blob, 0o600); err != nil {
		fmt.Fprintf(stderr, "export-bundle: write %s: %v\n", skbOut, err)
		return exitGeneric
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "export-bundle: encode envelope: %v\n", err)
		return exitGeneric
	}
	if err := os.WriteFile(metaOut, metaBytes, 0o600); err != nil {
		fmt.Fprintf(stderr, "export-bundle: write %s: %v\n", metaOut, err)
		return exitGeneric
	}

	fmt.Fprintf(stdout, "exported: %s\n", skbOut)
	fmt.Fprintf(stdout, "envelope: %s\n", metaOut)
	fmt.Fprintf(stdout, "digest:   %s\n", digest)
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Send BOTH files. The recipient needs your author key pinned first:")
	fmt.Fprintln(stdout, "  they run: skillctl peer add ... --pin sha256:<fingerprint>   (check it over a SECOND channel)")
	fmt.Fprintln(stdout, "  then:     skillctl verify --bundle "+base+".skb")
	fmt.Fprintln(stdout, "  then:     skillctl install --bundle "+base+".skb")
	return exitOK
}

// resolveExportDigest turns a name, or name@version, into the digest to export.
// An explicit sha256 pin is taken as-is; anything else goes through the
// registry's own latest/version resolution, so this command never invents a
// policy the rest of the tool does not have.
func resolveExportDigest(ctx context.Context, c *registry.Client, name, wantVersion string) (digest, resolved string, err error) {
	if strings.HasPrefix(wantVersion, "sha256:") {
		return wantVersion, strings.TrimPrefix(wantVersion, "sha256:")[:12], nil
	}
	versions, err := c.ResolveByName(ctx, name)
	if err != nil {
		return "", "", fmt.Errorf("export-bundle: list versions for %s: %w", name, err)
	}
	var newest *registry.BundleVersion
	for i := range versions {
		v := &versions[i]
		if v.Status != "admitted" {
			continue
		}
		if wantVersion != "" {
			if v.Version == wantVersion {
				return v.Digest, v.Version, nil
			}
			continue
		}
		if newest == nil {
			newest = v
		}
	}
	if wantVersion != "" {
		return "", "", fmt.Errorf("export-bundle: %s@%s is not admitted in this registry: %w", name, wantVersion, verify.ErrBlobMissing)
	}
	if newest == nil {
		return "", "", fmt.Errorf("export-bundle: no admitted version of %s in this registry: %w", name, verify.ErrBlobMissing)
	}
	return newest.Digest, newest.Version, nil
}
