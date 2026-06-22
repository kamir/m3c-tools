package main

// SPEC-0276 R4.2 — `skillctl verify --bundle <file.skb>`.
//
// The trustless third-party path: verify a standalone .skb FILE with NO
// install state and NO network, against locally pinned trust-roots. This is
// the property a hosted-CA rival markets ("anyone can verify, no trust
// required") but cannot deliver — their verify is a call to their server; ours
// runs on the verifier's machine against a key they pinned out-of-band.
//
// Inputs:
//   - the .skb blob (digest recomputed from its bytes — repack → exit 10)
//   - a BundleMeta envelope sidecar (<file>.skbmeta.json or --meta) carrying
//     the author + registry signatures and the governance verdict
//   - a pinned trust-roots file (default or --trust-roots) whose matched root
//     MUST be identity_keys_authorized: pinned, so the author signature is
//     verifiable with no registry call
//
// Everything routes through verify.Verify, so the §7 chain, the exit codes,
// and the content-binding (digest recompute vs advertised) are identical to
// the installed-skill path — only the inputs and the "no fetcher" wiring differ.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// verifyBundleParams is the resolved flag set for the --bundle path. Grouped
// into a struct so runVerify's dispatch stays a single readable call.
type verifyBundleParams struct {
	bundlePath     string
	metaPath       string
	trustRootsPath string
	registryURL    string
	governanceMin  string
	allowYellow    bool
	tenantFlag     string
	jsonOut        bool
	verbose        bool
}

// bundleVerifyResult is the --json shape. Stable field names so CI scripts can
// branch on `.ok` / `.exit_code` without parsing human text.
type bundleVerifyResult struct {
	OK            bool   `json:"ok"`
	Digest        string `json:"digest,omitempty"`
	Author        string `json:"author_identity,omitempty"`
	RegistryKeyID string `json:"registry_key_id,omitempty"`
	Governance    string `json:"governance_level,omitempty"`
	ChainSummary  string `json:"chain_summary,omitempty"`
	Error         string `json:"error,omitempty"`
	ExitCode      int    `json:"exit_code"`
}

// runVerifyBundle implements the --bundle path. Returns the SPEC-0188 §11
// numeric exit code.
func runVerifyBundle(p verifyBundleParams, stdout, stderr io.Writer) int {
	// The .skb file must exist and be a regular file.
	if st, err := os.Stat(p.bundlePath); err != nil || st.IsDir() {
		fmt.Fprintf(stderr, "skillctl verify --bundle: cannot read bundle file %s\n", p.bundlePath)
		return exitUsage
	}

	// Load the BundleMeta envelope from the sidecar (or --meta override).
	metaPath := p.metaPath
	if metaPath == "" {
		metaPath = defaultMetaSidecar(p.bundlePath)
	}
	meta, err := loadBundleMetaSidecar(metaPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Resolve the pinned trust-roots and pick the matching root.
	tr, root, err := loadAndPickRootFromPath(p.trustRootsPath, p.registryURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// --bundle is offline by construction: with no fetcher, the author
	// signature can only be checked against a locally pinned key. Refuse a
	// from-registry root up front with an actionable message rather than
	// letting verify.Verify fail with the generic "IdentityFetcher required".
	if root.IdentityKeysAuthorized != "pinned" {
		fmt.Fprintf(stderr,
			"skillctl verify --bundle is offline; trust root %s must use identity_keys_authorized: pinned "+
				"(so the author key is verifiable with no registry call). See SPEC-0276 R4.1.\n",
			root.RegistryURL)
		return exitGeneric
	}

	tenant := resolveTenant(p.tenantFlag, tr)

	var logger io.Writer
	if p.verbose {
		logger = stderr
	}

	res, verr := verify.Verify(verify.VerifyOpts{
		BundlePath:      p.bundlePath,
		BundleMeta:      meta,
		TrustRoot:       root,
		IdentityFetcher: nil, // pinned mode: no fetcher, no network
		GovernanceMin:   p.governanceMin,
		AllowYellow:     p.allowYellow,
		Tenant:          tenant,
		Logger:          logger,
		Ctx:             context.Background(),
	})

	if p.jsonOut {
		out := bundleVerifyResult{}
		if verr != nil {
			out.Error = verr.Error()
			out.ExitCode = verify.ExitCode(verr)
		} else {
			out.OK = true
			out.Digest = res.Digest
			out.Author = res.AuthorIdentity
			out.RegistryKeyID = res.RegistryKeyID
			out.Governance = res.GovernanceLevel
			out.ChainSummary = res.ChainSummary
			out.ExitCode = exitOK
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return out.ExitCode
	}

	if verr != nil {
		fmt.Fprintln(stderr, verr)
		return verify.ExitCode(verr)
	}
	fmt.Fprintln(stdout, res.ChainSummary+" (offline, bundle)")
	return exitOK
}

// defaultMetaSidecar derives the sidecar BundleMeta path from a .skb path:
// "foo@1.0.0.skb" -> "foo@1.0.0.skbmeta.json". A non-.skb path just gets
// ".skbmeta.json" appended.
func defaultMetaSidecar(bundlePath string) string {
	if strings.HasSuffix(bundlePath, ".skb") {
		return strings.TrimSuffix(bundlePath, ".skb") + ".skbmeta.json"
	}
	return bundlePath + ".skbmeta.json"
}

// loadBundleMetaSidecar reads and JSON-decodes the BundleMeta envelope. Lenient
// on unknown fields (a registry may attach extras we don't model) — the
// security-relevant fields are validated cryptographically downstream by
// verify.Verify, not by the JSON shape here.
func loadBundleMetaSidecar(path string) (*registry.BundleMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"verify --bundle: BundleMeta sidecar not found at %s "+
					"(produce one with `skillctl export-verification-kit`, or pass --meta <file>)", path)
		}
		return nil, fmt.Errorf("verify --bundle: read sidecar %s: %w", path, err)
	}
	var meta registry.BundleMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("verify --bundle: parse sidecar %s: %w", path, err)
	}
	return &meta, nil
}
