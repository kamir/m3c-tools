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
	bundlePath      string
	metaPath        string
	trustRootsPath  string
	revocationsPath string
	registryURL     string
	governanceMin   string
	allowYellow     bool
	tenantFlag      string
	jsonOut         bool
	verbose         bool
}

// bundleVerifyResult is the --json shape. Stable field names so CI scripts can
// branch on `.ok` / `.exit_code` without parsing human text.
type bundleVerifyResult struct {
	OK            bool   `json:"ok"`
	Digest        string `json:"digest,omitempty"`
	Author        string `json:"author_identity,omitempty"`
	RegistryKeyID string `json:"registry_key_id,omitempty"`
	Governance    string `json:"governance_level,omitempty"`
	// GovernanceVerified (SPEC-0281) lets machine consumers distinguish a
	// cryptographically re-verified "attested" level from an unsigned advisory
	// one — without scraping chain_summary free text.
	GovernanceVerified bool `json:"governance_verified"`
	// SelfAttested (SPEC-0246 §5) surfaces whether the binding governance
	// attestation was reviewed by the bundle's own author. Pointer-valued:
	// true (self), false (independent), null (unknown / no binding attestation).
	SelfAttested *bool  `json:"self_attested"`
	ChainSummary string `json:"chain_summary,omitempty"`
	Error        string `json:"error,omitempty"`
	ExitCode     int    `json:"exit_code"`
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

	// Offline revocation enforcement (SPEC-0276 R4.4): only meaningful once the
	// chain otherwise passed (a chain failure already returns its own code). A
	// forged/untrusted list is fail-closed (revErr → exit 12); a revoked digest
	// → exit 17.
	var revoked bool
	var revErr error
	if verr == nil && p.revocationsPath != "" {
		revoked, revErr = checkBundleRevoked(p.revocationsPath, root, res.Digest)
	}

	if p.jsonOut {
		out := bundleVerifyResult{}
		switch {
		case verr != nil:
			out.Error = verr.Error()
			out.ExitCode = verify.ExitCode(verr)
		case revErr != nil:
			out.Error = revErr.Error()
			out.ExitCode = verify.ExitCode(revErr)
		case revoked:
			out.Digest = res.Digest
			out.Error = "bundle digest is in the signed revocation list"
			out.ExitCode = exitBundleRevoked
		default:
			out.OK = true
			out.Digest = res.Digest
			out.Author = res.AuthorIdentity
			out.RegistryKeyID = res.RegistryKeyID
			out.Governance = res.GovernanceLevel
			out.GovernanceVerified = res.GovernanceVerified
			out.SelfAttested = res.SelfAttested
			out.ChainSummary = res.ChainSummary
			out.ExitCode = exitOK
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return out.ExitCode
	}

	switch {
	case verr != nil:
		fmt.Fprintln(stderr, verr)
		return verify.ExitCode(verr)
	case revErr != nil:
		fmt.Fprintln(stderr, revErr)
		return verify.ExitCode(revErr)
	case revoked:
		fmt.Fprintf(stderr, "REVOKED: %s is in the signed revocation list (%s)\n", res.Digest, p.revocationsPath)
		return exitBundleRevoked
	}
	fmt.Fprintln(stdout, res.ChainSummary+" (offline, bundle)")
	return exitOK
}

// checkBundleRevoked loads a signed revocation list, verifies its signature
// against the pinned root, and reports whether digest is revoked. A signature
// that matches no active registry key is an error (fail-closed), not a silent
// "not revoked".
func checkBundleRevoked(path string, root *verify.TrustRoot, digest string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("verify --bundle: read revocations %s: %w", path, err)
	}
	var list verify.RevocationList
	if err := json.Unmarshal(data, &list); err != nil {
		return false, fmt.Errorf("verify --bundle: parse revocations %s: %w", path, err)
	}
	set, err := verify.VerifyRevocationList(&list, root, root.MinRevocationEpoch)
	if err != nil {
		return false, err
	}
	_, revoked := set[strings.ToLower(strings.TrimSpace(digest))]
	return revoked, nil
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
