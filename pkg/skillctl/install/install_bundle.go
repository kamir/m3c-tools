package install

// install_bundle.go: installing a .skb FILE that arrived over an untrusted
// transport (SPEC-0406 D2, decided 2026-09-05).
//
// WHY THIS EXISTS. `Install` pulls from a registry: it resolves a name to a
// digest, fetches the blob and the metadata, and verifies. That is the right
// production path and it stays. But it cannot express the claim SPEC-0406 AC-02
// actually makes, which is that the RECIPIENT DOES NOT HAVE TO TRUST THE
// TRANSPORT. Eric mails Mirko a .skb; there is no registry in the middle. Until
// now there was no way to install it, so the acceptance test could not run its
// own scenario.
//
// WHAT MAKES THIS SAFE, and it is worth stating because "install from a local
// file" sounds like the weaker path and is not:
//
//   - The trust root is PINNED and local. The author key is not fetched from
//     anywhere; it was pinned out of band, before the artifact arrived.
//   - There is NO NETWORK. No fetcher is passed, so nothing about the decision
//     can be influenced by whoever handed over the file.
//   - The chain is the SAME verify.Verify the registry path runs, with the same
//     gates in the same order.
//   - The write sequence is the SAME finishInstall the registry path uses, so a
//     defence added to one is a defence in both.
//
// The transport is therefore not part of the trust decision at all, which is
// exactly the property the acceptance test sets out to demonstrate. What the
// transport CAN do is deliver a different file, and that is precisely what the
// digest and signature checks catch.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// BundleOpts is the input to InstallBundle.
type BundleOpts struct {
	// BundlePath is the .skb file on disk. It arrived over an untrusted
	// transport; nothing about it is believed until the chain says so.
	BundlePath string
	// Meta is the BundleMeta envelope that travelled with the bundle (the
	// .skbmeta.json sidecar). Its claims are signature-bound, not transport-bound.
	Meta *registry.BundleMeta
	// TrustRoot must be a pinned root: the author key has to be verifiable with
	// no registry call. The caller checks this and reports it in CLI terms.
	TrustRoot *verify.TrustRoot

	// Name, when set, is checked AGAINST the signed bundle name and a mismatch
	// refuses the install. It does not override anything: the install directory
	// is always decided by signed bytes. Empty is the normal case.
	Name string

	HomeDir           string
	GovernanceMin     string
	AllowYellow       bool
	IgnoreDeps        bool
	Tenant            string
	MaxExtractedBytes int64
	Logger            io.Writer
	Ctx               context.Context
	Now               func() time.Time
}

// InstallBundle verifies a local .skb against pinned trust roots and, only if
// the whole chain passes, installs it.
//
// The error returned is the verifier's typed sentinel, so verify.ExitCode maps
// it to the same numbered SPEC-0188 §11 code the registry path produces. A
// caller must not invent its own codes here: an operator comparing two machines
// has to see the same number for the same cause.
func InstallBundle(opts BundleOpts) (*Result, error) {
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.BundlePath == "" {
		return nil, errors.New("install: --bundle path is required")
	}
	if opts.Meta == nil {
		return nil, errors.New("install: bundle metadata is required")
	}
	if opts.TrustRoot == nil {
		return nil, errors.New("install: a pinned trust root is required")
	}

	blob, err := os.ReadFile(opts.BundlePath) // #nosec G304 -- an operator-supplied path to the artifact they asked to install.
	if err != nil {
		return nil, fmt.Errorf("install: read bundle %s: %w", opts.BundlePath, err)
	}

	// ----- verify BEFORE anything is written -----
	//
	// IdentityFetcher is deliberately nil: pinned mode, no network. A nil fetcher
	// is not a weaker check, it is what makes the check independent of the party
	// who sent the file.
	verRes, err := verify.Verify(verify.VerifyOpts{
		BundlePath:      opts.BundlePath,
		BundleMeta:      opts.Meta,
		TrustRoot:       opts.TrustRoot,
		IdentityFetcher: nil,
		Ctx:             ctx,
		GovernanceMin:   opts.GovernanceMin,
		AllowYellow:     opts.AllowYellow,
		IgnoreDeps:      opts.IgnoreDeps,
		Tenant:          opts.Tenant,
		Logger:          opts.Logger,
	})
	if err != nil {
		return nil, err
	}

	// ----- WHERE the skill lands is decided by SIGNED bytes -----
	//
	// This is the sharp edge of installing from a file, and getting it wrong
	// would hand the attack back to the transport we just took it away from.
	//
	// The author signature covers the 32-byte DIGEST and nothing else
	// (verify.go stepVerifyAuthor: ed25519.Verify(pub, digest[:], sig)). The
	// sidecar's bundle record is therefore NOT signature-covered. If the install
	// directory came from the sidecar, someone who forwards a genuinely signed
	// .skb could relabel it as an already-installed skill and overwrite it: every
	// signature would verify, and the wrong thing would land.
	//
	// The name inside the archive's bundle.json IS covered, because it is part of
	// the bytes the digest is taken over. ReadDigestVerifiedManifest is the
	// repository's existing, single trust boundary for exactly this (it recomputes
	// the digest and fails closed before returning anything), and it is used here
	// rather than reimplemented, for the reason its own doc comment gives: a second
	// reader of signed content is a second place to weaken the rule.
	//
	// This is the same class of defect as the git-backend event identity: never
	// take an identity from an unsigned projection when the signed original is
	// right there.
	signedManifest, err := verify.ReadDigestVerifiedManifest(opts.BundlePath, verRes.Digest)
	if err != nil {
		return nil, fmt.Errorf("install: read signed bundle.json: %w", err)
	}
	signedName, _ := signedManifest["name"].(string)
	if signedName == "" {
		return nil, fmt.Errorf("install: the signed bundle.json carries no name: %w", verify.ErrDigestMismatch)
	}
	// An explicit --name is a statement of intent, not an override. If it
	// disagrees with the signed name, the operator believes they are installing
	// something other than what the artifact says it is, and that disagreement is
	// exactly what should stop an install rather than be silently resolved.
	if opts.Name != "" && opts.Name != signedName {
		return nil, fmt.Errorf(
			"install: --name %q does not match the signed bundle name %q: refusing rather than guessing which one you meant: %w",
			opts.Name, signedName, verify.ErrDigestMismatch)
	}
	name := signedName

	// ----- stage -----
	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	stagingDir, err := makeStagingDir(homeDir, name, verRes.Digest)
	if err != nil {
		return nil, err
	}
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	// The staged copy is what finishInstall stashes into the target, so the
	// stashed file is named from the SIGNED name and digest rather than from
	// whatever the sender happened to call the file.
	blobPath := filepath.Join(stagingDir, sanitizeFilename(name)+"-"+sanitizeDigest(verRes.Digest)+".skb")
	// 0600, not the 0644 the registry path uses for its staged copy: this file is
	// transient scaffolding inside a staging dir, and nothing needs to read it but
	// this process. gosec G306 is right that the looser mode has no justification
	// here.
	//
	// #nosec G703 -- gosec's taint analysis follows `name` from the bundle
	// manifest into a path and cannot see through sanitizeFilename, which is a
	// strict ALLOWLIST (letters, digits, '-', '_', '.') that additionally refuses
	// "." , ".." and any leading dot. No separator of any kind survives it, so a
	// traversal component cannot reach this join. sanitizeDigest guards the second
	// half the same way, and the staging dir itself is already canonicalized.
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		return nil, fmt.Errorf("install: write staged blob: %w", err)
	}
	logStep(opts.Logger, "staged_blob", "path=%s size=%d", blobPath, len(blob))

	// ----- the SAME write sequence the registry path uses -----
	//
	// resolver is nil: there is no registry to resolve identities against. The
	// offline-meta stash degrades to best-effort, exactly as it does when a
	// registry call fails on the other path.
	res, err := finishInstall(finishOpts{
		blob:       blob,
		blobPath:   blobPath,
		stagingDir: stagingDir,
		homeDir:    homeDir,
		name:       name,
		digest:     verRes.Digest,
		meta:       opts.Meta,
		resolver:   nil,
		verRes:     verRes,
		maxBytes:   opts.MaxExtractedBytes,
		logger:     opts.Logger,
		ctx:        ctx,
		now:        now,
	})
	if err != nil {
		return nil, err
	}
	cleanedUp = true
	return res, nil
}
