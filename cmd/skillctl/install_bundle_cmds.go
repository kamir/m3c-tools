package main

// install_bundle_cmds.go: `skillctl install --bundle <file.skb>` (SPEC-0406 D2).
//
// The CLI half of the untrusted-transport install. It does the parts that are a
// user-interface concern (resolve the sidecar, load the pinned roots, explain a
// misconfiguration in terms the operator can act on) and hands the trust
// decision to install.InstallBundle, which shares its verification and its write
// sequence with the registry path.
//
// Sidecar resolution and pinned author verification match runVerifyBundle.
// Managed installation additionally requires a current full revocation snapshot;
// execution checkpoints and low-risk availability policy cannot relax that gate.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
	"github.com/kamir/m3c-tools/pkg/skillctl/install"
	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

type installBundleParams struct {
	projectPolicy  *projectpolicy.Policy
	result         *bundleVerifyResult
	bundlePath     string
	metaPath       string
	trustRootsPath string
	// Offline revocation enforcement (SPEC-0276 R4.4) + freshness contract
	// (SPEC-0279 R4/R5), same three inputs as the verify twin: a signed
	// revocation list, an optional signed freshness checkpoint, an optional
	// signed emergency deny-list. Managed installs require a signed revocation
	// list; unmanaged installs retain the optional evidence behavior.
	revocationsPath string
	checkpointPath  string
	emergencyPath   string
	registryURL     string
	governanceMin   string
	allowYellow     bool
	ignoreDeps      bool
	tenantFlag      string
	homeOverride    string
	verbose         bool
}

func runInstallBundle(p installBundleParams, stdout, stderr io.Writer) (code int) {
	// One lifecycle audit event for this run, on every path that reached a trust
	// decision. Only enabled after root and profile selection. The
	// skill name is filled in once the SIGNED name is known, and stays empty when
	// the run never got that far, which is itself the honest reading.
	var audErr error
	var audName, audDigest string
	auditSelectionReady := false
	defer func() {
		if !auditSelectionReady {
			return
		}
		appendLifecycleEvent(auditHomeOf(p.homeOverride), auditevent.LifecycleEvent{
			Op:       auditevent.OpInstall,
			Skill:    audName,
			Digest:   audDigest,
			Reason:   lifecycleReasonFor(code, audErr),
			ExitCode: code,
		})
	}()

	if st, err := os.Stat(p.bundlePath); err != nil || st.IsDir() {
		fmt.Fprintf(stderr, "skillctl install --bundle: cannot read bundle file %s\n", p.bundlePath)
		return exitUsage
	}

	metaPath := p.metaPath
	if metaPath == "" {
		metaPath = defaultMetaSidecar(p.bundlePath)
	}
	meta, err := loadBundleMetaSidecar(metaPath)
	if err != nil {
		audErr = err
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	tr, root, err := installProjectTrustRoots(p.projectPolicy, p.trustRootsPath, p.registryURL)
	if err != nil {
		audErr = err
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	if root.IsManaged() && p.projectPolicy == nil {
		fmt.Fprintln(stderr, "managed install requires --enterprise-profile")
		return 12
	}
	auditSelectionReady = true

	// Same refusal as verify --bundle, and for the same reason: with no fetcher
	// the author key can only come from a local pin. A from-registry root would
	// fail deep inside the verifier with a message about a missing fetcher, which
	// tells the operator nothing about what to fix.
	if root.IdentityKeysAuthorized != "pinned" {
		fmt.Fprintf(stderr,
			"skillctl install --bundle is offline; trust root %s must use identity_keys_authorized: pinned "+
				"(so the author key is verifiable with no registry call). See SPEC-0276 R4.1.\n",
			root.RegistryURL)
		return exitGeneric
	}

	var logger io.Writer
	if p.verbose {
		logger = stderr
	}

	// Bind revocation and freshness to the verified digest before staging.
	// Managed installs require the full signed snapshot's own issuance time.
	// Checkpoints still undergo verification but cannot refresh that snapshot.
	mutationCtx, cancelMutation := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelMutation()
	var gateCode int
	var gateFresh *freshnessOutcome
	postVerify := func(res *verify.VerifyResult) error {
		// The digest is signed-verified the moment the hook runs; record it even
		// on a refusal, so the audit trail names WHAT was refused.
		audDigest = res.Digest
		var snap revocationSnapshot
		var managedEvidence []byte
		var managedStore *mutationstate.Store
		if p.revocationsPath != "" {
			var revErr error
			if root.IsManaged() {
				snap, managedEvidence, revErr = managedInstallEvidence(p.revocationsPath, root, res.Digest)
			} else {
				snap, revErr = checkBundleRevoked(p.revocationsPath, root, res.Digest)
			}
			if revErr != nil {
				gateCode = verify.ExitCode(revErr)
				return revErr
			}
			if snap.revoked && !root.IsManaged() {
				gateCode = exitBundleRevoked
				return fmt.Errorf("REVOKED: %s is in the signed revocation list (%s); refusing to install", res.Digest, p.revocationsPath)
			}
		}
		if root.IsManaged() && p.revocationsPath != "" {
			var stateErr error
			managedStore, stateErr = mutationStateStore(p.homeOverride, root)
			if stateErr == nil {
				// Explicit evidence updates an existing enrollment only. Adopt
				// never bootstraps missing history or resets stored floors.
				_, stateErr = managedStore.Adopt(mutationCtx, managedEvidence)
			}
			if stateErr != nil {
				gateCode = mutationStateExitCode(stateErr)
				return fmt.Errorf("managed install state: %w", stateErr)
			}
		}
		if root.IsManaged() || p.revocationsPath != "" || p.checkpointPath != "" || p.emergencyPath != "" {
			fresh := evaluateInstallBundleFreshness(freshnessInputs{
				root:            root,
				checkpointPath:  p.checkpointPath,
				emergencyPath:   p.emergencyPath,
				syncedEpoch:     snap.epoch,
				syncedIssuedAt:  snap.issuedAt,
				risk:            bundleActionRisk(res.DataScopes),
				emergencyTokens: []string{res.Digest, res.AuthorIdentity},
			})
			// Record the snapshot-age decision separately from the subsequent
			// mutation-state authorization and final command result.
			if p.result != nil {
				p.result.Freshness = &fresh.Decision
			}
			auditFreshnessDecision("install-bundle", res.Digest, fresh)
			if fresh.Err != nil {
				gateCode = freshnessExitCode(fresh)
				gateFresh = &fresh
				return fresh.Err
			}
		}

		return nil
	}

	res, err := install.InstallBundle(install.BundleOpts{
		ProjectPolicy: p.projectPolicy,
		BundlePath:    p.bundlePath,
		Meta:          meta,
		TrustRoot:     root,
		HomeDir:       p.homeOverride,
		GovernanceMin: p.governanceMin,
		AllowYellow:   p.allowYellow,
		IgnoreDeps:    p.ignoreDeps,
		Tenant:        resolveTenant(p.tenantFlag, tr),
		Logger:        logger,
		PostVerify:    postVerify,
		Ctx:           context.Background(),
	})
	if err != nil {
		audErr = err
		fmt.Fprintln(stderr, err)
		if gateFresh != nil {
			printFreshness(stderr, *gateFresh, p.checkpointPath, p.emergencyPath)
		}
		if gateCode != 0 {
			return gateCode
		}
		return verify.ExitCode(err)
	}
	audDigest = res.Verify.Digest
	// The recorded name is the SIGNED one, read back from where the skill
	// actually landed, not from anything the sender supplied.
	audName = filepath.Base(res.InstalledPath)
	if p.result != nil {
		p.result.setVerified(res.Verify)
		p.result.InstallPath = res.InstalledPath
		p.result.ArchivedPath = res.ArchivedPath
		return exitOK
	}

	fmt.Fprintln(stdout, res.Verify.ChainSummary)
	fmt.Fprintf(stdout, "installed: %s\n", res.InstalledPath)
	if res.ArchivedPath != "" {
		fmt.Fprintf(stdout, "archived prior install: %s\n", res.ArchivedPath)
	}
	return exitOK
}
