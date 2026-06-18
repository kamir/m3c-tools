package main

// `skillctl publish` — SPEC-0225 P1.3.
//
// Two modes:
//   skillctl publish <name[@ver]> [--registry self] [--bundle <path>] [--skill-dir <dir>]
//                                 [--key <path>] [--identity <id>] [--inline-max <bytes>]
//                                 [--er1-target prod|stage|local] [--er1-context <ctx>]
//                                 [--yes] [--dry-run]
//      Builds (or reuses) a .skb, signs it, builds a SPEC-0190 BundleAdmittedEvent,
//      envelope-signs it with the same key, and POSTs the ER1 item via /upload_2.
//      Idempotent on bundle digest (re-runs are no-ops).
//
//   skillctl publish --attest <name[@ver]> --level green|yellow|red --rationale <text>
//                    [--digest sha256:<hex> | --bundle <path>] [--registry self] [...]
//      Posts an AttestationPublishedEvent item — the governance verdict for an
//      already-admitted digest.
//
// Default registry is "self" (the personal ER1-mediated tenant, SPEC-0225). The
// ER1 target/context default to env (ER1_TARGET / ER1_CONTEXT) → prod / "skills"
// when unset, matching INFRA/skill-registry/env/self.env.
//
// What's deliberately not here yet (next P1 commits): --all manifest loop (P1.4);
// auto-checkpoint on the open SPEC-0213 session (P1.5); MinIO claim-check
// overflow (deferred — keep bundles inline for v1).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/session"
	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// sessionCheckpoint is a thin wrapper around pkg/session.Checkpoint with the
// CLAUDE_SESSION_ID-derived session id + the publish-supplied note.
func sessionCheckpoint(sessionID, er1Target, er1Context, note string) (*session.CheckpointResult, error) {
	wd, _ := os.Getwd()
	return session.Checkpoint(session.CheckpointOpts{
		WorkingDir: wd,
		SessionID:  sessionID,
		ER1Target:  er1Target,
		ER1Context: er1Context,
		Note:       note,
		Auto:       false,
	})
}

// runPublish is the main.go entry point for the `publish` subcommand.
func runPublish(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		// Selection
		registryName = fs.String("registry", "self", "Registry spec. \"self\" (recommended) or \"er1://...\". HTTP registries route through the existing admission client, not this transport.")
		skillDir     = fs.String("skill-dir", "", "Path to the skill directory. Default: ~/.claude/skills/<name>.")
		bundle       = fs.String("bundle", "", "Path to a pre-built .skb. If empty, the skill dir is packed in-place to ./<name>@<version>.skb.")
		version      = fs.String("version", "", "Skill version (overrides the SKILL.md frontmatter). Required for admit; inferred from --bundle filename for attest.")
		identity     = fs.String("identity", "id:kamir@m3c", "Author/registry identity id stamped into the event and tags.")

		// Key
		keyPath = fs.String("key", defaultSelfKeyPath(), "Path to the ed25519 private key (PEM PKCS#8). Default: $SIGNING_KEY_LOCATION or ~/.config/m3c/skill-registry-self.key.")

		// ER1 target
		er1Target  = fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target: prod | stage | local.")
		er1Context = fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context to POST into.")

		// Tiering
		inlineMax = fs.Int("inline-max", envOrInt("ER1_INLINE_MAX_BYTES", 262144), "Inline base64 cap; bundles above this need a claim-check (not implemented v1).")

		// Modes
		attest    = fs.Bool("attest", false, "Mode: publish a governance attestation (AttestationPublishedEvent) rather than admitting a new bundle.")
		revoke    = fs.Bool("revoke", false, "Mode: publish a BundleRevokedEvent for an admitted digest. Requires --digest and --reason.")
		level     = fs.String("level", "green", "[--attest] Governance level: green | yellow | red.")
		rationale = fs.String("rationale", "", "[--attest|--revoke] One-line rationale.")
		reason    = fs.String("reason", "", "[--revoke] Short reason code (e.g. key-compromise, deprecated).")
		digestArg = fs.String("digest", "", "[--attest|--revoke] Existing bundle digest (sha256:<hex>). If empty, derived from --bundle.")

		// Batch (P1.4)
		all      = fs.Bool("all", false, "Publish every entry in --manifest (admit + attest as one batch).")
		manifest = fs.String("manifest", "INFRA/skill-registry/self/publish-manifest.txt", "Path to the publish manifest (only used with --all).")

		// Session hook (P1.5)
		noCheckpoint = fs.Bool("no-checkpoint", false, "Do not append a checkpoint to the open SPEC-0213 session (default: on if a session is open).")

		// SPEC-0275: auto-register the skill's runbook.html into the THOH catalog.
		noRunbookPublish = fs.Bool("no-runbook-publish", false, "Do not auto-register the skill's runbook.html/runbook.meta.json into the THOH catalog (SPEC-0275).")

		// UX
		yes    = fs.Bool("yes", false, "Skip the 🟡 confirm pause (scripted runs).")
		dryRun = fs.Bool("dry-run", false, "Print the plan + the rendered item body; do not POST or pack.")
	)
	// SPEC-0096 room mapping (SPEC-0246 §7). Repeatable; each value is a room's
	// room_label, stamped as a bare tag so room members can read the bundle.
	var shareRooms stringSliceFlag
	fs.Var(&shareRooms, "share-room", "Map the bundle into a SPEC-0096 co-learning room by its room_label, e.g. --share-room aims-basics. Repeatable. Default: $SKILL_SHARE_ROOMS (comma-separated).")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl publish <name[@ver]> [flags]")
		fmt.Fprintln(stderr, "       skillctl publish --attest <name[@ver]> --level green --rationale '<why>' [flags]")
		fs.PrintDefaults()
	}
	// stdlib flag.Parse stops at the first non-flag arg, so flags after the
	// positional skill name are silently dropped (the --dry-run bug surfaced
	// during the P5 run). Reorder: flag-tokens first, positionals last.
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	// Seed from $SKILL_SHARE_ROOMS when no --share-room was passed.
	rooms := []string(shareRooms)
	if len(rooms) == 0 {
		if env := strings.TrimSpace(os.Getenv("SKILL_SHARE_ROOMS")); env != "" {
			for _, r := range strings.Split(env, ",") {
				if r = strings.TrimSpace(r); r != "" {
					rooms = append(rooms, r)
				}
			}
		}
	}

	if *all {
		return runPublishAll(stdout, stderr, publishAllArgs{
			manifestPath: *manifest,
			identity:     *identity,
			keyPath:      *keyPath,
			er1Target:    *er1Target,
			er1Context:   *er1Context,
			inlineMax:    *inlineMax,
			yes:          *yes,
			dryRun:       *dryRun,
			noCheckpoint: *noCheckpoint,
			shareRooms:   rooms,
		})
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return 2
	}

	if !registry.IsER1Registry(*registryName) {
		fmt.Fprintf(stderr, "publish: only ER1 registries (\"self\" or \"er1://...\") are supported by this command — use `skillctl install` for HTTP admission registries; got %q\n", *registryName)
		return 2
	}

	name, ver := splitNameVersion(fs.Arg(0))
	if *version != "" {
		ver = *version
	}
	if name == "" {
		fmt.Fprintln(stderr, "publish: skill name required (positional arg 1)")
		return 2
	}

	if *attest {
		return runPublishAttest(stdout, stderr, publishAttestArgs{
			name:         name,
			version:      ver,
			level:        *level,
			rationale:    *rationale,
			digestArg:    *digestArg,
			bundlePath:   *bundle,
			identity:     *identity,
			keyPath:      *keyPath,
			er1Target:    *er1Target,
			er1Context:   *er1Context,
			yes:          *yes,
			dryRun:       *dryRun,
			noCheckpoint: *noCheckpoint,
			shareRooms:   rooms,
		})
	}
	if *revoke {
		return runPublishRevoke(stdout, stderr, publishRevokeArgs{
			name:         name,
			version:      ver,
			reason:       *reason,
			rationale:    *rationale,
			digestArg:    *digestArg,
			bundlePath:   *bundle,
			identity:     *identity,
			keyPath:      *keyPath,
			er1Target:    *er1Target,
			er1Context:   *er1Context,
			yes:          *yes,
			dryRun:       *dryRun,
			noCheckpoint: *noCheckpoint,
			shareRooms:   rooms,
		})
	}
	return runPublishAdmit(stdout, stderr, publishAdmitArgs{
		name:             name,
		version:          ver,
		skillDir:         *skillDir,
		bundlePath:       *bundle,
		identity:         *identity,
		keyPath:          *keyPath,
		er1Target:        *er1Target,
		er1Context:       *er1Context,
		inlineMax:        *inlineMax,
		yes:              *yes,
		dryRun:           *dryRun,
		noCheckpoint:     *noCheckpoint,
		noRunbookPublish: *noRunbookPublish,
		shareRooms:       rooms,
	})
}

// ─── admit mode ────────────────────────────────────────────────────────────

type publishAdmitArgs struct {
	name, version, skillDir, bundlePath, identity, keyPath string
	er1Target, er1Context                                  string
	inlineMax                                              int
	yes, dryRun, noCheckpoint, noRunbookPublish            bool
	shareRooms                                             []string
}

func runPublishAdmit(stdout, stderr io.Writer, a publishAdmitArgs) int {
	// 1. Locate or build the .skb.
	skbPath, ver, err := ensureBundle(a, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "publish: %v\n", err)
		return 1
	}
	if ver == "" {
		ver = "0.0.0"
	}

	// 2. Read the .skb bytes + compute the digest (the signing pkg also
	// computes it, but we need the bytes anyway for the inline body).
	skb, err := os.ReadFile(skbPath)
	if err != nil {
		fmt.Fprintf(stderr, "publish: read %s: %v\n", skbPath, err)
		return 1
	}
	digestHex, digestBytes := sha256Hex(skb)
	digest := "sha256:" + digestHex

	// 3. Load the key and produce the author+registry sigs. The personal
	// tenant uses one key playing both roles — same sig bytes, two records.
	priv, err := signing.LoadPrivateKey(a.keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "publish: load key: %v\n", err)
		return 1
	}
	defer wipe(priv)
	sigBytes := ed25519.Sign(priv, digestBytes[:])
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	pubFP := pubkeyFingerprint(priv.Public().(ed25519.PublicKey))

	sigs := []registry.SignatureRef{
		{Role: "author", IdentityID: a.identity, SignatureB64: sigB64, PubKeyFingerprint: pubFP},
		{Role: "registry", IdentityID: a.identity, SignatureB64: sigB64, PubKeyFingerprint: pubFP},
	}

	// 4. Build the BundleAdmittedEvent and sign its envelope.
	now := time.Now().UTC()
	ev, err := registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{
		BundleDigest:       digest,
		Name:               a.name,
		Version:            ver,
		AuthorIntent:       "green", // declared author intent; attestation verdict is separate
		AdmittedByIdentity: a.identity,
		AdmittedAt:         now,
		Signatures:         sigs,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish: build event: %v\n", err)
		return 1
	}
	if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
		fmt.Fprintf(stderr, "publish: sign envelope: %v\n", err)
		return 1
	}

	skill := registry.SkillMeta{
		Name:            a.name,
		Version:         ver,
		BundleDigest:    digest,
		AuthorIdentity:  a.identity,
		GovernanceLevel: "green",
		PackedOnHost:    shortHostname(),
		ShareRooms:      a.shareRooms,
	}

	// 5. Plan + 🟡 confirm pause.
	fmt.Fprintf(stdout, "==> publish (admit) %s@%s\n", a.name, ver)
	fmt.Fprintf(stdout, "    digest:    %s\n", digest)
	fmt.Fprintf(stdout, "    bytes:     %d\n", len(skb))
	fmt.Fprintf(stdout, "    transport: %s\n", chooseTransport(len(skb), a.inlineMax))
	fmt.Fprintf(stdout, "    host:      %s\n", skill.PackedOnHost)
	fmt.Fprintf(stdout, "    identity:  %s\n", a.identity)
	fmt.Fprintf(stdout, "    target:    %s  context: %s\n", a.er1Target, a.er1Context)
	if a.dryRun {
		fmt.Fprintln(stdout, "    (dry-run; skipping POST)")
		return 0
	}
	if !a.yes && !promptYesNo(stdout, "Proceed with publish? [y/N]: ") {
		fmt.Fprintln(stdout, "    aborted by operator")
		return 0
	}

	// 6. POST.
	cfg, err := resolveER1Config(a.er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "publish: %v\n", err)
		return 1
	}
	res, err := registry.PublishAdmitted(registry.PublishAdmittedOpts{
		ER1Cfg:         cfg,
		ContextID:      a.er1Context,
		Event:          ev,
		Skill:          skill,
		SkbBytes:       skb,
		InlineMaxBytes: a.inlineMax,
		Now:            now,
	})
	if errors.Is(err, registry.ErrAlreadyPublished) {
		fmt.Fprintf(stdout, "==> already published: doc_id=%s (idempotent no-op)\n", res.DocID)
		maybeRegisterRunbook(stdout, stderr, a, ver) // SPEC-0275 (best-effort)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "publish: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "==> admitted: doc_id=%s  transport=%s  body_bytes=%d\n", res.DocID, res.Transport, res.ItemBodySize)
	maybeCheckpoint(stdout, a.noCheckpoint, a.er1Target, a.er1Context, fmt.Sprintf("published (admit) %s@%s digest=%s doc=%s", a.name, ver, digest, res.DocID))
	maybeRegisterRunbook(stdout, stderr, a, ver) // SPEC-0275 (best-effort)
	return 0
}

// resolveBundleDigest determines the sha256 digest for --attest / --revoke:
//  1. --digest sha256:<hex> if given (verbatim)
//  2. --bundle <path> → sha256 of that file
//  3. the in-place bundle ./<name>@<version>.skb that `publish` (admit) writes —
//     so `publish --attest <name>@<ver>` works right after `publish <name>@<ver>`
//     with no repeated --digest/--bundle.
func resolveBundleDigest(digestArg, bundlePath, name, version string) (string, error) {
	if strings.TrimSpace(digestArg) != "" {
		return digestArg, nil
	}
	if bundlePath == "" {
		cand := fmt.Sprintf("%s@%s.skb", name, version)
		if _, err := os.Stat(cand); err == nil {
			bundlePath = cand
		}
	}
	if bundlePath == "" {
		return "", fmt.Errorf("need --digest sha256:<hex> or --bundle <path> "+
			"(no ./%s@%s.skb here — run from where you published, or pass --digest)", name, version)
	}
	skb, err := os.ReadFile(bundlePath)
	if err != nil {
		return "", fmt.Errorf("read bundle %s: %w", bundlePath, err)
	}
	d, _ := sha256Hex(skb)
	return "sha256:" + d, nil
}

// ─── attest mode ───────────────────────────────────────────────────────────

type publishAttestArgs struct {
	name, version, level, rationale, digestArg, bundlePath, identity, keyPath string
	er1Target, er1Context                                                     string
	yes, dryRun, noCheckpoint                                                 bool
	shareRooms                                                                []string
}

func runPublishAttest(stdout, stderr io.Writer, a publishAttestArgs) int {
	digest, err := resolveBundleDigest(a.digestArg, a.bundlePath, a.name, a.version)
	if err != nil {
		fmt.Fprintf(stderr, "publish --attest: %v\n", err)
		return 2
	}

	priv, err := signing.LoadPrivateKey(a.keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "publish --attest: load key: %v\n", err)
		return 1
	}
	defer wipe(priv)

	now := time.Now().UTC()
	ev, err := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{
		BundleDigest:    digest,
		ReviewerID:      a.identity,
		GovernanceLevel: a.level,
		Rationale:       a.rationale,
		OccurredAt:      now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish --attest: build event: %v\n", err)
		return 1
	}
	if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
		fmt.Fprintf(stderr, "publish --attest: sign envelope: %v\n", err)
		return 1
	}

	skill := registry.SkillMeta{
		Name:           a.name,
		Version:        a.version,
		BundleDigest:   digest,
		AuthorIdentity: a.identity,
		ShareRooms:     a.shareRooms,
	}

	fmt.Fprintf(stdout, "==> publish --attest %s@%s\n", a.name, a.version)
	fmt.Fprintf(stdout, "    digest:    %s\n", digest)
	fmt.Fprintf(stdout, "    level:     %s\n", a.level)
	fmt.Fprintf(stdout, "    rationale: %s\n", a.rationale)
	if a.dryRun {
		fmt.Fprintln(stdout, "    (dry-run; skipping POST)")
		return 0
	}
	if !a.yes && !promptYesNo(stdout, "Proceed with attestation? [y/N]: ") {
		fmt.Fprintln(stdout, "    aborted by operator")
		return 0
	}

	cfg, err := resolveER1Config(a.er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "publish --attest: %v\n", err)
		return 1
	}
	docID, err := registry.PublishAttested(registry.PublishAttestedOpts{
		ER1Cfg:    cfg,
		ContextID: a.er1Context,
		Event:     ev,
		Skill:     skill,
		Now:       now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish --attest: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "==> attested: doc_id=%s\n", docID)
	maybeCheckpoint(stdout, a.noCheckpoint, a.er1Target, a.er1Context, fmt.Sprintf("attested %s@%s level=%s digest=%s doc=%s", a.name, a.version, a.level, digest, docID))
	return 0
}

// ─── revoke mode (P2.3) ───────────────────────────────────────────────────

type publishRevokeArgs struct {
	name, version, reason, rationale, digestArg, bundlePath, identity, keyPath string
	er1Target, er1Context                                                      string
	yes, dryRun, noCheckpoint                                                  bool
	shareRooms                                                                 []string
}

func runPublishRevoke(stdout, stderr io.Writer, a publishRevokeArgs) int {
	digest, err := resolveBundleDigest(a.digestArg, a.bundlePath, a.name, a.version)
	if err != nil {
		fmt.Fprintf(stderr, "publish --revoke: %v\n", err)
		return 2
	}
	if a.reason == "" {
		fmt.Fprintln(stderr, "publish --revoke: --reason required (short code, e.g. key-compromise, deprecated)")
		return 2
	}

	priv, err := signing.LoadPrivateKey(a.keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "publish --revoke: load key: %v\n", err)
		return 1
	}
	defer wipe(priv)

	now := time.Now().UTC()
	ev, err := registry.BuildBundleRevokedEvent(registry.RevokedEventInput{
		BundleDigest: digest,
		ReasonCode:   a.reason,
		Rationale:    a.rationale,
		RevokedBy:    a.identity,
		OccurredAt:   now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish --revoke: build event: %v\n", err)
		return 1
	}
	if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
		fmt.Fprintf(stderr, "publish --revoke: sign envelope: %v\n", err)
		return 1
	}

	skill := registry.SkillMeta{
		Name:           a.name,
		Version:        a.version,
		BundleDigest:   digest,
		AuthorIdentity: a.identity,
		ShareRooms:     a.shareRooms,
	}

	fmt.Fprintf(stdout, "==> publish --revoke %s@%s\n", a.name, a.version)
	fmt.Fprintf(stdout, "    digest:    %s\n", digest)
	fmt.Fprintf(stdout, "    reason:    %s\n", a.reason)
	fmt.Fprintf(stdout, "    rationale: %s\n", a.rationale)
	if a.dryRun {
		fmt.Fprintln(stdout, "    (dry-run; skipping POST)")
		return 0
	}
	if !a.yes && !promptYesNo(stdout, "Proceed with revocation? [y/N]: ") {
		fmt.Fprintln(stdout, "    aborted by operator")
		return 0
	}
	cfg, err := resolveER1Config(a.er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "publish --revoke: %v\n", err)
		return 1
	}
	docID, err := registry.PublishRevoked(registry.PublishRevokedOpts{
		ER1Cfg:    cfg,
		ContextID: a.er1Context,
		Event:     ev,
		Skill:     skill,
		Now:       now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "publish --revoke: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "==> revoked: doc_id=%s\n", docID)
	maybeCheckpoint(stdout, a.noCheckpoint, a.er1Target, a.er1Context, fmt.Sprintf("revoked %s@%s digest=%s reason=%s doc=%s", a.name, a.version, digest, a.reason, docID))
	return 0
}

// ─── --all batch mode (P1.4) ──────────────────────────────────────────────

type publishAllArgs struct {
	manifestPath, identity, keyPath, er1Target, er1Context string
	inlineMax                                              int
	yes, dryRun, noCheckpoint                              bool
	shareRooms                                             []string
}

func runPublishAll(stdout, stderr io.Writer, a publishAllArgs) int {
	entries, err := LoadManifestFile(a.manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "publish --all: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintln(stderr, "publish --all: manifest is empty")
		return 1
	}

	// Batch-level 🟡 plan + confirm.
	fmt.Fprintf(stdout, "==> publish --all  (manifest: %s, %d entries)\n", a.manifestPath, len(entries))
	fmt.Fprintf(stdout, "    target: %s  context: %s  identity: %s\n", a.er1Target, a.er1Context, a.identity)
	for _, e := range entries {
		v := e.Version
		if v == "" {
			v = "(auto)"
		}
		lvl := e.Level
		if lvl == "" {
			lvl = "—"
		}
		fmt.Fprintf(stdout, "    %2d  admit + attest(%s)  %s@%s  %s\n", e.Line, lvl, e.Name, v, e.Rationale)
	}
	if a.dryRun {
		fmt.Fprintln(stdout, "    (dry-run; skipping POSTs)")
		return 0
	}
	if !a.yes && !promptYesNo(stdout, "Proceed with batch publish? [y/N]: ") {
		fmt.Fprintln(stdout, "    aborted by operator")
		return 0
	}

	// Run each entry (admit then attest) NON-interactively (the batch
	// confirm covers them all).
	okCount, failCount := 0, 0
	for _, e := range entries {
		fmt.Fprintf(stdout, "\n----  %s@%s  ----\n", e.Name, e.Version)
		rcA := runPublishAdmit(stdout, stderr, publishAdmitArgs{
			name:         e.Name,
			version:      e.Version,
			identity:     a.identity,
			keyPath:      a.keyPath,
			er1Target:    a.er1Target,
			er1Context:   a.er1Context,
			inlineMax:    a.inlineMax,
			yes:          true, // batch confirm covers this
			noCheckpoint: a.noCheckpoint,
			shareRooms:   a.shareRooms,
		})
		if rcA != 0 {
			failCount++
			fmt.Fprintf(stderr, "    admit failed (rc=%d)\n", rcA)
			continue
		}
		if e.Level != "" {
			rcT := runPublishAttest(stdout, stderr, publishAttestArgs{
				name:         e.Name,
				version:      e.Version,
				level:        e.Level,
				rationale:    e.Rationale,
				identity:     a.identity,
				keyPath:      a.keyPath,
				er1Target:    a.er1Target,
				er1Context:   a.er1Context,
				yes:          true,
				noCheckpoint: a.noCheckpoint,
				shareRooms:   a.shareRooms,
			})
			if rcT != 0 {
				failCount++
				fmt.Fprintf(stderr, "    attest failed (rc=%d)\n", rcT)
				continue
			}
		}
		okCount++
	}
	fmt.Fprintf(stdout, "\n==> batch done: ok=%d fail=%d total=%d\n", okCount, failCount, len(entries))
	if failCount > 0 {
		return 1
	}
	return 0
}

// ─── Auto-checkpoint (P1.5) ───────────────────────────────────────────────

// maybeCheckpoint appends a checkpoint child item to the open SPEC-0213
// session, if any. Silently skips when --no-checkpoint is set or no session
// is detected. Detection: CLAUDE_SESSION_ID env var (set by the harness for
// every hook payload; also set by `skillctl session open --export` flows).
//
// We deliberately do NOT search ER1 for an open session-state item — the env
// var is the authoritative "session is open here, right now" signal; searching
// ER1 would introduce ambiguity (multiple open sessions across hosts).
func maybeCheckpoint(stdout io.Writer, noCheckpoint bool, er1Target, er1Context, note string) {
	if noCheckpoint {
		return
	}
	sid := os.Getenv("CLAUDE_SESSION_ID")
	if sid == "" {
		return // no open session → silently skip
	}
	res, err := sessionCheckpoint(sid, er1Target, er1Context, note)
	if err != nil {
		fmt.Fprintf(stdout, "    (checkpoint skipped: %v)\n", err)
		return
	}
	if res != nil && res.DocID != "" {
		fmt.Fprintf(stdout, "    (checkpoint appended: doc=%s)\n", res.DocID)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func ensureBundle(a publishAdmitArgs, stderr io.Writer) (string, string, error) {
	if a.bundlePath != "" {
		// Reuse a pre-built .skb. Infer version from filename if not given.
		v := a.version
		if v == "" {
			v = versionFromBundleFilename(a.bundlePath)
		}
		return a.bundlePath, v, nil
	}
	dir := a.skillDir
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".claude", "skills", a.name)
	}
	if _, err := os.Stat(dir); err != nil {
		return "", "", fmt.Errorf("skill dir not found: %s (try --skill-dir)", dir)
	}
	v := a.version
	if v == "" {
		v = "0.0.0"
	}
	out := filepath.Join(".", a.name+"@"+v+".skb")
	if _, err := skillbundle.Pack(dir, out, skillbundle.PackOptions{}); err != nil {
		return "", "", fmt.Errorf("pack %s: %w", dir, err)
	}
	fmt.Fprintf(stderr, "    packed: %s\n", out)
	return out, v, nil
}

func resolveER1Config(target string) (*er1.Config, error) {
	base, verify := er1Endpoint(target)
	cfg := er1.LoadConfig()
	cfg.APIURL = base + "/upload_2"
	cfg.VerifySSL = verify
	// SPEC-0225 P5 fix: er1.LoadConfig hard-defaults ContextID to the user's
	// personal context (ER1_CONTEXT_ID env). The publish path must POST into
	// the registry's own ER1 context (the `--er1-context` flag value the
	// caller already passed in). We surface this by clearing the LoadConfig
	// default; runPublishAdmit / runPublishAttest / runPublishRevoke then set
	// cfg.ContextID explicitly to the resolved registry context just before
	// the POST.
	cfg.ContextID = ""
	if cfg.APIKey == "" {
		cfg.APIKey = resolveAPIKeyFromKeychain()
	}
	if cfg.APIKey == "" && os.Getenv("ER1_DEVICE_TOKEN") == "" {
		return nil, fmt.Errorf("no ER1 credential — set ER1_API_KEY or add the `aims-core-er1` Keychain item (ADR-0003)")
	}
	return cfg, nil
}

// er1Endpoint mirrors pkg/session.ER1Endpoint without taking a dependency on
// that package. (Same matrix; if it drifts, sync explicitly.)
func er1Endpoint(target string) (string, bool) {
	switch strings.ToLower(target) {
	case "prod":
		return "https://onboarding.guide", true
	case "local":
		return "https://127.0.0.1:8081", false
	}
	if strings.HasPrefix(target, "http") {
		return strings.TrimRight(target, "/"), !strings.Contains(target, "127.0.0.1") && !strings.Contains(target, "localhost")
	}
	if u := os.Getenv("ER1_API_URL"); u != "" {
		base := strings.TrimRight(strings.TrimSuffix(u, "/upload_2"), "/")
		verify := os.Getenv("ER1_VERIFY_SSL") != "false"
		// SEC-M7: only honour ER1_VERIFY_SSL=false for a loopback host; force
		// verification ON for any remote host so a stage/unknown target cannot
		// silently disable TLS on a public endpoint.
		if !verify && !strings.Contains(base, "127.0.0.1") && !strings.Contains(base, "localhost") {
			verify = true
		}
		return base, verify
	}
	return "https://onboarding.guide", true
}

func resolveAPIKeyFromKeychain() string {
	if k := os.Getenv("ER1_API_KEY"); k != "" {
		return k
	}
	u, _ := user.Current()
	uname := "kamir"
	if u != nil && u.Username != "" {
		uname = u.Username
	}
	out, err := exec.Command("security", "find-generic-password", "-s", "aims-core-er1", "-a", uname, "-w").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func defaultSelfKeyPath() string {
	if v := os.Getenv("SIGNING_KEY_LOCATION"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "m3c", "skill-registry-self.key")
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envOrInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		var n int
		_, err := fmt.Sscanf(v, "%d", &n)
		if err == nil {
			return n
		}
	}
	return fallback
}

func splitNameVersion(s string) (name, version string) {
	if i := strings.Index(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func versionFromBundleFilename(p string) string {
	base := strings.TrimSuffix(filepath.Base(p), ".skb")
	if i := strings.LastIndex(base, "@"); i > 0 {
		return base[i+1:]
	}
	return ""
}

func sha256Hex(b []byte) (string, [sha256.Size]byte) {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), d
}

func pubkeyFingerprint(pub ed25519.PublicKey) string {
	d := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(d[:])
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func shortHostname() string {
	if h, err := os.Hostname(); err == nil {
		if i := strings.IndexByte(h, '.'); i > 0 {
			return h[:i]
		}
		return h
	}
	return "unknown"
}

func chooseTransport(size, max int) string {
	if max > 0 && size > max {
		return "er1-claimcheck"
	}
	return "er1-inline"
}

func promptYesNo(stdout io.Writer, prompt string) bool {
	fmt.Fprint(stdout, prompt)
	var ans string
	if _, err := fmt.Fscanln(os.Stdin, &ans); err != nil {
		return false
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

// reorderFlagArgs walks `args` and returns a permutation that puts every
// flag (with its value, if it takes one) first, followed by the positionals.
// This works around Go stdlib flag.Parse() stopping at the first non-flag
// arg — a problem when a user writes e.g. `skillctl publish pdf --dry-run`
// (the `--dry-run` gets silently dropped). The reordering is conservative:
// only tokens that match a flag in `fs` are treated as flags; unknown
// `-foo` tokens fall through as positionals so Parse can report them.
func reorderFlagArgs(fs *flag.FlagSet, args []string) []string {
	var flagToks, positional []string
	i := 0
	for i < len(args) {
		t := args[i]
		// Stop at "--": everything after is positional (standard Go convention).
		if t == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(t) > 1 && t[0] == '-' {
			// Strip leading dashes and any =value suffix to look up the flag.
			name := strings.TrimLeft(t, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
			if fl := fs.Lookup(name); fl != nil {
				flagToks = append(flagToks, t)
				// Bool flags don't consume the next arg; string/int/etc do
				// (unless we already used the "=value" form).
				if !strings.Contains(t, "=") && !isBoolFlag(fl) && i+1 < len(args) {
					flagToks = append(flagToks, args[i+1])
					i += 2
					continue
				}
				i++
				continue
			}
			// Unknown flag — let fs.Parse error on it; leave in place.
			flagToks = append(flagToks, t)
			i++
			continue
		}
		positional = append(positional, t)
		i++
	}
	return append(flagToks, positional...)
}

// isBoolFlag reports whether a flag is a bool (consumes no arg). The
// FlagSet doesn't expose this directly; we detect via the Getter interface
// the bool flag implements.
func isBoolFlag(fl *flag.Flag) bool {
	type boolFlag interface{ IsBoolFlag() bool }
	if bf, ok := fl.Value.(boolFlag); ok {
		return bf.IsBoolFlag()
	}
	return false
}

// reference-the-imports-we-need to keep linters happy across partial builds.
var _ = http.MethodGet
var _ = url.Values{}
