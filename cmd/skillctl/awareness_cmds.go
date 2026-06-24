// SPEC-0195 / Sprint 2 Stream M1: `skillctl awareness sync` and
// `skillctl awareness verify` runners. Mirrors the existing S1 / S7 / S8
// pattern: pure runner functions taking args + io.Writers and returning
// numeric exit codes.
//
// Design pulled out of cmd/skillctl/main.go's dispatcher into this file so
// the dispatcher stays a one-liner-per-case switch and the SPEC-0195 logic
// is reviewable in one place.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/awareness"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// runAwareness is the dispatcher for `skillctl awareness <sub>`. Splits
// off `sync` / `verify` because each has its own flag set.
func runAwareness(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		printAwarenessUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "sync":
		return runAwarenessSync(args[1:], stdout, stderr)
	case "verify":
		return runAwarenessVerify(args[1:], stdout, stderr)
	case "reset":
		return runAwarenessReset(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printAwarenessUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "skillctl awareness: unknown subcommand %q\n", args[0])
		printAwarenessUsage(stderr)
		return exitUsage
	}
}

func printAwarenessUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl awareness <sub> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  sync     Admit local skills to a registry (SPEC-0195 §5.1).")
	fmt.Fprintln(w, "  verify   Read back per-session admissions (SPEC-0195 §4).")
	fmt.Fprintln(w, "  reset    Delete admit-from-scan docs scoped to a session_tag (G-23 two-step).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run any subcommand with --help for its flags.")
}

// runAwarenessSync implements `skillctl awareness sync`. Builds a
// scanner inventory (or reads --inventory), constructs the SPEC-0195 §5.1
// envelope, and POSTs to /admit-from-scan. Default mode is dry-run; the
// user must pass --confirm to actually write.
func runAwarenessSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("awareness sync", flag.ContinueOnError)
	fs.SetOutput(stderr)

	source := fs.String("source", "claude", "Scan source: claude | user | plugins | all (ignored if --inventory is set).")
	inventory := fs.String("inventory", "", "Read scan JSON from FILE; pass `-` to read from stdin.")
	registryURL := fs.String("registry", "", "Registry URL (overrides trust-roots default_registry and $M3C_REGISTRY_URL).")
	defaultAttestStr := fs.String("default-attest", "none", "After admission, request a default attestation: yellow | green | none.")
	defaultIntentStr := fs.String("default-intent", "", "Stamp this governance level on entries with no/UNKNOWN intent: yellow | green (empty = off).")
	requireIntent := fs.Bool("require-intent", false, "Refuse to send entries with no intent or the SPEC-0196 UNKNOWN sentinel.")
	sessionTag := fs.String("session", "", "Session tag (default: skill-awareness/<host>/<YYYY-MM-DD>).")
	dryRun := fs.Bool("dry-run", false, "Build envelope; do not POST.")
	confirm := fs.Bool("confirm", false, "Required to actually push to the registry (defense against accidental writes).")
	keyPath := fs.String("key", "", "Author key path (PEM PKCS#8). Default: ~/.claude/skillctl-keys/author.key.")
	authorIdentity := fs.String("author-identity", "", "Override the author identity. Default: id:<user>@m3c (or DevSeedSentinel when SKILLCTL_DEV_SEED is set).")
	helpAdvanced := fs.Bool("help-advanced", false, "Print advanced flags (e.g. --allow-overwrite footgun-resistance).")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl awareness sync [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Admit local skills to a registry by scanning (or reading a saved scan).")
		fmt.Fprintln(stderr, "Default mode is dry-run; pass --confirm to actually POST.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Registry resolution: --registry > trust-roots default_registry > $M3C_REGISTRY_URL.")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *helpAdvanced {
		fmt.Fprintln(stderr, "Advanced flags (footgun-resistance, kept off the main help):")
		fmt.Fprintln(stderr, "  --allow-overwrite   Allow re-admitting a digest under a different identity.")
		fmt.Fprintln(stderr, "                      Default: off (same-session re-runs are additive only).")
		return exitOK
	}

	attestLevel, err := parseAttestLevel(*defaultAttestStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	// Source the inventory: --inventory file, --inventory -, or live scan.
	inv, err := loadAwarenessInventory(*inventory, *source)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Trust-roots load (best-effort; tolerates missing file for the
	// dev-seed dry-run path).
	trustRoots, _ := loadTrustRootsBestEffort()

	// Resolve registry URL with the SPEC-0195 §4 / S2.1 precedence.
	resolvedRegistry, err := awareness.ResolveRegistry(*registryURL, trustRoots)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Build the signer + identity. SKILLCTL_DEV_SEED takes precedence
	// over an on-disk author key when set; this mirrors the SKILLOR-WORK/s1
	// procedure and lets the CI / demo path run without a real key.
	signer, identity, fingerprint, err := resolveAuthor(*keyPath, *authorIdentity)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Default mode: dry-run when neither --confirm nor explicit --dry-run
	// is set. Mirrors SPEC-0195's safer-by-default posture.
	effectiveDryRun := *dryRun || !*confirm

	res, err := awareness.Sync(awareness.Opts{
		Inventory:               inv,
		RegistryURL:             resolvedRegistry,
		TrustRoots:              trustRoots,
		SessionTag:              *sessionTag,
		AuthorIdentity:          identity,
		AuthorPubkeyFingerprint: fingerprint,
		AuthorSigner:            signer,
		DefaultAttest:           attestLevel,
		DefaultIntentLevel:      *defaultIntentStr,
		RequireIntent:           *requireIntent,
		DryRun:                  effectiveDryRun,
		Confirm:                 *confirm,
		Stdout:                  stdout,
		Stderr:                  stderr,
		Ctx:                     context.Background(),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, awareness.ErrDevSeedAgainstProd()) {
			// Distinct exit code for the §6.1 short-circuit so CI
			// can detect "tried to push dev-seed to prod" without
			// parsing strings. Map to exitUsage for now (caller
			// misuse) — a future SPEC-0195 numbered code matrix
			// would slot in here.
			return exitUsage
		}
		return exitGeneric
	}

	// Print a structured per-skill push event line on stderr (per
	// SPEC-0189 §13.2: "push events logged to stderr in a structured
	// form, one line per skill").
	printSyncSummary(stderr, res)
	return exitOK
}

// runAwarenessVerify implements `skillctl awareness verify`. Calls the
// registry's GET /admit-from-scan?session=<tag> path and prints a
// summary.
func runAwarenessVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("awareness verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registryURL := fs.String("registry", "", "Registry URL (overrides trust-roots default_registry and $M3C_REGISTRY_URL).")
	sessionTag := fs.String("session", "", "Session tag to verify (default: skill-awareness/<host>/<YYYY-MM-DD>).")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl awareness verify [--session TAG] [--registry URL]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	trustRoots, _ := loadTrustRootsBestEffort()
	resolvedRegistry, err := awareness.ResolveRegistry(*registryURL, trustRoots)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	tag := strings.TrimSpace(*sessionTag)
	if tag == "" {
		tag = defaultSessionTag()
	}

	_, err = awareness.Verify(awareness.VerifyOpts{
		RegistryURL: resolvedRegistry,
		SessionTag:  tag,
		Stdout:      stdout,
		Ctx:         context.Background(),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	return exitOK
}

// loadAwarenessInventory resolves the --inventory + --source flags into
// a *model.Inventory.
//
// Precedence:
//
//	--inventory FILE  (or `-` for stdin)
//	live scan with --source
//
// If --inventory is `-`, JSON is read from os.Stdin. This is the SPEC-0195
// §4 convention and the conduit for the SPEC-0189 §13 `--push-to-registry`
// shorthand which pipes its JSON via stdin.
func loadAwarenessInventory(inventoryPath, source string) (*model.Inventory, error) {
	if inventoryPath != "" {
		if inventoryPath == "-" {
			return decodeInventoryReader(os.Stdin, "stdin")
		}
		f, err := os.Open(inventoryPath)
		if err != nil {
			return nil, fmt.Errorf("awareness sync: open %s: %w", inventoryPath, err)
		}
		defer f.Close()
		return decodeInventoryReader(f, inventoryPath)
	}

	// Live scan path. Map --source to scanner sources; default is "claude".
	src := scanner.Source(source)
	if src == "" {
		src = scanner.SourceClaude
	}
	roots := scanner.ResolveDefaults([]scanner.Source{src})
	if len(roots) == 0 {
		return nil, fmt.Errorf("awareness sync: scanner found no roots for --source %q", source)
	}
	sc := &scanner.Scanner{Roots: roots, WithTrust: false}
	inv, err := sc.Scan()
	if err != nil {
		return nil, fmt.Errorf("awareness sync: scan: %w", err)
	}
	return inv, nil
}

// decodeInventoryReader is the shared JSON-decode path. Pulled out so
// stdin and file paths share the same error wrapping.
func decodeInventoryReader(r io.Reader, srcLabel string) (*model.Inventory, error) {
	var inv model.Inventory
	dec := json.NewDecoder(r)
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("awareness sync: decode inventory from %s: %w", srcLabel, err)
	}
	return &inv, nil
}

// loadTrustRootsBestEffort returns the parsed trust-roots file, or nil
// if the file doesn't exist. Other errors (malformed YAML, etc.) are
// surfaced so the user knows their config is broken.
//
// Why best-effort: many Sprint 2 dry-run flows (and CI) don't have a
// configured trust-roots file. A missing file should NOT block
// `awareness sync --dry-run`; the §6.1 short-circuit just degrades to
// "no environment signal, server is sole gate".
func loadTrustRootsBestEffort() (*verify.TrustRoots, error) {
	path, err := verify.DefaultPath()
	if err != nil {
		return nil, err
	}
	tr, err := verify.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// resolveAuthor builds the (signer, identity, fingerprint) triple. There
// are two modes:
//
//	SKILLCTL_DEV_SEED set            → deterministic dev-seed identity.
//	on-disk author.key               → real ed25519 key from file.
//
// The CLI passes through `--key` (override path) and `--author-identity`
// (override the identity string); the latter is rarely used outside
// tests but is exposed so an operator can experiment with multiple
// identities without rotating keys.
func resolveAuthor(keyPath, identityOverride string) (signer func([]byte) (string, error), identity, fingerprint string, err error) {
	if seed := strings.TrimSpace(os.Getenv(awareness.DevSeedEnv)); seed != "" {
		return resolveDevSeedAuthor(seed, identityOverride)
	}
	return resolveOnDiskAuthor(keyPath, identityOverride)
}

// resolveDevSeedAuthor mirrors the SKILLOR-WORK/s1 standalone script's
// seeded-key path: SHA-256 of the seed string is used as the 32-byte
// ed25519 private key material.
func resolveDevSeedAuthor(seed, identityOverride string) (signer func([]byte) (string, error), identity, fingerprint string, err error) {
	if len(seed) == 0 {
		return nil, "", "", errors.New("awareness: SKILLCTL_DEV_SEED is empty")
	}
	material := sha256.Sum256([]byte(seed))
	priv := ed25519.NewKeyFromSeed(material[:])
	pub := priv.Public().(ed25519.PublicKey)
	rawPubHash := sha256.Sum256(pub)
	fingerprint = "sha256:" + hexBytes(rawPubHash[:])

	identity = strings.TrimSpace(identityOverride)
	if identity == "" {
		identity = awareness.DevSeedSentinel
	}

	signer = func(message []byte) (string, error) {
		sig := ed25519.Sign(priv, message)
		return base64.StdEncoding.EncodeToString(sig), nil
	}
	return signer, identity, fingerprint, nil
}

// resolveOnDiskAuthor loads the author key from disk (PEM PKCS#8) and
// builds the signer / fingerprint pair.
func resolveOnDiskAuthor(keyPath, identityOverride string) (signer func([]byte) (string, error), identity, fingerprint string, err error) {
	if keyPath == "" {
		home, hErr := os.UserHomeDir()
		if hErr != nil {
			return nil, "", "", fmt.Errorf("awareness: resolve home dir: %w", hErr)
		}
		keyPath = filepath.Join(home, ".claude", "skillctl-keys", "author.key")
	}
	priv, err := signing.LoadPrivateKey(keyPath)
	if err != nil {
		return nil, "", "", fmt.Errorf(
			"awareness: no authoring key at %s — run `skillctl keygen --out ~/.claude/skillctl-keys/author` "+
				"or set SKILLCTL_DEV_SEED for a dev keypair: %w", keyPath, err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	rawPubHash := sha256.Sum256(pub)
	fingerprint = "sha256:" + hexBytes(rawPubHash[:])

	identity = strings.TrimSpace(identityOverride)
	if identity == "" {
		// Default identity: "id:<user>@m3c". Matches the SKILLOR-WORK
		// convention; an operator can override via --author-identity.
		u, _ := os.UserHomeDir()
		identity = "id:" + filepath.Base(u) + "@m3c"
	}

	signer = func(message []byte) (string, error) {
		sig := ed25519.Sign(priv, message)
		return base64.StdEncoding.EncodeToString(sig), nil
	}
	return signer, identity, fingerprint, nil
}

// parseAttestLevel maps the CLI string into the awareness package's
// AttestLevel constant. Strict: only the closed set is accepted, no
// silent fallback to AttestNone.
func parseAttestLevel(s string) (awareness.AttestLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return awareness.AttestNone, nil
	case "yellow":
		return awareness.AttestYellow, nil
	case "green":
		return awareness.AttestGreen, nil
	default:
		return awareness.AttestNone, fmt.Errorf("awareness: invalid --default-attest %q (want yellow | green | none)", s)
	}
}

// printSyncSummary is the human-readable summary written to stderr after
// a sync completes. Emits one structured line per admitted/skipped row
// so the output is grep-friendly.
func printSyncSummary(stderr io.Writer, res *awareness.SyncResult) {
	if res == nil {
		return
	}
	if res.Response == nil {
		// Dry-run path: nothing actionable to print here; the
		// envelope dump went to stdout already.
		fmt.Fprintf(stderr, "awareness sync: dry-run; %d skill(s) in envelope, %d locally skipped\n",
			len(res.Envelope.Skills), len(res.LocalSkippedReasons))
		return
	}
	resp := res.Response
	fmt.Fprintf(stderr, "awareness sync: session=%s admitted=%d skipped=%d received=%d\n",
		resp.SessionTag, resp.Summary.Admitted, resp.Summary.Skipped, resp.Summary.Received)
	for _, row := range resp.Admitted {
		fmt.Fprintf(stderr, "  ADMIT  %-30s  %s\n", row.Name, row.LocalDigest)
		// SPEC-0278 L1: best-effort mirror of each admit into the local
		// transparency log (opt-in via M3C_TRANSLOG=1). Malformed digests
		// are skipped by the entry validator; never blocks the sync.
		bestEffortTranslogAppend(translogEventAdmit, row.LocalDigest, row.Name, stderr)
	}
	for _, row := range resp.Skipped {
		fmt.Fprintf(stderr, "  SKIP   %-30s  %s\n", row.Name, row.Reason)
	}
	for _, row := range res.LocalSkippedReasons {
		fmt.Fprintf(stderr, "  LOCAL  %-30s  %s (%s)\n", row.Name, row.Reason, row.FailedRule)
	}
	if res.Attestation != nil {
		fmt.Fprintf(stderr, "awareness sync: attested=%d at session=%s\n",
			res.Attestation.Attested, res.Attestation.SessionTag)
	}
}

// defaultSessionTag is the same default the awareness package computes
// internally; we duplicate it here so `verify` (which doesn't go through
// the Sync path) can default the same way.
func defaultSessionTag() string {
	host, _ := os.Hostname()
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	if host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("skill-awareness/%s/%s", host, time.Now().UTC().Format("2006-01-02"))
}

// hexBytes is a tiny lowercase-hex helper; encoding/hex would do, but we
// avoid the import to keep this file's import set tight.
func hexBytes(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, hex[x>>4], hex[x&0x0f])
	}
	return string(out)
}
