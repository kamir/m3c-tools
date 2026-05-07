// Package awareness implements the SPEC-0195 admission bridge: take a
// scanner inventory, build a signed admission envelope, POST it to
// aims-core's /api/skills/admit-from-scan endpoint, and (optionally) run
// a bulk default-attestation pass.
//
// This package is the Go productization of the standalone Python script
// `aims-core/tools/skill_awareness/run.py`. The wire contract is fixed by
// SPEC-0195 §5.1 (request shape) and §5.2 (response shape). The CLI surface
// (`skillctl awareness sync` / `skillctl awareness verify`) lives one layer
// up in `cmd/skillctl/awareness_cmds.go`; this package owns the data shapes,
// envelope construction, and HTTP plumbing.
//
// Subpackage layout:
//
//	awareness.go  — Sync(), Verify(), public types + the orchestration loop.
//	envelope.go   — BuildEnvelope() + the SPEC-0196 §3.3 client-side
//	                intent / data_dependencies cross-rule that mirrors
//	                what the registry will (also) enforce.
//	client.go     — HTTP wrapper around POST /admit-from-scan,
//	                POST /admit-from-scan/attest, GET /admit-from-scan?session=.
//
// What this package is NOT:
//   - Not a verifier. The registry decides whether to admit; we just send
//     and surface the response.
//   - Not a scanner. The caller passes a model.Inventory; if they want it
//     fresh, they re-scan first.
//   - Not a key generator. The author key is loaded from disk via
//     `pkg/skillctl/signing` (SPEC-0188 author-key file format).
package awareness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// EnvelopeVersion is the wire-contract version we currently emit.
// Kept as a constant so envelope drift is a deliberate change, not a
// silent caller mismatch.
const EnvelopeVersion = "awareness/v1"

// DevSeedSentinel is the synthetic client_identity used when the user
// has SKILLCTL_DEV_SEED set instead of a real authoring key. SPEC-0195
// §6.1 (G-21 closure 2026-05-06) refuses this identity against any
// registry whose trust-roots `_environment` is `prod`.
//
// The exact spelling is shared with the SKILLOR-WORK/s1 standalone
// script — `id:dev-skill-awareness@m3c` — so envelopes built by the Go
// path and the Python path are interchangeable for backstops/comparison.
const DevSeedSentinel = "id:dev-skill-awareness@m3c"

// EnvProdEnvironment is the canonical value for trust-roots
// `_environment` that triggers the dev-seed short-circuit refusal.
// Spelled out as a constant so a future "production" alias would land
// here once and propagate everywhere.
const EnvProdEnvironment = "prod"

// DefaultRegistryEnv is the env var consulted as the third precedence
// step for registry resolution (after the flag and the trust-roots
// `default_registry`). SPEC-0195 §4 + S2-QUESTIONS S2.1 lock-in.
const DefaultRegistryEnv = "M3C_REGISTRY_URL"

// DevSeedEnv toggles the dev-seed authoring identity path. When set
// (any non-empty value) the envelope's client_identity becomes
// DevSeedSentinel rather than reading ~/.claude/skillctl-keys/author.key.
// Mirrors the Python script's seeded-key behaviour.
const DevSeedEnv = "SKILLCTL_DEV_SEED"

// AttestLevel is the governance verdict the bulk-attestation pass will
// stamp. Closed set: only "yellow" and "green" are meaningful for
// default-attest (red would be a refusal, expressed by AttestNone).
type AttestLevel string

const (
	AttestNone   AttestLevel = "none"   // do not call the attest endpoint
	AttestYellow AttestLevel = "yellow" // SPEC-0130 yellow default
	AttestGreen  AttestLevel = "green"  // SPEC-0130 green default
)

// IsCallable reports whether this AttestLevel actually triggers a
// /admit-from-scan/attest call. AttestNone does not.
func (l AttestLevel) IsCallable() bool {
	return l == AttestYellow || l == AttestGreen
}

// SkillEntry is one row in the SPEC-0195 §5.1 request envelope's
// `skills[]` array. Field names match the wire JSON exactly — any
// rename here is a wire-contract break and should be reflected in
// SPEC-0195 in the same change.
type SkillEntry struct {
	Name              string                 `json:"name"`
	Version           string                 `json:"version,omitempty"`
	Tier              string                 `json:"tier,omitempty"`
	SkillMDSHA256     string                 `json:"skill_md_sha256"`
	Frontmatter       map[string]interface{} `json:"frontmatter,omitempty"`
	SourcePath        string                 `json:"source_path,omitempty"`
	ClientSignatureB64 string                `json:"client_signature_b64,omitempty"`
	// Intent / data_dependencies are SPEC-0196 §3 fields. We mirror them
	// verbatim from the frontmatter so the registry can run its
	// SPEC-0196 §3.3 cross-rule check; see envelope.go for the
	// client-side mirror that also enforces them locally when
	// --require-intent is set.
	Intent          map[string]interface{}   `json:"intent,omitempty"`
	DataDependencies []map[string]interface{} `json:"data_dependencies,omitempty"`
}

// SyncEnvelope is the body POSTed to /api/skills/admit-from-scan. It
// matches SPEC-0195 §5.1 verbatim. Field order in the JSON output is
// stable because Go's encoding/json walks struct fields in declaration
// order; tests assert this order to make the envelope-equivalence
// acceptance check (#6) trivial to express.
type SyncEnvelope struct {
	SessionTag             string       `json:"session_tag"`
	ClientIdentity         string       `json:"client_identity"`
	ClientPubkeyFingerprint string      `json:"client_pubkey_fingerprint"`
	Skills                 []SkillEntry `json:"skills"`
	// EnvelopeVersion is sent for forward-compat; the server may reject
	// envelopes whose version it doesn't speak. v1 is the only value as
	// of 2026-05-06.
	EnvelopeVersion string `json:"envelope_version,omitempty"`
}

// AttestEnvelope is the body POSTed to /api/skills/admit-from-scan/attest.
// Matches SPEC-0195 §5.4 verbatim.
type AttestEnvelope struct {
	SessionTag      string `json:"session_tag"`
	GovernanceLevel string `json:"governance_level"`
	Rationale       string `json:"rationale,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

// AdmittedRow / SkippedRow / SyncSummary mirror SPEC-0195 §5.2.
type AdmittedRow struct {
	Name        string `json:"name"`
	LocalDigest string `json:"local_digest"`
	Status      string `json:"status"`
}

type SkippedRow struct {
	Name       string `json:"name"`
	Reason     string `json:"reason"`
	FailedRule string `json:"failed_rule,omitempty"`
}

type SyncSummary struct {
	Received int            `json:"received"`
	Admitted int            `json:"admitted"`
	Skipped  int            `json:"skipped"`
	ByTier   map[string]int `json:"by_tier,omitempty"`
}

type SyncResponse struct {
	SessionTag string        `json:"session_tag"`
	Admitted   []AdmittedRow `json:"admitted"`
	Skipped    []SkippedRow  `json:"skipped"`
	Summary    SyncSummary   `json:"summary"`
}

// Opts is the input bundle for Sync(). The three "what to send" inputs
// (Inventory, AuthorIdentity, AuthorSigner) are required; everything else
// has a sensible default.
type Opts struct {
	// Inventory is the scanner output to admit. Must be non-nil.
	Inventory *model.Inventory

	// RegistryURL is the registry root, e.g. https://aims.example.com/api/skills.
	// Resolution is the caller's job (see ResolveRegistry); by the time
	// Opts reaches Sync(), this MUST be set.
	RegistryURL string

	// TrustRoots is the loaded ~/.claude/skill-trust-roots.yaml. Used
	// only for the §6.1 dev-seed-against-prod short-circuit. May be nil
	// in tests; the short-circuit then degrades to "no environment
	// information, allow the server to be the sole gate".
	TrustRoots *verify.TrustRoots

	// SessionTag is the per-session tag stamped on every admission doc.
	// Default (when empty): "skill-awareness/<hostname>/<YYYY-MM-DD>"
	// per SPEC-0195 §4 + S2-QUESTIONS S2.3 lock-in.
	SessionTag string

	// AuthorIdentity is the canonical client_identity string sent in the
	// envelope. For the dev-seed path, set this to DevSeedSentinel.
	AuthorIdentity string

	// AuthorPubkeyFingerprint is the "sha256:<hex>" fingerprint of the
	// raw 32-byte ed25519 public key (matching the s1 Python script's
	// _pubkey_fingerprint shape).
	AuthorPubkeyFingerprint string

	// AuthorSigner signs the local_digest message ("sha256:<hex>" as
	// ASCII bytes) and returns the base64-encoded raw signature. The
	// CLI wires this to pkg/skillctl/signing.LoadPrivateKey + ed25519.Sign;
	// tests pass a deterministic stub.
	AuthorSigner func(message []byte) (string, error)

	// DefaultAttest, if not AttestNone, triggers a follow-on POST to
	// /admit-from-scan/attest with this governance level.
	DefaultAttest AttestLevel

	// AttestRationale is forwarded verbatim to the attest envelope.
	// Default: "skill-awareness default attestation".
	AttestRationale string

	// AttestScope, if non-empty, narrows the attest pass (e.g.
	// "tier:user"). Empty means "all".
	AttestScope string

	// RequireIntent makes Sync() refuse to send any skill whose
	// frontmatter carries no `intent` block or whose
	// `intent.side_effects` is the SPEC-0196 §7 sentinel ["UNKNOWN"].
	// SPEC-0195 §5.3 step 1.5 + S2-QUESTIONS S2.1 acceptance test #5.
	RequireIntent bool

	// DefaultIntentLevel, if non-empty, stamps the chosen
	// `governance_level` onto every skill whose frontmatter is missing
	// it OR whose `intent.side_effects` is the UNKNOWN sentinel. It
	// does NOT replace explicit non-sentinel intent — it only fills
	// gaps. SPEC-0195 §5.3 step 1.5 + S2-QUESTIONS S2.1 acceptance #6.
	//
	// Closed set: "" | "yellow" | "green". An invalid value is rejected
	// by validateOpts before any HTTP call.
	DefaultIntentLevel string

	// Stdout / Stderr are I/O sinks for the dry-run envelope dump and
	// per-skill push-event log lines. Defaults: os.Stdout / os.Stderr.
	Stdout io.Writer
	Stderr io.Writer

	// HTTPClient is injected for tests; nil means "use the default
	// 30s-timeout client built by registry.New".
	HTTPClient HTTPDoer

	// DryRun, when true, builds the envelope but does NOT issue any
	// HTTP request. The envelope is dumped (one JSON line per skill +
	// the wrapping envelope) to Stdout. Returns a SyncResult with
	// Summary.Received populated and Admitted/Skipped/Summary empty.
	DryRun bool

	// Confirm gates non-dry-run pushes. SPEC-0195 §4: dry-run is the
	// default; the user must opt in to actually POST. The CLI maps
	// `--confirm` to true; if neither --dry-run nor --confirm is set,
	// Sync() defaults to dry-run (matching the spec's safer-by-default
	// posture).
	Confirm bool

	// Now is the clock used for default-session-tag generation. Default:
	// time.Now. Tests pin this for deterministic tags.
	Now func() time.Time

	// Hostname is the hostname used for default-session-tag generation.
	// Default: os.Hostname().
	Hostname func() (string, error)

	// Ctx is the context.Context used for HTTP calls. Default:
	// context.Background().
	Ctx context.Context
}

// SyncResult is what Sync() returns. It carries enough information for
// the CLI to print a summary and decide on its exit code.
type SyncResult struct {
	// Envelope is the request body that was (or would have been) sent.
	// Always populated, even on dry-run.
	Envelope SyncEnvelope

	// Response is the parsed server response. Nil on dry-run; nil on
	// network error (Sync returns the error directly).
	Response *SyncResponse

	// Attestation, when non-nil, carries the attest endpoint's response
	// (currently a thin {"attested": N, "session_tag": ...} shape; we
	// store it as raw JSON for forward-compat).
	Attestation *AttestResponse

	// LocalSkippedReasons records skills the CLIENT refused to send
	// (e.g. --require-intent + UNKNOWN sentinel). Distinct from the
	// server's Skipped list so the operator can see exactly where the
	// gate fired.
	LocalSkippedReasons []SkippedRow
}

// AttestResponse is the parsed body of POST /admit-from-scan/attest.
// Field names per SPEC-0195 §5.4; a generic Extra map captures
// forward-compat fields we don't yet decode.
type AttestResponse struct {
	SessionTag string                 `json:"session_tag"`
	Attested   int                    `json:"attested"`
	Extra      map[string]interface{} `json:"-"`
}

// errDevSeedAgainstProd is the §6.1 client-side short-circuit error.
// Exposed as a sentinel so the CLI / tests can branch on it.
var errDevSeedAgainstProd = errors.New(
	"awareness: dev-seed identity not allowed against prod registry " +
		"(SPEC-0195 §6.1); set a real ~/.claude/skillctl-keys/author.key " +
		"or point at a non-prod registry")

// ErrDevSeedAgainstProd returns the §6.1 short-circuit sentinel.
// Callers should `errors.Is(err, ErrDevSeedAgainstProd())` to detect it.
func ErrDevSeedAgainstProd() error { return errDevSeedAgainstProd }

// Sync implements `skillctl awareness sync`.
//
// Steps:
//
//  1. validateOpts — refuse obvious caller bugs (missing inventory,
//     missing registry URL, missing identity, etc.) BEFORE any I/O.
//  2. resolveSession — fill in the default session_tag from
//     hostname + today's date if not set.
//  3. buildEnvelope — convert the inventory into a SyncEnvelope, apply
//     --require-intent / --default-intent gates, sign each digest.
//  4. shortCircuitIfDevSeedProd — §6.1 client-side gate.
//  5. dumpDryRun OR doSync — emit the envelope to stdout (dry-run) OR
//     POST to the registry and decode the response.
//  6. doAttest — if DefaultAttest != AttestNone AND the sync succeeded
//     AND not in dry-run, POST to /admit-from-scan/attest.
//
// The function returns the SyncResult on every successful path (including
// dry-run); errors are returned without a partial result so the CLI's
// exit-code mapping stays unambiguous.
func Sync(opts Opts) (*SyncResult, error) {
	opts = applyOptDefaults(opts)
	if err := validateOpts(opts); err != nil {
		return nil, err
	}

	tag, err := resolveSessionTag(opts)
	if err != nil {
		return nil, err
	}
	opts.SessionTag = tag

	env, localSkipped, err := BuildEnvelope(opts)
	if err != nil {
		return nil, err
	}

	// §6.1 client-side short-circuit. Server is still the authoritative
	// gate; this just prevents the obviously-wrong request from leaving
	// the box at all.
	if err := shortCircuitIfDevSeedProd(env, opts.TrustRoots); err != nil {
		return nil, err
	}

	res := &SyncResult{
		Envelope:            env,
		LocalSkippedReasons: localSkipped,
	}

	// Dry-run path: emit the envelope, don't talk to the network.
	if opts.DryRun || !opts.Confirm {
		if err := dumpDryRun(opts.Stdout, env); err != nil {
			return nil, err
		}
		return res, nil
	}

	// Live path.
	syncResp, err := postSync(opts, env)
	if err != nil {
		return nil, err
	}
	res.Response = syncResp

	// Optional default-attestation pass. Only fires on non-dry-run AND
	// when the user explicitly asked for it. Failure is non-fatal — the
	// admission has already happened — but surfaces as a return error
	// so the CLI's exit code reflects "not entirely clean".
	if opts.DefaultAttest.IsCallable() {
		atResp, atErr := postAttest(opts, opts.SessionTag)
		res.Attestation = atResp
		if atErr != nil {
			return res, fmt.Errorf("awareness: attest pass failed (admission succeeded): %w", atErr)
		}
	}
	return res, nil
}

// VerifyOpts is the input bundle for Verify().
type VerifyOpts struct {
	RegistryURL string
	SessionTag  string
	HTTPClient  HTTPDoer
	Stdout      io.Writer
	Ctx         context.Context
}

// VerifyResponse is the parsed shape of GET /admit-from-scan?session=<tag>.
type VerifyResponse struct {
	SessionTag string        `json:"session_tag"`
	Admitted   []AdmittedRow `json:"admitted"`
	Summary    SyncSummary   `json:"summary"`
}

// Verify implements `skillctl awareness verify`. It fetches the per-session
// admission record from the registry and prints a one-line-per-skill
// summary plus the by-tier histogram. Returns the parsed response so
// callers can do further inspection in tests.
//
// SPEC-0195 §4 acceptance #6 ("rerun-able"): the same session_tag should
// always return the same digests on the second call.
func Verify(opts VerifyOpts) (*VerifyResponse, error) {
	if opts.RegistryURL == "" {
		return nil, errors.New("awareness verify: --registry is required")
	}
	if opts.SessionTag == "" {
		return nil, errors.New("awareness verify: --session is required")
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Ctx == nil {
		opts.Ctx = context.Background()
	}

	resp, err := getSessionAdmissions(opts)
	if err != nil {
		return nil, err
	}

	// One-line summary per the SPEC-0195 demo flow. Stable column widths
	// keep the output diffable across runs.
	fmt.Fprintf(opts.Stdout, "session: %s\n", resp.SessionTag)
	fmt.Fprintf(opts.Stdout, "admitted: %d\n", resp.Summary.Admitted)
	for _, row := range resp.Admitted {
		fmt.Fprintf(opts.Stdout, "  %-30s  %s\n", row.Name, row.LocalDigest)
	}
	if len(resp.Summary.ByTier) > 0 {
		fmt.Fprintln(opts.Stdout, "by tier:")
		// Stable order: sort by tier name. A tiny ordering helper in
		// envelope.go keeps the dependency surface narrow.
		for _, k := range sortedTierKeys(resp.Summary.ByTier) {
			fmt.Fprintf(opts.Stdout, "  %-8s  %d\n", k, resp.Summary.ByTier[k])
		}
	}
	return resp, nil
}

// ResolveRegistry implements the SPEC-0195 §4 / S2-QUESTIONS S2.1 lookup:
//
//	flag → trust-roots.default_registry → $M3C_REGISTRY_URL → error
//
// Exposed as a public helper so the CLI and the SPEC-0189 §13
// `--push-to-registry` shorthand share one resolution path.
func ResolveRegistry(flag string, trustRoots *verify.TrustRoots) (string, error) {
	flag = strings.TrimSpace(flag)
	if flag != "" {
		return flag, nil
	}
	if trustRoots != nil {
		if v := strings.TrimSpace(trustRoots.DefaultRegistry); v != "" {
			return v, nil
		}
	}
	if v := strings.TrimSpace(os.Getenv(DefaultRegistryEnv)); v != "" {
		return v, nil
	}
	return "", errors.New(
		"awareness: registry URL not set; pass --registry, set " +
			"`default_registry:` in ~/.claude/skill-trust-roots.yaml, " +
			"or export " + DefaultRegistryEnv)
}

// applyOptDefaults fills in nil-able fields. Pulled out of Sync so
// validateOpts can inspect the post-default-fill shape.
func applyOptDefaults(o Opts) Opts {
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Hostname == nil {
		o.Hostname = os.Hostname
	}
	if o.Ctx == nil {
		o.Ctx = context.Background()
	}
	if o.DefaultAttest == "" {
		o.DefaultAttest = AttestNone
	}
	if o.AttestRationale == "" {
		o.AttestRationale = "skill-awareness default attestation"
	}
	return o
}

// validateOpts refuses obviously-broken Opts. Runs BEFORE any I/O so a
// caller misuse never leaks a half-constructed envelope.
func validateOpts(o Opts) error {
	if o.Inventory == nil {
		return errors.New("awareness: Opts.Inventory is required")
	}
	if o.RegistryURL == "" {
		return errors.New("awareness: Opts.RegistryURL is required")
	}
	if o.AuthorIdentity == "" {
		return errors.New("awareness: Opts.AuthorIdentity is required")
	}
	if o.AuthorPubkeyFingerprint == "" {
		return errors.New("awareness: Opts.AuthorPubkeyFingerprint is required")
	}
	if o.AuthorSigner == nil {
		return errors.New("awareness: Opts.AuthorSigner is required")
	}
	switch o.DefaultAttest {
	case AttestNone, AttestYellow, AttestGreen:
		// ok
	default:
		return fmt.Errorf("awareness: invalid DefaultAttest %q (want none|yellow|green)", o.DefaultAttest)
	}
	switch o.DefaultIntentLevel {
	case "", "yellow", "green":
		// ok
	default:
		return fmt.Errorf("awareness: invalid DefaultIntentLevel %q (want \"\"|yellow|green)", o.DefaultIntentLevel)
	}
	return nil
}

// resolveSessionTag fills the default per SPEC-0195 §4: the spec's
// default is `skill-awareness/<hostname>/<YYYY-MM-DD>` and S2-QUESTIONS
// S2.3 confirms that's unchanged. The format is intentionally stable
// (no nano-second precision) so same-day re-runs hit the SAME tag and
// the §7 idempotency upsert kicks in.
func resolveSessionTag(o Opts) (string, error) {
	if v := strings.TrimSpace(o.SessionTag); v != "" {
		return v, nil
	}
	host, err := o.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	// Trim domain suffix if Hostname returned a FQDN; keeps tags short.
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	date := o.Now().UTC().Format("2006-01-02")
	return fmt.Sprintf("skill-awareness/%s/%s", host, date), nil
}

// shortCircuitIfDevSeedProd implements SPEC-0195 §6.1.
//
// Decision matrix:
//
//	envelope.client_identity == DevSeedSentinel  AND  trust_roots._environment == "prod"
//	    → refuse, errDevSeedAgainstProd
//	envelope.client_identity != DevSeedSentinel
//	    → permit (we only gate the dev-seed identity)
//	trust_roots == nil OR trust_roots._environment != "prod"
//	    → permit (no trust-roots = no signal; non-prod = explicitly allowed)
//
// The SKILLCTL_DEV_SEED env var is consulted indirectly: BuildEnvelope sets
// `client_identity = DevSeedSentinel` when SKILLCTL_DEV_SEED is exported.
// This function only inspects the resulting envelope, so a caller that
// constructs an envelope manually with `DevSeedSentinel` as identity hits
// the same gate. Defense in depth.
func shortCircuitIfDevSeedProd(env SyncEnvelope, tr *verify.TrustRoots) error {
	if env.ClientIdentity != DevSeedSentinel {
		return nil
	}
	if tr == nil {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(tr.Environment)) != EnvProdEnvironment {
		return nil
	}
	return errDevSeedAgainstProd
}

// dumpDryRun emits the envelope on stdout: a one-line-per-skill JSON
// dump (per SPEC-0189 §13.4 acceptance #7) followed by the wrapping
// envelope as a final line. The CLI tee's this for inspection.
func dumpDryRun(w io.Writer, env SyncEnvelope) error {
	for _, sk := range env.Skills {
		if err := writeJSONLine(w, sk); err != nil {
			return fmt.Errorf("awareness: dump skill %q: %w", sk.Name, err)
		}
	}
	if err := writeJSONLine(w, env); err != nil {
		return fmt.Errorf("awareness: dump envelope: %w", err)
	}
	return nil
}
