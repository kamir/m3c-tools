package main

// agentid_cmds.go — SPEC-0277 P0+P1 `skillctl agentid` verb surface.
//
//	agentid issue  --owner <plm-id> --owner-key <path> --for-agent <ref>
//	               --skills <set> --intents <set> [--data-scopes <set>]
//	               [--approver <id> --approver-key <path>]
//	               [--limit k=v] [--expires <date>] [--out agentid.json]
//	agentid verify --bundle agentid.json [--offline] [--trust-roots <file>]
//	               [--revocations <file>] [--json]
//	agentid show   <agentid.json>
//	agentid revoke <agent-id> --reason … [--key <path>] [--registry <url>]
//	               [--out <list.json>]
//
// `verify` deliberately MIRRORS `verify --bundle` (SPEC-0276): same exit codes
// (0 / 10–17, plus 21 for the distinct "expired" verdict), same offline +
// --revocations semantics. An AgentID is "just another signed thing" to the
// verifier — the only difference is the role it verifies (owner/approver instead
// of author/registry) and the payload it canonicalizes.
//
// The crypto + authorization live in pkg/skillctl/agentid (pure, stdlib-only).
// This file is WIRING: flag parsing, the trust-roots pinned-key adapter, file
// IO, and the exit-code translation.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/agentid"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// exitAgentIDExpired (21) — the AgentID's not_after is in the past (or its
// created_at is in the future). A DISTINCT code from a signature failure (11) so
// an operator/CI can tell "the mandate lapsed" from "the signature is wrong"
// (AC-P0). Picks 21 — the next free code after SPEC-0246's ExitSelfAttested(20).
const exitAgentIDExpired = 21

// agentIDExitCode maps an agentid verifier error to the mirror of the SPEC-0188
// §11 numeric codes, so `agentid verify` shares the exit-code surface with
// `verify --bundle`:
//
//	nil                     → 0
//	ErrOwnerSigInvalid      → 11 (owner sig failed OR owner not pinned)
//	ErrApproverFloor        → 20 (the reviewer≠author family; approver floor)
//	ErrExpired/ErrNotYetValid → 21 (DISTINCT validity-window code)
//	ErrRevoked              → 17 (the SPEC-0198 revoke theme)
//	anything else           → 1  (generic / malformed)
func agentIDExitCode(err error) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, agentid.ErrOwnerSigInvalid):
		return verify.ExitAuthorSigInvalid // 11
	case errors.Is(err, agentid.ErrApproverFloor):
		return verify.ExitSelfAttested // 20
	case errors.Is(err, agentid.ErrExpired), errors.Is(err, agentid.ErrNotYetValid):
		return exitAgentIDExpired // 21
	case errors.Is(err, agentid.ErrRevoked):
		return exitBundleRevoked // 17
	default:
		return exitGeneric // 1
	}
}

// runAgentID is main's dispatch entry point for `skillctl agentid <sub>`.
func runAgentID(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, agentIDUsage)
		return exitUsage
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "issue":
		return runAgentIDIssue(rest, stdout, stderr)
	case "verify":
		return runAgentIDVerify(rest, stdout, stderr)
	case "show":
		return runAgentIDShow(rest, stdout, stderr)
	case "revoke":
		return runAgentIDRevoke(rest, stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, agentIDUsage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "skillctl agentid: unknown subcommand %q\n\n%s\n", sub, agentIDUsage)
		return exitUsage
	}
}

const agentIDUsage = `Usage: skillctl agentid <issue|verify|show|revoke> [flags]

  issue   Build + owner-sign an AgentID mandate (SPEC-0277 §2).
          --owner <plm-id> --owner-key <path> --for-agent <ref>
          --skills a,b --intents x,y [--data-scopes s,t]
          [--approver <id> --approver-key <path>] [--limit k=v ...]
          [--display-name N] [--agent-id <id>] [--trust-root URL]
          [--expires 2026-12-31T00:00:00Z] [--out agentid.json]

  verify  Verify an AgentID offline against pinned owner/approver keys.
          --bundle agentid.json [--offline] [--trust-roots <file>]
          [--registry <url>] [--revocations <file>]
          [--checkpoint <file>] [--emergency <file>] [--json]
          Exit: 0 ok | 11 owner-sig/not-pinned | 20 approver-floor |
                21 expired | 17 revoked/emergency | 12 registry-not-pinned |
                22 revocation-stale (SPEC-0279 freshness) | 1 other.

  show    Print owner, grant, expiry, fingerprints, signatures.
          skillctl agentid show <agentid.json>

  revoke  Add agent:<id> to a signed, offline revocation list (SPEC-0276).
          skillctl agentid revoke <agent-id> --reason <text>
          [--registry <url>] [--key <registry-key>] [--out <list.json>] [--epoch N]`

// ---- issue ----

func runAgentIDIssue(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agentid issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	owner := fs.String("owner", "", "Owner PLM principal id that holds the signing key, e.g. id:kamir@m3c (required).")
	ownerKey := fs.String("owner-key", "", "Path to the owner's ed25519 private key (PEM PKCS#8) (required).")
	forAgent := fs.String("for-agent", "", "The agent this mandate is FOR: an agent ref or sha256:<digest> (FR-0060 agent bundle).")
	agentIDFlag := fs.String("agent-id", "", "Stable agent id (default: agent:<random>).")
	displayName := fs.String("display-name", "", "Human label for the agent.")
	skills := fs.String("skills", "", "Comma-separated skill grant, e.g. fetch-contract@>=1.0.0,summarize (required).")
	intents := fs.String("intents", "", "Comma-separated SPEC-0196 intents, e.g. network:read,fs:read.")
	dataScopes := fs.String("data-scopes", "", "Comma-separated SPEC-0196 data-scope ids.")
	trustRoot := fs.String("trust-root", "", "Registry URL this mandate speaks for.")
	expires := fs.String("expires", "", "Optional RFC3339 expiry, e.g. 2026-12-31T00:00:00Z (absent = no expiry).")
	approver := fs.String("approver", "", "Optional approver (sign-off human) principal id (SPEC-0277 §11.2).")
	approverKey := fs.String("approver-key", "", "Path to the approver's ed25519 private key (required with --approver).")
	out := fs.String("out", "agentid.json", "Output path for the signed AgentID JSON.")
	var limits multiFlag
	fs.Var(&limits, "limit", "Hard ceiling k=v (repeatable), e.g. --limit spend_eur_max=0.")
	fs.Usage = func() { fmt.Fprintln(stderr, agentIDUsage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if strings.TrimSpace(*owner) == "" || strings.TrimSpace(*ownerKey) == "" {
		fmt.Fprintln(stderr, "skillctl agentid issue: --owner and --owner-key are required.")
		return exitUsage
	}
	if strings.TrimSpace(*skills) == "" {
		fmt.Fprintln(stderr, "skillctl agentid issue: --skills is required (an AgentID with no skills can invoke nothing).")
		return exitUsage
	}
	if (strings.TrimSpace(*approver) == "") != (strings.TrimSpace(*approverKey) == "") {
		fmt.Fprintln(stderr, "skillctl agentid issue: --approver and --approver-key must be given together.")
		return exitUsage
	}

	limitMap, err := parseLimits(limits)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid issue: %v\n", err)
		return exitUsage
	}

	if exp := strings.TrimSpace(*expires); exp != "" {
		if _, perr := agentid.ParseRFC3339UTC(exp); perr != nil {
			fmt.Fprintf(stderr, "skillctl agentid issue: %v\n", perr)
			return exitUsage
		}
	}

	id := strings.TrimSpace(*agentIDFlag)
	if id == "" {
		id = newAgentID()
	} else if !strings.HasPrefix(strings.ToLower(id), "agent:") {
		// Normalize a custom --agent-id to the agent: scheme, exactly as `revoke`
		// does, so the issue and revoke key-spaces always agree. Without this a
		// bare custom id (payload "custombot") would never match a revocation
		// entry ("agent:custombot") — a silent revocation miss (P3 challenge gate).
		id = "agent:" + id
	}

	payload := agentid.Payload{
		ID:                id,
		Owner:             strings.TrimSpace(*owner),
		DisplayName:       strings.TrimSpace(*displayName),
		AgentBundleDigest: strings.TrimSpace(*forAgent),
		CreatedAt:         signing.FormatAttestationTimestamp(time.Now()),
		NotAfter:          strings.TrimSpace(*expires),
		TrustRoot:         strings.TrimSpace(*trustRoot),
		Grant: agentid.Grant{
			Skills:     splitCSV(*skills),
			Intents:    splitCSV(*intents),
			DataScopes: splitCSV(*dataScopes),
			Limits:     limitMap,
		},
	}

	ownerPriv, err := signing.LoadPrivateKey(*ownerKey)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid issue: load owner key %s: %v\n", *ownerKey, err)
		return exitGeneric
	}
	ownerSig, err := agentid.Sign(payload, agentid.RoleOwner, payload.Owner, ownerPriv)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid issue: owner sign: %v\n", err)
		return exitGeneric
	}
	sigs := []agentid.Signature{ownerSig}

	if strings.TrimSpace(*approver) != "" {
		approverPriv, kerr := signing.LoadPrivateKey(*approverKey)
		if kerr != nil {
			fmt.Fprintf(stderr, "skillctl agentid issue: load approver key %s: %v\n", *approverKey, kerr)
			return exitGeneric
		}
		approverSig, serr := agentid.Sign(payload, agentid.RoleApprover, strings.TrimSpace(*approver), approverPriv)
		if serr != nil {
			fmt.Fprintf(stderr, "skillctl agentid issue: approver sign: %v\n", serr)
			return exitGeneric
		}
		sigs = append(sigs, approverSig)
	}

	doc := agentid.AgentID{Payload: payload, Signatures: sigs}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid issue: marshal: %v\n", err)
		return exitGeneric
	}
	if err := os.WriteFile(*out, append(blob, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "skillctl agentid issue: write %s: %v\n", *out, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "issued AgentID %s for owner %s → %s\n", id, payload.Owner, *out)
	if len(sigs) == 2 {
		fmt.Fprintf(stdout, "  co-signed by approver %s (sign-off human)\n", strings.TrimSpace(*approver))
	}
	return exitOK
}

// ---- verify ----

func runAgentIDVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agentid verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundle := fs.String("bundle", "", "Path to the AgentID JSON to verify (required).")
	trustRootsPath := fs.String("trust-roots", "", "Trust-roots YAML to use (default: ~/.claude/skill-trust-roots.yaml).")
	registryURL := fs.String("registry", "", "Registry URL whose pinned root to use (default: the AgentID's trust_root, else the sole root).")
	revocationsPath := fs.String("revocations", "", "Signed revocation list (JSON) to enforce offline. A revoked agent → exit 17.")
	checkpointPath := fs.String("checkpoint", "", "Signed freshness checkpoint (SPEC-0279 R4) that can reset the staleness clock for --revocations without a full re-sync. A forged/stale/rollback checkpoint → exit 12.")
	emergencyPath := fs.String("emergency", "", "Signed emergency deny-list (SPEC-0279 R5). A named agent/owner denies immediately (exit 17), short-circuiting the staleness cadence; a forged list → exit 12.")
	_ = fs.Bool("offline", false, "Offline mode (default; the verifier never touches the network either way).")
	jsonOut := fs.Bool("json", false, "Emit the verdict as JSON.")
	fs.Usage = func() { fmt.Fprintln(stderr, agentIDUsage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if strings.TrimSpace(*bundle) == "" {
		fmt.Fprintln(stderr, "skillctl agentid verify: --bundle is required.")
		return exitUsage
	}

	doc, err := loadAgentIDFile(*bundle)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Resolve pinned trust-roots and pick the matching root (mirrors verify --bundle).
	regForPick := strings.TrimSpace(*registryURL)
	if regForPick == "" {
		regForPick = strings.TrimSpace(doc.Payload.TrustRoot)
	}
	_, root, err := loadAndPickRootFromPath(*trustRootsPath, regForPick)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// Offline revocation: load + signature-verify the list against the pinned
	// root, then collect the agent:<id> revoked set. Fail-closed: a forged /
	// untrusted list is an error (exit 12), not a silent "not revoked". We also
	// capture the snapshot's epoch + issued_at for the SPEC-0279 freshness check.
	var revoked map[string]struct{}
	var revEpoch int
	var revIssuedAt string
	if strings.TrimSpace(*revocationsPath) != "" {
		revoked, revEpoch, revIssuedAt, err = loadAgentRevocationsWithMeta(*revocationsPath, root)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return verify.ExitRegistryNotTrusted
		}
	}

	res, verr := agentid.Verify(doc, agentid.VerifyOpts{
		Pins:            pinnedKeysFromRoot(root),
		RequireApprover: root.RequireAgentApprover,
		RevokedAgentIDs: revoked,
	})
	code := agentIDExitCode(verr)

	// SPEC-0279 R3/R4/R5/R6 — the freshness contract, evaluated once the mandate
	// itself verified (a stale snapshot still gates a high-risk grant). Emergency
	// channel first (R5); a stale snapshot fails closed for a high-risk grant
	// (R3); the checkpoint can reset the clock (R4). Risk is classified from the
	// grant's SPEC-0196 intents.
	var fresh freshnessOutcome
	freshActive := verr == nil &&
		(strings.TrimSpace(*revocationsPath) != "" || strings.TrimSpace(*checkpointPath) != "" || strings.TrimSpace(*emergencyPath) != "")
	if freshActive {
		fresh = evaluateFreshness(freshnessInputs{
			root:            root,
			checkpointPath:  *checkpointPath,
			emergencyPath:   *emergencyPath,
			syncedEpoch:     revEpoch,
			syncedIssuedAt:  revIssuedAt,
			risk:            grantActionRisk(res.Grant),
			emergencyTokens: []string{res.AgentID, res.Owner},
		})
		auditFreshnessDecision("agentid", res.AgentID, fresh)
		if fresh.Err != nil {
			code = freshnessExitCode(fresh)
		}
	}

	if *jsonOut {
		out := agentIDVerifyJSON{ExitCode: code}
		switch {
		case verr != nil:
			out.Error = verr.Error()
		case freshActive && fresh.Err != nil:
			out.Error = fresh.Err.Error()
			out.AgentID = res.AgentID
			out.Owner = res.Owner
			out.Freshness = &fresh.Decision
		default:
			out.OK = true
			out.AgentID = res.AgentID
			out.Owner = res.Owner
			out.ApproverVerified = res.ApproverVerified
			out.Approver = res.Approver
			out.Grant = &res.Grant
			if !res.NotAfter.IsZero() {
				out.NotAfter = res.NotAfter.Format(time.RFC3339)
			}
			if freshActive {
				out.Freshness = &fresh.Decision
			}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return code
	}

	if verr != nil {
		fmt.Fprintln(stderr, verr)
		return code
	}
	if freshActive && fresh.Err != nil {
		fmt.Fprintln(stderr, fresh.Err)
		printFreshness(stderr, fresh, *checkpointPath, *emergencyPath)
		return code
	}
	summary := fmt.Sprintf("AgentID %s OK: owner %s", res.AgentID, res.Owner)
	if res.ApproverVerified {
		summary += fmt.Sprintf(", approver %s (sign-off)", res.Approver)
	}
	if !res.NotAfter.IsZero() {
		summary += ", expires " + res.NotAfter.Format(time.RFC3339)
	}
	summary += fmt.Sprintf(" — grant: %d skills, %d intents (offline)", len(res.Grant.Skills), len(res.Grant.Intents))
	fmt.Fprintln(stdout, summary)
	if freshActive {
		printFreshness(stdout, fresh, *checkpointPath, *emergencyPath)
	}
	return exitOK
}

// grantActionRisk classifies the freshness risk of an AgentID grant from its
// SPEC-0196 intent tokens (the agent's declared capabilities). ANY high-risk
// intent (a write/egress/subprocess/destructive/spend/prod token) makes the grant
// HIGH-risk for freshness purposes; a read-only grant is LOW-risk. Reusing
// ClassifyActionRisk over the grant intents means the red-team cannot downgrade a
// high-risk mandate to low-risk to dodge fail-closed.
func grantActionRisk(g agentid.Grant) verify.ActionRisk {
	// The grant's intents ARE SPEC-0196 side-effect-style tokens (network:write,
	// fs:write, …); pass them as both side-effects and extra signals so spend/prod
	// limit keys also count.
	signals := append([]string{}, g.Intents...)
	for k := range g.Limits {
		signals = append(signals, k)
	}
	return verify.ClassifyActionRisk(g.Intents, false, signals...)
}

type agentIDVerifyJSON struct {
	OK               bool                      `json:"ok"`
	AgentID          string                    `json:"agent_id,omitempty"`
	Owner            string                    `json:"owner,omitempty"`
	ApproverVerified bool                      `json:"approver_verified"`
	Approver         string                    `json:"approver,omitempty"`
	NotAfter         string                    `json:"not_after,omitempty"`
	Grant            *agentid.Grant            `json:"grant,omitempty"`
	Freshness        *verify.FreshnessDecision `json:"freshness,omitempty"`
	Error            string                    `json:"error,omitempty"`
	ExitCode         int                       `json:"exit_code"`
}

// ---- show ----

func runAgentIDShow(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "Usage: skillctl agentid show <agentid.json>")
		return exitUsage
	}
	doc, err := loadAgentIDFile(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	p := doc.Payload
	fmt.Fprintf(stdout, "agent_id:      %s\n", p.ID)
	fmt.Fprintf(stdout, "owner:         %s\n", p.Owner)
	if p.DisplayName != "" {
		fmt.Fprintf(stdout, "display_name:  %s\n", p.DisplayName)
	}
	if p.AgentBundleDigest != "" {
		fmt.Fprintf(stdout, "agent_bundle:  %s\n", p.AgentBundleDigest)
	}
	fmt.Fprintf(stdout, "created_at:    %s\n", p.CreatedAt)
	if p.NotAfter != "" {
		fmt.Fprintf(stdout, "not_after:     %s\n", p.NotAfter)
	} else {
		fmt.Fprintln(stdout, "not_after:     (no expiry)")
	}
	if p.TrustRoot != "" {
		fmt.Fprintf(stdout, "trust_root:    %s\n", p.TrustRoot)
	}
	fmt.Fprintf(stdout, "grant.skills:      %s\n", strings.Join(p.Grant.Skills, ", "))
	fmt.Fprintf(stdout, "grant.intents:     %s\n", strings.Join(p.Grant.Intents, ", "))
	if len(p.Grant.DataScopes) > 0 {
		fmt.Fprintf(stdout, "grant.data_scopes: %s\n", strings.Join(p.Grant.DataScopes, ", "))
	}
	for k, v := range p.Grant.Limits {
		fmt.Fprintf(stdout, "grant.limit:       %s=%s\n", k, v)
	}
	for _, s := range doc.Signatures {
		fp := s.PubkeyFingerprint
		if fp == "" {
			fp = "(no fingerprint)"
		}
		fmt.Fprintf(stdout, "signature:     role=%s identity=%s fingerprint=%s\n", s.Role, s.IdentityID, fp)
	}
	return exitOK
}

// ---- pinned-key adapter (the load-bearing reuse) ----

// rootPins adapts a *verify.TrustRoot to agentid.PinnedKeys. The owner key is
// the principal pinned in the root's `authors:` list (reusing FindAuthor — the
// SAME pin that admits bundles, SPEC-0277 §3); the approver/sign-off human is
// pinned in `reviewers:` (reusing FindReviewer). This GENERALIZES the verified
// role from author→owner WITHOUT forking the verifier: agentid.Verify asks for
// "owner" and "approver" keys; this adapter resolves them from the existing
// pinned-identity lists. No new pinning mechanism, no new crypto.
type rootPins struct{ root *verify.TrustRoot }

func pinnedKeysFromRoot(root *verify.TrustRoot) agentid.PinnedKeys { return rootPins{root: root} }

func (r rootPins) FindOwner(id string) *agentid.PinnedKey {
	ak := r.root.FindAuthor(id)
	if ak == nil {
		return nil
	}
	return &agentid.PinnedKey{ID: ak.ID, Pubkey: ak.Pubkey}
}

func (r rootPins) FindApprover(id string) *agentid.PinnedKey {
	rk := r.root.FindReviewer(id)
	if rk == nil {
		return nil
	}
	return &agentid.PinnedKey{ID: rk.ID, Pubkey: rk.Pubkey}
}

// ---- shared helpers ----

func loadAgentIDFile(path string) (*agentid.AgentID, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agentid: read %s: %w", path, err)
	}
	var doc agentid.AgentID
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("agentid: parse %s: %w", path, err)
	}
	return &doc, nil
}

// splitCSV splits a comma-separated flag value, trimming + dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseLimits turns repeated --limit k=v into a string->string map.
func parseLimits(in []string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for _, kv := range in {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --limit %q (want k=v)", kv)
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

// multiFlag accumulates a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// newAgentID returns a random "agent:<hex>" id. Reuses the invocation-trail
// nonce shape (timestamp + random) so ids are sortable and collision-resistant.
func newAgentID() string {
	return "agent:" + strings.TrimPrefix(newInvocationEventID(), "inv:")
}

// loadAgentRevocations reads a signed revocation list, verifies its signature
// against the pinned root (reusing verify.VerifyRevocationList), and returns the
// set of revoked agent ids (NormalizeID-keyed). The list reuses the SPEC-0276
// RevocationList format; agent ids occupy the RevokedDigests slot under the
// agent: scheme — see runAgentIDRevoke for how the list is produced. Because the
// SPEC-0276 normalizer enforces sha256:<hex> digests, this loader reads the raw
// JSON's revoked_digests verbatim AND verifies the signature, so an agent: key
// is carried without weakening the digest validator for bundles.
func loadAgentRevocations(path string, root *verify.TrustRoot) (map[string]struct{}, error) {
	set, err := verify.LoadVerifiedAgentRevocations(path, root)
	if err != nil {
		return nil, fmt.Errorf("agentid verify: %w", err)
	}
	out := make(map[string]struct{}, len(set))
	for k := range set {
		out[agentid.NormalizeID(k)] = struct{}{}
	}
	return out, nil
}

// loadAgentRevocationsWithMeta is loadAgentRevocations plus the snapshot's epoch
// + issued_at, which the SPEC-0279 freshness contract needs to judge the
// staleness of the SAME signed list it just verified. The signature + rollback
// floor are STILL enforced by LoadVerifiedAgentRevocations (the metadata is read
// from the verified list, never trusted unsigned).
func loadAgentRevocationsWithMeta(path string, root *verify.TrustRoot) (map[string]struct{}, int, string, error) {
	set, err := loadAgentRevocations(path, root)
	if err != nil {
		return nil, 0, "", err
	}
	// Re-read the verified list's metadata (epoch/issued_at). The file already
	// passed signature + epoch-floor verification inside loadAgentRevocations, so
	// re-decoding here only extracts the freshness anchor — a parse failure is
	// surfaced (fail-closed), never silently treated as "no freshness".
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		return nil, 0, "", fmt.Errorf("agentid verify: read revocations for freshness %s: %w", path, rerr)
	}
	var list verify.AgentRevocationList
	if jerr := json.Unmarshal(data, &list); jerr != nil {
		return nil, 0, "", fmt.Errorf("agentid verify: parse revocations for freshness %s: %w", path, jerr)
	}
	return set, list.Epoch, list.IssuedAt, nil
}
