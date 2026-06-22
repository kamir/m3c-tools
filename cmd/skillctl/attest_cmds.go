package main

// Stream S9-cli (SPEC-0188 Phase 5). CLI runner for `skillctl attest`.
//
// Mirrors the signing_cmds.go pattern from S1: the testable handler lives
// in a separate file from main.go so cmd/skillctl/attest_cmds_test.go can
// drive it without a process boundary.
//
// Flow:
//   1. Parse + validate flags (digest, level, rationale, reviewer-id, key, registry).
//   2. Load private key (S1 helper, refuses non-0600 modes).
//   3. attested_at = time.Now().UTC().Truncate(time.Second), formatted via S9 helper.
//   4. Build canonical message bytes via signing.CanonicalizeAttestationMessage.
//      Validation happens here BEFORE signing — a malformed CLI invocation can never
//      produce an ed25519 signature over malformed bytes.
//   5. Sign with stdlib ed25519 (constant-time, deterministic).
//   6. POST JSON to <registry>/attestations.
//   7. On 201: print returned attestation_id, exit 0.
//   8. On non-2xx: stderr-log status + body, exit 1.
//
// Network policy:
//   - 30s HTTP timeout (configurable via --timeout but defaults to 30s).
//   - TLS verification on by default (stdlib default).
//   - Plain HTTP allowed only for localhost / RFC1918 — needed for the homelab
//     MinIO-style registry at 192.168.0.131:9100. See isPrivateRegistryURL below.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// defaultRegistryURL is the registry endpoint used when --registry is not
// passed. Aligns with SPEC-0188 §5: aims-core mounts attestations under
// /api/skills.
const defaultRegistryURL = "http://localhost:8080/api/skills"

// defaultHTTPTimeout is the per-request budget for the registry POST.
// 30s is comfortable for an authenticated single-record write; anything
// longer indicates the registry is broken and the client should fail
// rather than hang.
const defaultHTTPTimeout = 30 * time.Second

// attestRequest is the wire shape posted to /attestations. Matches the
// S9-aims schema exactly. signature is base64-encoded over the 64 raw
// bytes of the ed25519 detached signature.
type attestRequest struct {
	BundleDigest    string `json:"bundle_digest"`
	GovernanceLevel string `json:"governance_level"`
	Rationale       string `json:"rationale"`
	ReviewerID      string `json:"reviewer_id"`
	AttestedAt      string `json:"attested_at"`
	Signature       string `json:"signature"`

	// SelfAttested (SPEC-0246 §5.1) records that the reviewer signing this
	// attestation is the bundle's own author (reviewer_id == author_id,
	// normalized). The server records it on the attestation row so the verifier
	// and inspect/audit can enforce / surface the reviewer≠author floor. The
	// field is NOT folded into the signed bytes (same as rationale) — it is an
	// honest derived label, and the server is the authority that re-derives it
	// from its own author record where one exists.
	SelfAttested bool `json:"self_attested"`

	// AuthorID (SPEC-0246 §5.1) is the bundle author identity the self_attested
	// flag was computed against. Sent so the server can re-derive / cross-check.
	// omitempty: the server prefers its own admit record when present.
	AuthorID string `json:"author_id,omitempty"`
}

// attestResponse is the success shape returned by aims-core on 201.
// We extract attestation_id; everything else is informational.
type attestResponse struct {
	AttestationID string `json:"attestation_id"`
}

// runAttest implements `skillctl attest <bundle-digest> --level ... --rationale ...
// --reviewer-id ... --key ... [--registry ...]`.
func runAttest(args []string, stdout, stderr io.Writer) int {
	return runAttestWithClient(args, stdout, stderr, time.Now, nil)
}

// runAttestWithClient is the test-friendly variant. nowFn lets a test pin
// the wall clock so the canonical message is reproducible; httpClient lets
// a test point the CLI at httptest.Server. When nil, sane defaults apply.
func runAttestWithClient(
	args []string,
	stdout, stderr io.Writer,
	nowFn func() time.Time,
	httpClient *http.Client,
) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	fs.SetOutput(stderr)

	level := fs.String("level", "", "Governance verdict: green | yellow | red. Required.")
	rationale := fs.String("rationale", "", "Free-text rationale (audit metadata; NOT folded into signed bytes). Required.")
	reviewerID := fs.String("reviewer-id", "", "Reviewer identity ID (e.g. id:reviewer@m3c). Required.")
	authorID := fs.String("author-id", "", "Bundle author identity ID, for the SPEC-0246 §5 reviewer≠author check when the server's admit record is unavailable (offline). Optional.")
	keyPath := fs.String("key", "", "Path to PEM PKCS#8 ed25519 private key (mode 0600). Required.")
	registry := fs.String("registry", defaultRegistryURL, "Registry base URL (e.g. https://aims-core/api/skills).")
	timeoutFlag := fs.Duration("timeout", defaultHTTPTimeout, "HTTP request timeout.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl attest <bundle-digest> --level <green|yellow|red> \\")
		fmt.Fprintln(stderr, "         --rationale \"<text>\" --reviewer-id <id> --key <path> \\")
		fmt.Fprintln(stderr, "         [--registry <url>] [--timeout <duration>]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Composes the canonical attestation message,")
		fmt.Fprintln(stderr, "  attestation\\n<digest>\\n<level>\\n<attested_at>\\n<reviewer_id>\\n,")
		fmt.Fprintln(stderr, "signs it with the given ed25519 private key, and POSTs the result to")
		fmt.Fprintln(stderr, "<registry>/attestations.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes: 0 ok | 1 generic/network/non-2xx | 2 usage error.")
		fs.PrintDefaults()
	}

	// Go's stdlib flag package stops at the first non-flag argument. The
	// brief shows the bundle-digest as the FIRST positional, before any
	// flags ("skillctl attest <digest> --level ..."), which is also how
	// users will type it. To support that ergonomic, extract a single
	// looks-like-a-digest token from anywhere in args BEFORE handing the
	// remainder to flag.Parse. We accept any positional that begins with
	// "sha256:" (validated strictly downstream by canonicalize).
	digestArg, flagArgs := extractDigestPositional(args)

	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}
	// Allow either pre-flag positional (extracted above) or trailing
	// positional via fs.Arg(0). Reject if both, or neither.
	bundleDigest := digestArg
	switch {
	case digestArg == "" && fs.NArg() == 1:
		bundleDigest = fs.Arg(0)
	case digestArg != "" && fs.NArg() == 0:
		// already set
	default:
		fs.Usage()
		return exitUsage
	}

	// ----- Input validation BEFORE signing -----
	// Order: cheap checks first, key load last, sign even later. Anything
	// that should reject the invocation outright must reject here so we
	// never produce a signature that reflects a malformed request.
	if *level == "" || *rationale == "" || *reviewerID == "" || *keyPath == "" {
		fs.Usage()
		return exitUsage
	}
	if !isKnownLevel(*level) {
		fmt.Fprintf(stderr, "skillctl attest: invalid --level %q (want green|yellow|red)\n", *level)
		return exitUsage
	}
	// Reject malformed digests up front — easier to reason about than a
	// canonicalize error after we've already loaded the key.
	if _, err := signing.CanonicalizeAttestationMessage(bundleDigest, *level, "1970-01-01T00:00:00Z", *reviewerID); err != nil {
		// This canonicalize call is purely a validator (we'll throw the
		// bytes away). The 1970 timestamp is just a known-good format
		// to satisfy that field's check; the real timestamp is built
		// below.
		fmt.Fprintf(stderr, "skillctl attest: %v\n", err)
		return exitUsage
	}
	if !filepath.IsAbs(*keyPath) {
		fmt.Fprintf(stderr, "warning: --key %q is a relative path; resolving against CWD\n", *keyPath)
	}
	if err := validateRegistryURL(*registry); err != nil {
		fmt.Fprintf(stderr, "skillctl attest: %v\n", err)
		return exitUsage
	}

	// ----- Load the private key -----
	// LoadPrivateKey already enforces mode 0600 and PEM validation.
	priv, err := signing.LoadPrivateKey(*keyPath)
	if err != nil {
		// LoadPrivateKey only references the path, never the bytes.
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	// ----- SPEC-0246 §5.1: derive self_attested BEFORE signing -----
	// self_attested := normalize(reviewer_id) == normalize(author_id). The
	// author identity comes from --author-id (offline) — when the server has an
	// admit record it re-derives authoritatively, but we send our honest local
	// computation so the offline path still records the right label. When
	// --author-id is absent we cannot compute it locally; the server decides.
	selfAttested := false
	authorKnownLocally := strings.TrimSpace(*authorID) != ""
	if authorKnownLocally {
		selfAttested = normalizeIdentity(*reviewerID) == normalizeIdentity(*authorID)
	}
	if selfAttested {
		fmt.Fprintf(stderr,
			"skillctl attest: NOTE — self-attestation: reviewer %q is the bundle author. "+
				"This attestation is self_attested=true; a trust root with "+
				"require_independent_review will REFUSE the bundle (SPEC-0246 §5).\n",
			*reviewerID)
	}

	// ----- Build canonical message and sign -----
	if nowFn == nil {
		nowFn = time.Now
	}
	attestedAt := signing.FormatAttestationTimestamp(nowFn())

	msg, err := signing.CanonicalizeAttestationMessage(bundleDigest, *level, attestedAt, *reviewerID)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl attest: %v\n", err)
		return exitGeneric
	}
	sigBytes := signing.SignAttestation(priv, msg)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// ----- POST to registry -----
	body := attestRequest{
		BundleDigest:    bundleDigest,
		GovernanceLevel: *level,
		Rationale:       *rationale,
		ReviewerID:      *reviewerID,
		AttestedAt:      attestedAt,
		Signature:       sigB64,
		SelfAttested:    selfAttested,
		AuthorID:        strings.TrimSpace(*authorID),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl attest: marshal request: %v\n", err)
		return exitGeneric
	}

	endpoint := strings.TrimRight(*registry, "/") + "/attestations"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		fmt.Fprintf(stderr, "skillctl attest: build request: %v\n", err)
		return exitGeneric
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "skillctl/spec-0188")

	if httpClient == nil {
		httpClient = &http.Client{Timeout: *timeoutFlag}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl attest: POST %s: %v\n", endpoint, err)
		return exitGeneric
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1 MiB
	if err != nil {
		fmt.Fprintf(stderr, "skillctl attest: read response: %v\n", err)
		return exitGeneric
	}

	if resp.StatusCode != http.StatusCreated {
		fmt.Fprintf(stderr, "skillctl attest: registry returned %s\n", resp.Status)
		if len(respBody) > 0 {
			fmt.Fprintf(stderr, "response body: %s\n", string(respBody))
		}
		return exitGeneric
	}

	var ok attestResponse
	if err := json.Unmarshal(respBody, &ok); err != nil {
		fmt.Fprintf(stderr, "skillctl attest: registry returned 201 but body is not JSON: %v\n", err)
		return exitGeneric
	}
	if ok.AttestationID == "" {
		fmt.Fprintln(stderr, "skillctl attest: registry returned 201 but no attestation_id")
		return exitGeneric
	}

	fmt.Fprintf(stdout, "attestation_id: %s\n", ok.AttestationID)
	fmt.Fprintf(stdout, "bundle_digest: %s\n", bundleDigest)
	fmt.Fprintf(stdout, "level: %s\n", *level)
	fmt.Fprintf(stdout, "attested_at: %s\n", attestedAt)
	if authorKnownLocally {
		fmt.Fprintf(stdout, "self_attested: %t\n", selfAttested)
	}
	return exitOK
}

// extractDigestPositional pulls a single positional argument that looks
// like a digest ("sha256:...") out of args, returning the digest and the
// args with that token removed. If multiple sha256: tokens are present,
// returns ("", args) so the downstream parser produces a usage error
// rather than guessing.
//
// Why: Go's stdlib flag package doesn't support flags after positional
// args. The S9 brief's CLI shape ("skillctl attest <digest> --level ...")
// puts the digest first. This helper bridges the gap so users can write
// either ordering.
func extractDigestPositional(args []string) (digest string, rest []string) {
	rest = make([]string, 0, len(args))
	found := 0
	var picked string
	for _, a := range args {
		if strings.HasPrefix(a, "sha256:") {
			found++
			picked = a
			continue
		}
		rest = append(rest, a)
	}
	if found == 1 {
		return picked, rest
	}
	// Either no digest-shaped positional (caller may have placed it at
	// the trailing slot — fs.Arg(0) handles that path) or multiple
	// (ambiguous — bail with empty so downstream usage check fires).
	return "", args
}

// isKnownLevel returns true if level is one of the three Ampel verdicts.
// Duplicate of signing's internal check but kept here so we can raise a
// clean usage error (exit 2) rather than a generic validation error.
func isKnownLevel(level string) bool {
	switch level {
	case "green", "yellow", "red":
		return true
	default:
		return false
	}
}

// validateRegistryURL refuses obviously broken URLs and enforces the TLS
// policy: HTTPS is always allowed; HTTP is allowed only for localhost or
// RFC1918 ranges (homelab registries — 192.168.0.131:9100 must work).
//
// Returns nil if the URL passes; an error explaining the reason otherwise.
func validateRegistryURL(raw string) error {
	if raw == "" {
		return errors.New("--registry must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--registry %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("--registry scheme %q not supported (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("--registry %q has no host", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	// Plain HTTP — only allow loopback or RFC1918 hosts.
	if !isPrivateOrLoopbackHost(u.Hostname()) {
		return fmt.Errorf("--registry %q uses plain HTTP against a non-private host; use HTTPS or point at localhost / RFC1918", raw)
	}
	return nil
}

// isPrivateOrLoopbackHost reports whether host is a hostname/literal that
// resolves into RFC1918 / loopback / link-local space without us needing
// to actually do DNS. We accept:
//   - "localhost" string literal
//   - any literal IP that's loopback or in the private/link-local ranges
//
// We deliberately do NOT do DNS lookups here — that would be a TOCTOU
// risk (an attacker could change DNS between our check and net/http's
// dial). For named hosts that aren't "localhost", we require HTTPS.
func isPrivateOrLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	return ip.IsPrivate()
}
