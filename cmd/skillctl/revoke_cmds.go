package main

// SPEC-0188 §4.5 (S3.6 closure 2026-05-06). CLI runner for `skillctl revoke`.
//
// Mirrors the attest_cmds.go pattern: the testable handler lives in this
// file so cmd/skillctl/revoke_cmds_test.go can drive it without spinning a
// process. main.go's dispatcher is a one-line case → runRevoke.
//
// Three actor paths (S3-DECISIONS S3.6 Q1=A — single endpoint, server
// dispatches by role):
//
//   skillctl revoke <digest> --reason <enum>
//                            [--role registry_operator|governance_reviewer|original_author]
//                            [--actor-identity id:...]
//                            [--key PATH]
//                            [--registry URL]
//                            [--timeout 30s]
//
// Default --role is `original_author` (the trainer's own machine; uses
// the local skillctl author key). The other two roles are operator paths;
// `registry_operator` is unsigned (HTTP-layer admin auth at the registry),
// `governance_reviewer` requires --actor-identity + --key on the
// reviewer's machine.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// validRevocationReasons mirrors the closed enum in SPEC-0188 §4.5 / the
// server's _REVOCATION_REASONS frozenset.
var validRevocationReasons = map[string]struct{}{
	"key_compromise":        {},
	"vulnerability":         {},
	"governance_retraction": {},
	"author_request":        {},
	"duplicate":             {},
}

// validRevocationRoles mirrors the server's _REVOCATION_ACTOR_ROLES.
var validRevocationRoles = map[string]struct{}{
	"registry_operator":   {},
	"governance_reviewer": {},
	"original_author":     {},
}

// revokeRequest is the wire shape of POST /api/skills/bundles/<digest>/revoke.
// Field names match the Python handler's request.get_json() keys.
type revokeRequest struct {
	ActorRole            string `json:"actor_role"`
	ActorIdentity        string `json:"actor_identity,omitempty"`
	Reason               string `json:"reason"`
	RevocationTimestamp  string `json:"revocation_timestamp"`
	RequestSignatureB64  string `json:"request_signature_b64,omitempty"`
}

// revokeResponse is the success-shape from the server (the updated bundle row).
type revokeResponse struct {
	Status         string `json:"status"`
	BundleDigest   string `json:"bundle_digest"`
	RevokedAt      string `json:"revoked_at"`
	RevokedReason  string `json:"revoked_reason"`
	RevokedBy      string `json:"revoked_by"`
	RevokedByRole  string `json:"revoked_by_role"`
}

// revokeError is the failure-shape with a `reason` discriminator.
type revokeError struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// runRevoke is main's dispatch entry point. Returns a numeric exit code:
//
//   0  — revoked.
//   1  — generic / network / server 5xx.
//   2  — usage / flag error.
//   15 — server returned 409 already_revoked OR 404 not_admitted.
//
// Exit 15 reuses the SPEC-0188 §11 ExitBlobMissing class because the
// trust-chain semantics are identical: the bundle is not in a state
// the verifier can install. The `reason` field on stderr distinguishes
// already-revoked from never-admitted for the operator.
func runRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)

	role := fs.String("role", "original_author", "Actor role: registry_operator | governance_reviewer | original_author.")
	reason := fs.String("reason", "", "Revocation reason (required). One of: key_compromise | vulnerability | governance_retraction | author_request | duplicate.")
	actorIdentity := fs.String("actor-identity", "", "Identity id for governance_reviewer / original_author roles. Defaults to id:<user>@m3c for original_author.")
	keyPath := fs.String("key", "", "ed25519 private key (PEM PKCS#8). Required for governance_reviewer / original_author. Default: ~/.claude/skillctl-keys/author.key.")
	registryURL := fs.String("registry", defaultRegistryURL, "Registry base URL (e.g. http://127.0.0.1:8081/api/skills).")
	timeout := fs.Duration("timeout", defaultHTTPTimeout, "HTTP timeout for the registry POST.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl revoke <digest> --reason <enum> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Revoke an admitted bundle (SPEC-0188 §4.5).")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "<digest> is the canonical 'sha256:<64 hex>' bundle digest.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Reasons: key_compromise | vulnerability | governance_retraction | author_request | duplicate.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Roles:")
		fmt.Fprintln(stderr, "  original_author      (default) — sign with your skillctl author key")
		fmt.Fprintln(stderr, "  governance_reviewer  — sign with the reviewer's key (requires --actor-identity + --key)")
		fmt.Fprintln(stderr, "  registry_operator    — unsigned; HTTP-layer admin auth at the registry")
		fmt.Fprintln(stderr, "")
		fs.PrintDefaults()
	}

	digest, rest := extractDigestPositional(args)
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}

	if digest == "" {
		fmt.Fprintln(stderr, "skillctl revoke: bundle digest argument is required (positional, before flags).")
		fs.Usage()
		return exitUsage
	}

	// --reason is mandatory; check enum.
	if *reason == "" {
		fmt.Fprintln(stderr, "skillctl revoke: --reason is required.")
		return exitUsage
	}
	if _, ok := validRevocationReasons[*reason]; !ok {
		fmt.Fprintf(stderr, "skillctl revoke: invalid --reason %q (want one of: key_compromise|vulnerability|governance_retraction|author_request|duplicate)\n", *reason)
		return exitUsage
	}

	// --role enum.
	if _, ok := validRevocationRoles[*role]; !ok {
		fmt.Fprintf(stderr, "skillctl revoke: invalid --role %q (want one of: registry_operator|governance_reviewer|original_author)\n", *role)
		return exitUsage
	}

	if err := validateRegistryURL(*registryURL); err != nil {
		fmt.Fprintf(stderr, "skillctl revoke: %v\n", err)
		return exitUsage
	}

	// Build the canonical message + sign for the two non-operator roles.
	tsISO := signing.FormatAttestationTimestamp(time.Now())

	req := revokeRequest{
		ActorRole:           *role,
		Reason:              *reason,
		RevocationTimestamp: tsISO,
		ActorIdentity:       *actorIdentity,
	}

	if *role != "registry_operator" {
		// Sign the canonical message.
		if req.ActorIdentity == "" {
			// Sensible default for the original_author path: use the
			// caller's local user as identity. Reviewer path requires
			// an explicit identity.
			if *role == "original_author" {
				req.ActorIdentity = defaultAuthorIdentity()
			}
		}
		if req.ActorIdentity == "" {
			fmt.Fprintf(stderr, "skillctl revoke: --actor-identity is required for role=%s\n", *role)
			return exitUsage
		}

		msg, err := signing.CanonicalizeRevocationMessage(digest, tsISO, *role)
		if err != nil {
			fmt.Fprintf(stderr, "skillctl revoke: %v\n", err)
			return exitUsage
		}

		keyFile := *keyPath
		if keyFile == "" {
			keyFile = defaultAuthorKeyPath()
		}
		priv, err := signing.LoadPrivateKey(keyFile)
		if err != nil {
			fmt.Fprintf(stderr, "skillctl revoke: load key %s: %v\n", keyFile, err)
			return exitGeneric
		}
		sig := signing.SignRevocation(priv, msg)
		req.RequestSignatureB64 = base64.StdEncoding.EncodeToString(sig)
	}

	// POST to <registry>/bundles/<digest>/revoke.
	client := &http.Client{Timeout: *timeout}
	endpoint := strings.TrimRight(*registryURL, "/") + "/bundles/" + digest + "/revoke"

	body, err := json.Marshal(&req)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl revoke: marshal: %v\n", err)
		return exitGeneric
	}

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(stderr, "skillctl revoke: build request: %v\n", err)
		return exitGeneric
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "skillctl/spec-0188-s3.6")

	resp, err := client.Do(httpReq)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl revoke: POST %s: %v\n", endpoint, err)
		return exitGeneric
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	if resp.StatusCode == 200 {
		var ok revokeResponse
		if err := json.Unmarshal(respBody, &ok); err != nil {
			fmt.Fprintf(stderr, "skillctl revoke: decode response: %v\n", err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "bundle_digest: %s\n", ok.BundleDigest)
		fmt.Fprintf(stdout, "status:        %s\n", ok.Status)
		fmt.Fprintf(stdout, "revoked_at:    %s\n", ok.RevokedAt)
		fmt.Fprintf(stdout, "revoked_by:    %s (%s)\n", ok.RevokedBy, ok.RevokedByRole)
		fmt.Fprintf(stdout, "reason:        %s\n", ok.RevokedReason)
		return exitOK
	}

	// Decode error envelope.
	var e revokeError
	_ = json.Unmarshal(respBody, &e)
	switch resp.StatusCode {
	case http.StatusNotFound:
		fmt.Fprintf(stderr, "skillctl revoke: bundle not found or not admitted (digest=%s, reason=%s)\n", digest, e.Reason)
		return 15
	case http.StatusConflict:
		fmt.Fprintf(stderr, "skillctl revoke: bundle is already revoked (digest=%s)\n", digest)
		return 15
	case http.StatusForbidden:
		fmt.Fprintf(stderr, "skillctl revoke: refused (reason=%s) — %s\n", e.Reason, e.Error)
		return exitGeneric
	case http.StatusBadRequest:
		fmt.Fprintf(stderr, "skillctl revoke: bad request (reason=%s) — %s\n", e.Reason, e.Error)
		return exitUsage
	default:
		fmt.Fprintf(stderr, "skillctl revoke: HTTP %d — %s\n", resp.StatusCode, e.Error)
		return exitGeneric
	}
}

// defaultAuthorIdentity returns id:<user>@m3c. Mirrors what the
// awareness path uses when no --actor-identity is given.
func defaultAuthorIdentity() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}
	if user == "" {
		return ""
	}
	return "id:" + user + "@m3c"
}

// defaultAuthorKeyPath returns ~/.claude/skillctl-keys/author.key.
func defaultAuthorKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".claude", "skillctl-keys", "author.key")
}
