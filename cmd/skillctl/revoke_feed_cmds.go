package main

// revoke_feed_cmds.go — `skillctl revoke feed` (FR-0045 D5).
//
// Operator-facing view of the signed revocation HEAD (the G5 kill-switch feed):
//   --status  (default) fetch the HEAD from the registry, verify its ed25519
//             envelope signature against the PINNED registry key, and print a
//             one-line status (verified / epoch / issued_at / staleness / counts).
//   --refresh run the revocation sweep now (adopts the HEAD into the local cache
//             + freshness anchor the SPEC-0247 gate reads).

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func runRevokeFeed(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("revoke feed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registryURL := fs.String("registry", defaultRegistryURL, "Registry base URL (e.g. http://127.0.0.1:8081/api/skills).")
	tenant := fs.String("tenant", "", "Tenant scope (optional; default global).")
	timeout := fs.Duration("timeout", defaultHTTPTimeout, "HTTP timeout for the HEAD fetch.")
	refresh := fs.Bool("refresh", false, "Run the revocation sweep now to refresh the local cache + freshness anchor.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl revoke feed [--status] [--refresh] [--registry URL] [--tenant T]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Inspect or refresh the signed revocation HEAD — the G5 kill-switch feed (FR-0045).")
		fmt.Fprintln(stderr, "  --status  (default) fetch + verify the HEAD against the pinned registry key")
		fmt.Fprintln(stderr, "  --refresh sweep now: adopt the HEAD into the local cache + freshness anchor")
		fmt.Fprintln(stderr, "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	home, _ := userHome()

	if *refresh {
		// Ensure the production fetch seam is installed even if this runs outside
		// the main() dispatch (e.g. a test binary), then sweep.
		if fetchRevocationHeadFn == nil {
			fetchRevocationHeadFn = fetchRevocationHeadOnline
		}
		set, online := fetchRevokedOnline(home)
		epoch, issuedAt := readRevokedCacheHead(home)
		fmt.Fprintf(stdout, "refreshed: %d revoked digest(s), epoch=%d issued_at=%q online=%v\n",
			len(set), epoch, issuedAt, online)
		return exitOK
	}

	// --status (default): fetch + verify the HEAD.
	head, err := registry.FetchRevocationHead(*registryURL, *tenant, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl revoke feed: fetch failed: %v\n", err)
		return exitGeneric
	}

	verified := false
	if _, root, rerr := loadRootsFn(*registryURL); rerr == nil && root != nil {
		for _, k := range root.ActiveKeys() {
			if registry.VerifyEnvelopeSignature(ed25519.PublicKey(k.Pubkey), head) == nil {
				verified = true
				break
			}
		}
	}

	epoch, _ := registry.HeadEpoch(head)
	issuedAt, _ := registry.HeadIssuedAt(head)
	staleness := "n/a"
	issuedStr := "n/a"
	if !issuedAt.IsZero() {
		issuedStr = issuedAt.Format(time.RFC3339)
		staleness = time.Since(issuedAt).Truncate(time.Second).String()
	}
	emergency, _ := registry.HeadEmergency(head)
	revokedCount := 0
	if v, ok := head["revoked_count"].(float64); ok {
		revokedCount = int(v)
	}

	fmt.Fprintf(stdout,
		"revocation-head[%s] verified=%v epoch=%d issued_at=%s staleness=%s revoked=%d emergency=%d\n",
		*registryURL, verified, epoch, issuedStr, staleness, revokedCount, len(emergency))

	if !verified {
		fmt.Fprintln(stderr, "WARNING: HEAD signature not verified against any pinned registry key (untrusted registry, or no trust roots configured).")
		return exitGeneric
	}
	return exitOK
}
