package main

// sync_cmds.go — SPEC-0317 §R-5 (P1): the sync agent.
//
//	skillctl sync --once     drain audit_events → the KafShield ingest, then exit.
//	skillctl sync --daemon   loop the same drain on an interval with a
//	                         signal-handled graceful shutdown.
//
// This is a SEPARATE process. It is NEVER invoked on the PreToolUse hook path —
// the hot path only writes the outbox (P0) and, at most, best-effort "nudges" a
// sync. Draining, HTTPS egress, backoff and dedup all live here, off the hot
// path, so decision latency (AC-3) and decision-invariance (SPEC-0255) are
// untouched.
//
// Contract (R-5.3 / AC-4): a row is marked synced ONLY on a VALID signed
// durable-seq ack. A bare-2xx from a non-durable stub does NOT mark synced. A
// replay of an already-acked event_id is a client-side no-op (dedup by the
// signature-bound event_id — an already-synced row never re-enters the drain
// set, and the outbox INSERT/MarkSynced are idempotent). Transient 5xx →
// delivery_attempts row with retryqueue-shaped backoff. A 4xx auth reject →
// exit 29 (ingest_rejected).
//
// Egress posture (R-9.1): the drain is DEFAULT-OFF. With no endpoint configured
// the command reports "local-only evidence" and exits 0 without egress. The
// enforcement-evidence records ship verbatim (they are device-signed; mutating
// them for data-minimisation would break verifiability) — cwd/host_id/session_id
// minimisation is a property of the SEPARATE PII telemetry stream (sync-usage),
// not this signed-evidence stream (R-9.2).
//
// HTTPS-only (R-5.2). --insecure (skip TLS verify) is honoured ONLY for a
// loopback endpoint; a prod (non-loopback) endpoint never inherits
// InsecureSkipVerify.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/device"
	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillgate"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

const (
	syncExitOK             = 0
	syncExitError          = 1
	syncExitUsage          = 2
	syncExitIngestRejected = 29 // exitcode.SyncIngestRejected — auth/validation reject (4xx)
)

// syncDefaultBatch is the default drain batch size (R-5.1).
const syncDefaultBatch = 100

// syncDefaultInterval is the default --daemon loop interval.
const syncDefaultInterval = 60 * time.Second

// --- test seams ---------------------------------------------------------------

// syncNow is the clock seam (synced_at / attempt timestamps). Tests pin it.
var syncNow = func() time.Time { return time.Now().UTC() }

// syncResolveDevicePub resolves the ed25519 public key for a row's device_key_id
// so the drain can re-verify the row's signature locally before egress. Default:
// the local device key (a row this host wrote). Tests inject the signer's key.
// A row whose key cannot be resolved still ships if its payload↔hash binding is
// intact (the load-bearing tamper check); the signature check is best-effort.
var syncResolveDevicePub = func(home, keyID string) (ed25519.PublicKey, bool) {
	k, err := device.Load(home)
	if err != nil || k == nil {
		return nil, false
	}
	if k.KeyID() != keyID {
		return nil, false
	}
	return k.PublicKey(), true
}

// --- entry point --------------------------------------------------------------

func runSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		once     = fs.Bool("once", false, "Drain pending evidence once, then exit.")
		daemon   = fs.Bool("daemon", false, "Loop the drain on --interval with a signal-handled shutdown.")
		batch    = fs.Int("batch", syncDefaultBatch, "Max rows per drain batch.")
		endpoint = fs.String("endpoint", "", "Ingest endpoint base URL (https). Default OFF (local-only evidence).")
		pubkey   = fs.String("ingest-pubkey", "", "PEM (SPKI) ed25519 public key that signs durable-seq acks. Required to mark rows synced.")
		logID    = fs.String("log-id", "skillctl-local", "Log id the durable-seq signature is bound to.")
		interval = fs.Duration("interval", syncDefaultInterval, "Daemon loop interval.")
		insecure = fs.Bool("insecure", false, "Skip TLS verification (loopback endpoints only).")
	)
	if err := fs.Parse(args); err != nil {
		return syncExitUsage
	}
	if *once == *daemon {
		fmt.Fprintln(stderr, "skillctl sync: choose exactly one of --once or --daemon")
		return syncExitUsage
	}
	if *batch <= 0 {
		*batch = syncDefaultBatch
	}

	home, err := userHome()
	if err != nil {
		fmt.Fprintf(stderr, "skillctl sync: resolve home: %v\n", err)
		return syncExitError
	}

	// R-9.1 egress gate: default-OFF. Endpoint may also come from the
	// environment so a daemon unit need not repeat it on the command line.
	ep := strings.TrimSpace(*endpoint)
	if ep == "" {
		ep = strings.TrimSpace(os.Getenv("M3C_INGEST_ENDPOINT"))
	}
	if ep == "" {
		fmt.Fprintln(stdout, "skillctl sync: egress disabled (local-only evidence); set --endpoint or M3C_INGEST_ENDPOINT to enable")
		return syncExitOK
	}

	client, err := buildIngestClient(ep, *pubkey, *logID, *insecure, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl sync: %v\n", err)
		return syncExitError
	}

	store, err := outbox.Open(home)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl sync: open outbox: %v\n", err)
		return syncExitError
	}
	defer store.Close()

	if *daemon {
		return runSyncDaemon(store, client, home, *batch, *interval, stdout, stderr)
	}
	code, res := drainAll(context.Background(), store, client, home, *batch, stderr)
	reportDrain(stdout, res)
	return code
}

// buildIngestClient assembles the IngestClient and its HTTP transport. HTTPS is
// enforced by IngestClient.PostBatch; here we gate InsecureSkipVerify to
// loopback so a prod endpoint can never inherit it (R-5.2).
func buildIngestClient(endpoint, pubkeyPath, logID string, insecure bool, stderr io.Writer) (*outbox.IngestClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("endpoint must be https, got %q", u.Scheme)
	}

	transport := &http.Transport{}
	if insecure {
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("--insecure is only permitted for a loopback endpoint (got host %q)", u.Hostname())
		}
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback-only, gated above
	}

	var pub ed25519.PublicKey
	if strings.TrimSpace(pubkeyPath) != "" {
		pub, err = signing.LoadPublicKey(pubkeyPath)
		if err != nil {
			return nil, fmt.Errorf("load ingest pubkey: %w", err)
		}
	} else {
		fmt.Fprintln(stderr, "[skillctl sync] no --ingest-pubkey: durable-seq acks cannot be verified; rows will NOT be marked synced")
	}

	return &outbox.IngestClient{
		Endpoint:    endpoint,
		Token:       strings.TrimSpace(os.Getenv("ER1_DEVICE_TOKEN")),
		LogID:       logID,
		PubKey:      pub,
		Client:      &http.Client{Timeout: 15 * time.Second, Transport: transport},
		ClientEpoch: syncNow().Unix(),
	}, nil
}

// isLoopbackHost reports whether host is a loopback address or "localhost".
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// --- daemon -------------------------------------------------------------------

func runSyncDaemon(store *outbox.Store, client *outbox.IngestClient, home string, batch int, interval time.Duration, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "skillctl sync: daemon started (interval %s, batch %d)\n", interval, batch)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Drain immediately on start, then on each tick.
	for {
		code, res := drainAll(ctx, store, client, home, batch, stderr)
		reportDrain(stdout, res)
		if code == syncExitIngestRejected {
			fmt.Fprintln(stderr, "skillctl sync: ingest rejected the batch (auth/validation); stopping daemon")
			_ = store.Checkpoint()
			return syncExitIngestRejected
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(stdout, "skillctl sync: shutdown signal received; checkpointing and exiting")
			_ = store.Checkpoint()
			return syncExitOK
		case <-ticker.C:
		}
	}
}

// --- drain --------------------------------------------------------------------

// drainResult accumulates one drain invocation's counters for reporting.
type drainResult struct {
	Reconciled int
	Posted     int
	Synced     int
	Deferred   int // rows that got a backoff row (bare-2xx / transient / invalid ack)
	Flagged    int // rows dropped for a payload↔hash divergence (tamper signal)
}

func reportDrain(stdout io.Writer, r drainResult) {
	fmt.Fprintf(stdout, "skillctl sync: reconciled=%d posted=%d synced=%d deferred=%d flagged=%d\n",
		r.Reconciled, r.Posted, r.Synced, r.Deferred, r.Flagged)
}

// drainAll runs the full drain: reconcile the spool, then post batches until no
// forward progress is made (an empty pending set, or a batch where nothing could
// be marked synced — the bare-2xx stub case, which must not loop forever). It
// returns an exit code and the accumulated counters.
func drainAll(ctx context.Context, store *outbox.Store, client *outbox.IngestClient, home string, batch int, stderr io.Writer) (int, drainResult) {
	var res drainResult

	// Rows backed off during THIS drain: never re-posted within the same cycle.
	// The PendingBatchDue due-gate excludes deferred rows ACROSS cycles (their
	// next_retry_at is in the future); this in-memory set is the belt-and-suspenders
	// guard for the same cycle — chiefly the capped-attempt case whose next_retry_at
	// no longer advances (INSERT OR IGNORE at the attempt ceiling), which would
	// otherwise re-enter the drain set behind a marked row.
	deferred := map[string]struct{}{}

	// R-5.1 / R-2.5: reconcile the spool BEFORE the first batch so spilled rows are
	// drained into audit_events in occurred_at order ahead of fresh evidence.
	// (Per-batch translog anchoring — AC-5a — is NOT-YET-BUILT: nothing stamps
	// translog_seq, so there is no local-monotonicity claim here.)
	if n, err := store.Reconcile(); err != nil {
		fmt.Fprintf(stderr, "skillctl sync: reconcile spool: %v\n", err)
	} else {
		res.Reconciled = n
	}

	for {
		if ctx.Err() != nil {
			return syncExitOK, res
		}
		// Backoff-aware drain set (R-5.3): a row whose delivery_attempts.next_retry_at
		// is still in the future is NOT due and is excluded — so a deferred row is not
		// re-POSTed before its backoff elapses.
		pending, err := store.PendingBatchDue(batch, syncNow().UTC().Format(time.RFC3339))
		if err != nil {
			fmt.Fprintf(stderr, "skillctl sync: pending batch: %v\n", err)
			return syncExitError, res
		}
		pending = filterDeferred(pending, deferred)
		if len(pending) == 0 {
			return syncExitOK, res
		}

		// Re-verify each row locally and collect the shippable records. A
		// payload↔hash divergence is a tamper signal (R-2.6): drop the row from
		// egress (it stays in the store, flagged) rather than shipping an
		// unverifiable local row.
		records := make([][]byte, 0, len(pending))
		rows := make([]outbox.Event, 0, len(pending))
		for _, ev := range pending {
			if !reVerifyRow(home, ev) {
				res.Flagged++
				continue
			}
			records = append(records, []byte(ev.PayloadJSON))
			rows = append(rows, ev)
		}
		if len(records) == 0 {
			// Every row in this batch is unverifiable; no forward progress is
			// possible without operator action. Stop to avoid a hot loop.
			return syncExitOK, res
		}

		resp, status, err := client.PostBatch(ctx, records)
		res.Posted += len(records)
		switch {
		case err != nil || status == 0 || status/100 == 5:
			// Transient: record a backoff attempt for every posted row and stop
			// this drain cycle (the daemon retries on the next tick; --once
			// exits, leaving the rows for a later run).
			if err != nil {
				fmt.Fprintf(stderr, "skillctl sync: post batch: %v\n", err)
			} else {
				fmt.Fprintf(stderr, "skillctl sync: ingest transient status %d; backing off\n", status)
			}
			for _, ev := range rows {
				recordBackoff(store, ev.EventID, status, transientMsg(err, status))
				deferred[ev.EventID] = struct{}{}
				res.Deferred++
			}
			return syncExitOK, res
		case status/100 == 4:
			// Auth / validation reject — not transient. Surface the numbered
			// code so an operator (non-hot-path) sees it.
			fmt.Fprintf(stderr, "skillctl sync: ingest rejected batch with status %d (%s)\n",
				status, exitcode.SyncIngestRejected.Label)
			return syncExitIngestRejected, res
		}

		// 2xx: mark synced ONLY those rows with a VALID signed durable-seq ack.
		acks := map[string]outbox.DurableAck{}
		for _, a := range resp.Acks {
			acks[a.EventID] = a
		}
		markedThisBatch := 0
		for _, ev := range rows {
			ack, ok := acks[ev.EventID]
			if ok && client.VerifyAck(ack) {
				if err := store.MarkSynced(ev.EventID, syncNow().UTC().Format(time.RFC3339)); err != nil {
					fmt.Fprintf(stderr, "skillctl sync: mark synced %s: %v\n", ev.EventID, err)
					continue
				}
				res.Synced++
				markedThisBatch++
			} else {
				// Bare-2xx (no/invalid durable-seq): DO NOT mark synced. Record a
				// backoff attempt so the row is retried later (R-5.3 / AC-4).
				recordBackoff(store, ev.EventID, status, "bare-2xx: no valid durable-seq ack")
				deferred[ev.EventID] = struct{}{}
				res.Deferred++
			}
		}
		if markedThisBatch == 0 {
			// No forward progress (e.g. a bare-2xx stub). Stop so PendingBatch
			// does not return the same rows forever.
			return syncExitOK, res
		}
	}
}

// filterDeferred drops rows already backed off in the current drain cycle so a
// mixed-ack batch (some rows marked synced, some deferred) does not re-POST the
// deferred rows behind a marked row within the same cycle. It reuses evs's backing
// array (evs is freshly queried each iteration, so this is safe).
func filterDeferred(evs []outbox.Event, deferred map[string]struct{}) []outbox.Event {
	if len(deferred) == 0 {
		return evs
	}
	out := evs[:0]
	for _, e := range evs {
		if _, skip := deferred[e.EventID]; skip {
			continue
		}
		out = append(out, e)
	}
	return out
}

// transientMsg renders a compact error string for a delivery_attempts row.
func transientMsg(err error, status int) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("http %d", status)
}

// recordBackoff appends one delivery_attempts row with retryqueue-shaped backoff
// (30s→1h, cap 10 attempts, scale 2.0 — reused from pkg/tracking). The attempt
// number is monotonic per event_id; next_retry_at = now + backoff(attempt-1),
// mirroring RetryQueueDB.UpdateAttempt. The attempt is CAPPED at the intended
// ceiling (DefaultMaxAttempts=10) so a chronically-failing row cannot grow an
// unbounded number of delivery_attempts rows — at the ceiling the (event_id,
// attempt) INSERT OR IGNORE is a no-op. Best-effort: a bookkeeping failure never
// blocks the drain (the evidence row itself is untouched — write-once).
func recordBackoff(store *outbox.Store, eventID string, httpStatus int, errMsg string) {
	prior, _ := store.Attempts(eventID)
	attempt := len(prior) + 1
	if attempt > tracking.DefaultMaxAttempts {
		attempt = tracking.DefaultMaxAttempts // ceiling: do not accrue rows past the cap
	}
	now := syncNow().UTC()
	delay := syncBackoff(attempt - 1)
	next := now.Add(delay).Format(time.RFC3339)
	_ = store.RecordAttempt(eventID, attempt, now.Format(time.RFC3339), httpStatus, errMsg, next)
}

// syncBackoff computes min(base * scale^attempt, maxDelay) using the shared
// pkg/tracking defaults, so the sync agent and the ER1 retry queue back off
// identically. attempt is 0-indexed (attempt 0 → base delay).
func syncBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > tracking.DefaultMaxAttempts {
		attempt = tracking.DefaultMaxAttempts
	}
	delay := float64(tracking.DefaultBaseDelay)
	for i := 0; i < attempt; i++ {
		delay *= tracking.DefaultBackoffScale
		if delay >= float64(tracking.DefaultMaxDelay) {
			return tracking.DefaultMaxDelay
		}
	}
	if delay > float64(tracking.DefaultMaxDelay) {
		return tracking.DefaultMaxDelay
	}
	return time.Duration(delay)
}

// reVerifyRow reconstructs the canonical bytes from the row's payload_json and
// asserts (a) the recomputed sha256 equals the stored payload_hash column — the
// column↔payload divergence tamper check (R-2.6), which needs no key — and
// (b) when the device pubkey is resolvable, the detached signature verifies. A
// row that fails EITHER available check is not shipped.
func reVerifyRow(home string, ev outbox.Event) bool {
	if strings.TrimSpace(ev.PayloadJSON) == "" {
		return false // payload retention-nulled: nothing to ship
	}
	var rec skillgate.InvocationRecord
	if err := json.Unmarshal([]byte(ev.PayloadJSON), &rec); err != nil {
		return false
	}
	canon, err := skillgate.CanonicalizeInvocationRecord(&rec)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(sum[:]) != ev.PayloadHash {
		return false // column↔payload divergence — tamper signal
	}
	if pub, ok := syncResolveDevicePub(home, rec.DeviceKeyID); ok {
		if !skillgate.VerifyInvocationRecord(&rec, pub, base64.StdEncoding.DecodeString) {
			return false
		}
	}
	return true
}
