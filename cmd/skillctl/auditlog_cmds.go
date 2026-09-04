package main

// auditlog_cmds.go: FR-0111, the SPEC-0403 §8 observability CLI for the audit
// event layer: `skillctl auditlog status | test | flush`.
//
// VERB CHOICE + EXIT SPACE (REQ-8.5 / REQ-8.6). The subsystem verbs live under
// their OWN stem `auditlog`, NOT under `audit`. `skillctl audit` already exists
// (SPEC-0189 §14): it computes per-skill posture verdicts with its OWN exit codes
// 0/2/3. A `skillctl audit status` next to it would be ambiguous and its exit
// codes would collide (a health finding read as a posture finding). `auditlog`
// therefore has a DISJOINT exit space: 0 = healthy / accepted / drained, 1 =
// unhealthy / not accepted / drain error. 2 is reserved for a usage/flag error, the
// universal skillctl meaning; it is orthogonal to the 0/1 health verdict and, being
// on a DIFFERENT verb, never collides with `skillctl audit`'s posture 2.
//
//	skillctl audit               posture verdicts        0/2/3   (SPEC-0189 §14)
//	skillctl auditlog status     subsystem health        0/1     (this file)
//	skillctl auditlog test        "
//	skillctl auditlog flush       "
//
// FR-0113 VERB REGISTER (REQ-8.7). `auditlog` is meant to be the FIRST entry in the
// SPEC-0404 §7-K3 verb register: a verb is REGISTERED before it is implemented, so
// the register catches a future collision. That register is NOT built yet (no
// register mechanism exists in cmd/skillctl today: verbs are a hand-rolled switch
// in main.go). This file therefore registers `auditlog` the SAME way every existing
// verb is registered (a case in main.go's dispatch) and records the dependency:
// when FR-0113's register lands, `auditlog` should be its first migrated entry. We
// deliberately do NOT build the register here (out of scope for FR-0111).
//
// REQ-8.1 / REQ-8.2 (observability without recursion). A transport failure is
// surfaced as an observable audit.sink.* / audit.queue.* event on a SEPARATE, safe
// channel (a stderr WriterSink built fresh in emitAuditlogObservability), NEVER back
// through the sink that just failed. That separation is the no-recursion guard in
// CODE: a failure reporting a sink failure cannot re-enter the failed sink.
//
// NO KAFKA (REQ-8.3 shape, but only true fields). `status` reports the fields that
// are real today: the default file sink and the local SPEC-0317 outbox/spool. It
// does NOT fabricate a broker endpoint/topic/connection: a direct Kafka sink is
// FR-0112 and EC-blocked (§7.2).

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
)

const (
	auditlogExitOK        = 0 // healthy / sink accepted / queue drained
	auditlogExitUnhealthy = 1 // unhealthy / sink refused / drain error
	auditlogExitUsage     = 2 // usage / flag error (orthogonal to the 0/1 health verdict)
)

// runAuditlog is the `skillctl auditlog <status|test|flush>` dispatcher.
func runAuditlog(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printAuditlogUsage(stderr)
		return auditlogExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return runAuditlogStatus(rest, stdout, stderr)
	case "test":
		return runAuditlogTest(rest, stdout, stderr)
	case "flush":
		return runAuditlogFlush(rest, stdout, stderr)
	case "help", "-h", "--help":
		printAuditlogUsage(stdout)
		return auditlogExitOK
	default:
		fmt.Fprintf(stderr, "skillctl auditlog: unknown subcommand %q\n\n", sub)
		printAuditlogUsage(stderr)
		return auditlogExitUsage
	}
}

func printAuditlogUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl auditlog <status|test|flush> [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  status   Report audit-subsystem health (enabled, mode, sink, outbox/spool pending, last event). Exit 0 healthy / 1 unhealthy.")
	fmt.Fprintln(w, "  test     Emit one synthetic skillctl.audit.v1 event and confirm the sink accepted it. Exit 0 accepted / 1 refused.")
	fmt.Fprintln(w, "  flush    Reconcile the local spool queue into the durable outbox (the local half of `skillctl sync`; no broker egress). Exit 0 / 1.")
}

// --- status -------------------------------------------------------------------

// auditlogStatus is the REQ-8.3-shaped health report, restricted to the fields
// that are TRUE today: there is no Kafka endpoint/topic/connection (FR-0112,
// EC-blocked), so none is reported.
type auditlogStatus struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	Sink          string `json:"sink"`
	SinkPath      string `json:"sink_path"`
	OutboxPending int    `json:"outbox_pending"`
	SpoolPending  int    `json:"spool_pending"`
	LastEvent     string `json:"last_event,omitempty"`
	Healthy       bool   `json:"healthy"`
	Detail        string `json:"detail,omitempty"`
}

func runAuditlogStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditlog status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "Emit the status as stable JSON.")
	if err := fs.Parse(args); err != nil {
		return auditlogExitUsage
	}
	home, err := userHome()
	if err != nil || home == "" {
		fmt.Fprintln(stderr, "skillctl auditlog status: cannot resolve home dir")
		return auditlogExitUnhealthy
	}
	st := gatherAuditlogStatus(home)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
	} else {
		printAuditlogStatusHuman(stdout, st)
	}
	if st.Healthy {
		return auditlogExitOK
	}
	return auditlogExitUnhealthy
}

// gatherAuditlogStatus reads the REAL subsystem state: the gate's default file
// sink plus the SPEC-0317 outbox/spool. It performs a no-network writability probe
// on the audit directory as the health signal.
func gatherAuditlogStatus(home string) auditlogStatus {
	st := auditlogStatus{
		Enabled:  true, // REQ-5.1: audit logging is on by default, no infrastructure required.
		Sink:     "file",
		SinkPath: gateAuditPath(home),
	}
	// Mode: the gate default is best-effort (REQ-6.4 decision-invariance). The one
	// live `required` escalation is require_local_audit (SPEC-0317 R-8.2), which makes
	// policy.allow fail-closed at the local spool (SPEC-0403 §6b, REQ-6.10b).
	if gateRequireLocalAudit() {
		st.Mode = "required (policy.allow, fulfilled at the local spool; SPEC-0403 §6b / SPEC-0317 R-8.2)"
	} else {
		st.Mode = "best-effort (gate default, decision-invariant; durable outbox available)"
	}

	// Health probe: is the audit trail directory writable? Pure local, no network.
	dir := verdictDir(home)
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		st.Healthy = false
		st.Detail = fmt.Sprintf("audit directory not writable: %v", mkErr)
		return st
	}

	// Outbox pending (durable rows awaiting the SEPARATE `skillctl sync` egress) and
	// spool pending (un-reconciled hot-path fallback lines). If the db cannot be
	// opened, the spool-only fallback still records, so this is DEGRADED, not
	// unhealthy: report the spool count and note the db is unavailable.
	if store, oErr := outbox.Open(home); oErr == nil {
		if n, cErr := store.PendingCount(); cErr == nil {
			st.OutboxPending = n
		}
		st.SpoolPending = countSpoolLines(store.SpoolPath())
		_ = store.Close()
	} else {
		st.SpoolPending = countSpoolLines(filepath.Join(dir, "spool.jsonl"))
		st.Detail = fmt.Sprintf("outbox db unavailable, spool-only fallback in force: %v", oErr)
	}

	st.LastEvent = lastAuditEventTimestamp(home)
	st.Healthy = true // the trail directory is writable: the subsystem can record.
	return st
}

func printAuditlogStatusHuman(w io.Writer, st auditlogStatus) {
	fmt.Fprintln(w, "skillctl auditlog status")
	fmt.Fprintf(w, "  Audit:        %s\n", enabledWord(st.Enabled))
	fmt.Fprintf(w, "  Mode:         %s\n", st.Mode)
	fmt.Fprintf(w, "  Sink:         %s\n", st.Sink)
	fmt.Fprintf(w, "  Sink path:    %s\n", st.SinkPath)
	fmt.Fprintf(w, "  Outbox:       %d pending (awaiting `skillctl sync` egress, default-OFF)\n", st.OutboxPending)
	fmt.Fprintf(w, "  Spool:        %d pending (un-reconciled; drain with `skillctl auditlog flush`)\n", st.SpoolPending)
	if st.LastEvent != "" {
		fmt.Fprintf(w, "  Last event:   %s\n", st.LastEvent)
	} else {
		fmt.Fprintf(w, "  Last event:   (none recorded)\n")
	}
	fmt.Fprintf(w, "  Health:       %s\n", healthWord(st.Healthy))
	if st.Detail != "" {
		fmt.Fprintf(w, "  Detail:       %s\n", st.Detail)
	}
	// No broker line: a Kafka sink is FR-0112 and EC-blocked (§7.2); status does not
	// fabricate an endpoint that does not exist.
}

func enabledWord(b bool) string {
	if b {
		return "ENABLED"
	}
	return "DISABLED"
}

func healthWord(b bool) string {
	if b {
		return "HEALTHY"
	}
	return "UNHEALTHY"
}

// --- test ---------------------------------------------------------------------

// auditlogTestResult is the JSON shape of `auditlog test`.
type auditlogTestResult struct {
	Accepted bool   `json:"accepted"`
	Sink     string `json:"sink"`
	Marker   string `json:"marker"`
	EventID  string `json:"event_id"`
	Error    string `json:"error,omitempty"`
}

func runAuditlogTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditlog test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "Emit the result as stable JSON.")
	if err := fs.Parse(args); err != nil {
		return auditlogExitUsage
	}
	home, err := userHome()
	if err != nil || home == "" {
		fmt.Fprintln(stderr, "skillctl auditlog test: cannot resolve home dir")
		return auditlogExitUnhealthy
	}

	marker := fmt.Sprintf("auditlog-test-%d", time.Now().UnixNano())
	ev := auditevent.New(auditevent.EventAuditSinkConnect, auditevent.OutcomeSuccess,
		auditevent.SeverityNotice, auditevent.ProducerString(version))
	ev.Message = "synthetic auditlog test event (skillctl auditlog test); NOT a real audit record"
	_ = ev.SetExt("synthetic", true)
	_ = ev.SetExt("test_marker", marker)

	// Emit through the REAL default file sink (the gate audit path) so the test
	// exercises the sink the subsystem actually uses. Best-effort dispatcher: a
	// write failure is surfaced here, never re-reported through the same sink.
	sink, sErr := auditevent.NewFileSink(gateAuditPath(home), 0)
	if sErr != nil {
		emitAuditlogObservability(stderr, auditevent.EventAuditSinkFail, auditevent.OutcomeError,
			fmt.Sprintf("could not build the audit file sink: %v", sErr), marker)
		reportAuditlogTest(stdout, *jsonOut, auditlogTestResult{Accepted: false, Marker: marker, EventID: ev.EventID, Error: sErr.Error()})
		return auditlogExitUnhealthy
	}
	d := auditevent.NewDispatcher(auditevent.DefaultRedactor(), sink)
	wErr := d.Dispatch(ev)
	_ = d.Close()

	res := auditlogTestResult{Accepted: wErr == nil, Sink: sink.Name(), Marker: marker, EventID: ev.EventID}
	if wErr != nil {
		res.Error = wErr.Error()
		// REQ-8.1: surface the transport error as an observable audit.sink.fail event
		// on a SEPARATE channel (stderr), never back through the file sink that just
		// failed (REQ-8.2: no recursion).
		emitAuditlogObservability(stderr, auditevent.EventAuditSinkFail, auditevent.OutcomeError,
			fmt.Sprintf("synthetic test event was NOT accepted by sink %q: %v", sink.Name(), wErr), marker)
		reportAuditlogTest(stdout, *jsonOut, res)
		return auditlogExitUnhealthy
	}
	reportAuditlogTest(stdout, *jsonOut, res)
	return auditlogExitOK
}

func reportAuditlogTest(w io.Writer, jsonOut bool, res auditlogTestResult) {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}
	if res.Accepted {
		fmt.Fprintf(w, "skillctl auditlog test: sink %s ACCEPTED the synthetic event (marker %s, event_id %s)\n",
			res.Sink, res.Marker, res.EventID)
		return
	}
	fmt.Fprintf(w, "skillctl auditlog test: sink did NOT accept the synthetic event (marker %s): %s\n",
		res.Marker, res.Error)
}

// --- flush --------------------------------------------------------------------

// auditlogFlushResult is the JSON shape of `auditlog flush`. SpoolBefore/After are
// the queue this command actually drains (the un-reconciled hot-path spool);
// PendingBefore/After are the durable rows still awaiting the SEPARATE network sync.
type auditlogFlushResult struct {
	SpoolBefore   int    `json:"spool_before"`
	Drained       int    `json:"drained"`
	SpoolAfter    int    `json:"spool_after"`
	PendingBefore int    `json:"outbox_pending_before"`
	PendingAfter  int    `json:"outbox_pending_after"`
	Error         string `json:"error,omitempty"`
}

// runAuditlogFlush reconciles the local spool queue into the durable outbox. It is
// the LOCAL half of `skillctl sync`: sync calls store.Reconcile() first and THEN
// does the EC-gated network egress; flush does ONLY the reconcile and stops there
// (REQ-6.10b: fulfillment is the local spool, never a broker ack). It reports
// pending-before/after and never reaches the network.
func runAuditlogFlush(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditlog flush", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "Emit the result as stable JSON.")
	if err := fs.Parse(args); err != nil {
		return auditlogExitUsage
	}
	home, err := userHome()
	if err != nil || home == "" {
		fmt.Fprintln(stderr, "skillctl auditlog flush: cannot resolve home dir")
		return auditlogExitUnhealthy
	}

	store, oErr := outbox.Open(home)
	if oErr != nil {
		fmt.Fprintf(stderr, "skillctl auditlog flush: cannot open outbox: %v\n", oErr)
		emitAuditlogObservability(stderr, auditevent.EventAuditQueueFlush, auditevent.OutcomeError,
			fmt.Sprintf("flush could not open the outbox: %v", oErr), "")
		return auditlogExitUnhealthy
	}
	defer store.Close()

	res := auditlogFlushResult{
		SpoolBefore: countSpoolLines(store.SpoolPath()),
	}
	res.PendingBefore, _ = store.PendingCount()

	drained, rErr := store.Reconcile()
	res.Drained = drained
	res.SpoolAfter = countSpoolLines(store.SpoolPath())
	res.PendingAfter, _ = store.PendingCount()

	if rErr != nil {
		res.Error = rErr.Error()
		reportAuditlogFlush(stdout, *jsonOut, res)
		// REQ-8.1: the queue-flush transport error becomes observable state on a
		// separate channel (stderr), never recursed through the outbox/spool it drained.
		emitAuditlogObservability(stderr, auditevent.EventAuditQueueFlush, auditevent.OutcomeError,
			fmt.Sprintf("spool reconcile failed after draining %d row(s): %v", drained, rErr), "")
		return auditlogExitUnhealthy
	}
	reportAuditlogFlush(stdout, *jsonOut, res)
	// REQ-8.1: a normal flush also produces the observable audit.queue.flush state.
	emitAuditlogObservability(stderr, auditevent.EventAuditQueueFlush, auditevent.OutcomeSuccess,
		fmt.Sprintf("reconciled %d spooled row(s) into the durable outbox", drained), "")
	return auditlogExitOK
}

func reportAuditlogFlush(w io.Writer, jsonOut bool, res auditlogFlushResult) {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}
	fmt.Fprintln(w, "skillctl auditlog flush")
	fmt.Fprintf(w, "  spool queue before:   %d line(s)\n", res.SpoolBefore)
	fmt.Fprintf(w, "  reconciled:           %d row(s) into the durable outbox\n", res.Drained)
	fmt.Fprintf(w, "  spool queue after:    %d line(s)\n", res.SpoolAfter)
	fmt.Fprintf(w, "  outbox pending sync:  %d -> %d  [egress is `skillctl sync`, default-OFF; a broker sink is FR-0112, EC-gated]\n",
		res.PendingBefore, res.PendingAfter)
	if res.Error != "" {
		fmt.Fprintf(w, "  error:                %s\n", res.Error)
	}
}

// --- shared helpers -----------------------------------------------------------

// emitAuditlogObservability writes one audit.sink.* / audit.queue.* observability
// event to a DEDICATED stderr WriterSink (REQ-8.1). The sink is built FRESH here and
// is a WriterSink, never the file/outbox sink under inspection, so a failure while
// reporting a sink failure cannot recurse through the failed sink (REQ-8.2, the
// no-recursion guard in code). Best-effort: its own error is dropped, never
// re-emitted.
func emitAuditlogObservability(w io.Writer, et auditevent.EventType, outcome auditevent.Outcome, msg, marker string) {
	sev := auditevent.SeverityInfo
	if outcome == auditevent.OutcomeError {
		sev = auditevent.SeverityError
	}
	ev := auditevent.New(et, outcome, sev, auditevent.ProducerString(version))
	ev.Message = msg
	_ = ev.SetExt("observability", true)
	if marker != "" {
		_ = ev.SetExt("test_marker", marker)
	}
	d := auditevent.NewDispatcher(auditevent.DefaultRedactor(), auditevent.NewWriterSink("stderr", w))
	_ = d.Dispatch(ev) // best-effort; a failure here is intentionally NOT re-reported.
	_ = d.Close()
}

// countSpoolLines counts the non-empty lines in the spool file. A missing file is
// zero (nothing spooled), never an error.
func countSpoolLines(path string) int {
	f, err := os.Open(path) // #nosec G304 -- path is the operator's own outbox spool, not attacker input.
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		if len(trimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	return n
}

// trimSpace trims ASCII whitespace from both ends of b without allocating a string.
func trimSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	j := len(b)
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r' || b[j-1] == '\n') {
		j--
	}
	return b[i:j]
}

// lastAuditEventTimestamp returns the timestamp of the most recent well-formed
// audit event in the gate audit log (the default file sink), or "" if none. It
// reads the live generation only (the newest events); a torn/malformed line is
// skipped, never fatal.
func lastAuditEventTimestamp(home string) string {
	f, err := os.Open(gateAuditPath(home)) // #nosec G304 -- operator's own audit log path.
	if err != nil {
		return ""
	}
	defer f.Close()
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e auditevent.Event
		if jErr := json.Unmarshal(sc.Bytes(), &e); jErr != nil {
			continue
		}
		if e.Timestamp != "" {
			last = e.Timestamp
		}
	}
	return last
}
