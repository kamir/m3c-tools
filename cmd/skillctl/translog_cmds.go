package main

// SPEC-0278 L1 CLI: `skillctl translog <verb>`.
//
// Verbs:
//
//	append <type> <digest> [--subject S] [--log PATH] [--log-id ID]
//	    Append an event (admit|attest|revoke|agentid-issue|agentid-revoke)
//	    to the local append-only transparency log. Logs the DIGEST of an
//	    already-signed event — data stays OFF the log (SPEC-0278 §5).
//
//	sth [--log PATH] [--log-id ID] [--key PATH.priv]
//	    Show the current tree head. With --key, sign it into an STH (JSON).
//
//	prove <digest> [--log PATH] [--log-id ID] --key PATH.priv [--out FILE]
//	    Emit a portable inclusion RECEIPT (entry + proof + signed STH) for
//	    the event with the given digest.
//
//	verify --receipt FILE --log-pubkey PATH.pub
//	    OFFLINE: verify an inclusion receipt against a pinned log public key.
//	    No network. Exit 0 ok | 23 not-included/invalid | 1 other | 2 usage.
//
//	consistency --sth1 FILE --sth2 FILE --proof FILE --log-pubkey PATH.pub
//	    Verify a consistency proof between two signed heads (append-only /
//	    anti-rewrite). DETECTS a log that dropped or rewrote an entry.
//
//	witness --sths FILE --log-pubkey PATH.pub
//	    Cross-witness a JSON array of STHs for split-view / equivocation.
//	    DETECTS two same-size heads with different roots. Closes SPEC-0279
//	    AC4 (the cross-company STH freshness / split-view check).
//
// Honesty: L1 makes equivocation/withholding DETECTABLE, not impossible.
// Only the DEFERRED L2 (BFT consortium ledger) could PREVENT a single
// operator from equivocating. The Kafka/SPEC-0190 gossip transport is also
// DEFERRED — these verbs operate on locally-held STHs/proofs.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
)

// bestEffortTranslogAppend appends one event to the LOCAL transparency log
// at the existing admit/attest/revoke/agentid emit points. It is
// BEST-EFFORT and MUST NEVER change the primary decision: the caller has
// ALREADY produced and (for attest/revoke) posted the signed event; we only
// mirror its DIGEST into the local append-only log so the verifier can later
// prove inclusion. Any error is written to stderr as a non-fatal note and
// swallowed — mirroring the SPEC-0202 audit-trail pattern.
//
// Disabled by default unless the operator opts in via M3C_TRANSLOG=1 (so the
// existing commands' behaviour and output are unchanged for users who have
// not adopted L1). When enabled, the log id defaults to "skillctl-local" or
// $M3C_TRANSLOG_ID.
func bestEffortTranslogAppend(evType translog.EventType, digest, subject string, stderr io.Writer) {
	if os.Getenv("M3C_TRANSLOG") != "1" {
		return
	}
	path, err := translog.DefaultLogFilePath()
	if err != nil {
		fmt.Fprintf(stderr, "note: transparency-log append skipped: %v\n", err)
		return
	}
	logID := os.Getenv("M3C_TRANSLOG_ID")
	if logID == "" {
		logID = "skillctl-local"
	}
	l, err := translog.OpenLog(path, logID)
	if err != nil {
		fmt.Fprintf(stderr, "note: transparency-log append skipped: %v\n", err)
		return
	}
	idx, err := l.Append(translog.LogEntry{
		Type:      evType,
		Digest:    digest,
		Timestamp: translog.FormatSTHTimestamp(time.Now()),
		Subject:   subject,
	})
	if err != nil {
		fmt.Fprintf(stderr, "note: transparency-log append failed (non-fatal): %v\n", err)
		return
	}
	fmt.Fprintf(stderr, "note: logged %s event to transparency log at index %d (tree size %d)\n", evType, idx, l.Size())
}

// splitPositionalThenFlags separates leading positional arguments (those
// that do NOT start with "-") from the trailing flag arguments. The Go
// `flag` package stops parsing at the first non-flag token, so to support
// the natural `translog append <type> <digest> --log X` ordering we pull the
// leading positionals off first and hand only the flag tail to fs.Parse.
//
// want is the exact number of leading positionals required; it returns the
// positionals, the remaining (flag) args, and ok=false if fewer than `want`
// positionals are present before the first flag.
func splitPositionalThenFlags(args []string, want int) (pos, rest []string, ok bool) {
	i := 0
	for i < len(args) && i < want {
		if len(args[i]) > 0 && args[i][0] == '-' {
			break
		}
		i++
	}
	if i < want {
		return nil, nil, false
	}
	return args[:want], args[want:], true
}

// decodeHex32 decodes a 64-char hex string into a 32-byte array, rejecting
// any other length so a malformed proof element can't be padded into shape.
func decodeHex32(s string) ([translog.HashSize]byte, error) {
	var out [translog.HashSize]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != translog.HashSize {
		return out, fmt.Errorf("is %d bytes, want %d", len(raw), translog.HashSize)
	}
	copy(out[:], raw)
	return out, nil
}

// translog-specific exit codes, layered on the generic 0/1/2. The
// "not-included" code is 23 to match the verify package's
// verify.ExitLogInclusionMissing (20/21/22 are taken by ExitSelfAttested /
// agentid-expired / ExitRevocationStale); split-view and rewrite detection
// are this subcommand's own distinct signals.
const (
	exitTranslogNotIncluded = 23 // receipt did not verify / not included
	exitTranslogSplitView   = 24 // a split view (equivocation) was DETECTED
	exitTranslogRewrite     = 25 // a consistency/rewrite violation DETECTED
)

// Package-local event-type aliases so the emit-point command files
// (attest_cmds.go, revoke_cmds.go) can call bestEffortTranslogAppend without
// each importing the translog package directly.
const (
	translogEventAttest = translog.EventAttest
	translogEventRevoke = translog.EventRevoke
	translogEventAdmit  = translog.EventAdmit
)

// runTranslog is the `skillctl translog` dispatcher.
func runTranslog(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		translogUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "append":
		return runTranslogAppend(args[1:], stdout, stderr)
	case "sth":
		return runTranslogSTH(args[1:], stdout, stderr)
	case "prove":
		return runTranslogProve(args[1:], stdout, stderr)
	case "verify":
		return runTranslogVerify(args[1:], stdout, stderr)
	case "consistency":
		return runTranslogConsistency(args[1:], stdout, stderr)
	case "witness":
		return runTranslogWitness(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		translogUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "translog: unknown verb %q\n\n", args[0])
		translogUsage(stderr)
		return exitUsage
	}
}

func translogUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl translog <verb> [args]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "SPEC-0278 L1 transparency log (RFC-6962 Merkle, stdlib-only).")
	fmt.Fprintln(w, "L1 makes equivocation/withholding DETECTABLE, not impossible;")
	fmt.Fprintln(w, "L2 (BFT consortium ledger) and L3 (public anchoring) are DEFERRED.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Verbs:")
	fmt.Fprintln(w, "  append <type> <digest>   Append an event (data stays OFF the log).")
	fmt.Fprintln(w, "  sth                      Show / sign the current tree head.")
	fmt.Fprintln(w, "  prove <digest>           Emit an offline inclusion receipt.")
	fmt.Fprintln(w, "  verify --receipt F       Offline inclusion check vs a pinned log key.")
	fmt.Fprintln(w, "  consistency ...          Verify append-only between two heads.")
	fmt.Fprintln(w, "  witness --sths F         Cross-witness STHs for a split view.")
}

// resolveLogPath returns the explicit --log or the default
// ~/.claude/skillctl/transparency-log.jsonl.
func resolveLogPath(explicit string, stderr io.Writer) (string, bool) {
	if explicit != "" {
		return explicit, true
	}
	p, err := translog.DefaultLogFilePath()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", false
	}
	return p, true
}

func runTranslogAppend(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("translog append", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subject := fs.String("subject", "", "Optional event subject (skill name, agent id, ...).")
	logPath := fs.String("log", "", "Log file path (default ~/.claude/skillctl/transparency-log.jsonl).")
	logID := fs.String("log-id", "skillctl-local", "Log id.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl translog append <type> <digest> [--subject S] [--log PATH] [--log-id ID]")
		fmt.Fprintln(stderr, "  type:   admit | attest | revoke | agentid-issue | agentid-revoke")
		fmt.Fprintln(stderr, "  digest: sha256:<64 lowercase hex> of the already-signed event")
		fs.PrintDefaults()
	}
	pos, rest, ok := splitPositionalThenFlags(args, 2)
	if !ok {
		fs.Usage()
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	evType := translog.EventType(pos[0])
	digest := pos[1]

	path, ok := resolveLogPath(*logPath, stderr)
	if !ok {
		return exitGeneric
	}
	l, err := translog.OpenLog(path, *logID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	entry := translog.LogEntry{
		Type:      evType,
		Digest:    digest,
		Timestamp: translog.FormatSTHTimestamp(time.Now()),
		Subject:   *subject,
	}
	idx, err := l.Append(entry)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "appended %s event at index %d (tree size now %d)\n", evType, idx, l.Size())
	fmt.Fprintf(stdout, "note: only the event digest is logged; the event data stays off the log.\n")
	return exitOK
}

func runTranslogSTH(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("translog sth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("log", "", "Log file path (default ~/.claude/skillctl/transparency-log.jsonl).")
	logID := fs.String("log-id", "skillctl-local", "Log id.")
	keyPath := fs.String("key", "", "Log ed25519 private key (PEM). If set, sign the head into an STH.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl translog sth [--log PATH] [--log-id ID] [--key PATH.priv]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	path, ok := resolveLogPath(*logPath, stderr)
	if !ok {
		return exitGeneric
	}
	l, err := translog.OpenLog(path, *logID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if l.Size() == 0 {
		fmt.Fprintln(stderr, "translog: log is empty; nothing to sign")
		return exitGeneric
	}
	if *keyPath == "" {
		root, err := l.Root()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "tree_size: %d\nroot_hash: %x\nlog_id:    %s\n", l.Size(), root, l.LogID())
		fmt.Fprintln(stdout, "(pass --key to sign this head into an STH)")
		return exitOK
	}
	priv, err := signing.LoadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	sth, err := l.SignHead(priv, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	out, err := json.MarshalIndent(sth, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	fmt.Fprintln(stdout, string(out))
	return exitOK
}

func runTranslogProve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("translog prove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("log", "", "Log file path (default ~/.claude/skillctl/transparency-log.jsonl).")
	logID := fs.String("log-id", "skillctl-local", "Log id.")
	keyPath := fs.String("key", "", "Log ed25519 private key (PEM) to sign the head. Required.")
	outPath := fs.String("out", "", "Write the receipt JSON to this file (default: stdout).")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl translog prove <digest> --key PATH.priv [--log PATH] [--log-id ID] [--out FILE]")
		fs.PrintDefaults()
	}
	pos, rest, ok := splitPositionalThenFlags(args, 1)
	if !ok {
		fs.Usage()
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *keyPath == "" {
		fs.Usage()
		return exitUsage
	}
	digest := pos[0]
	path, ok := resolveLogPath(*logPath, stderr)
	if !ok {
		return exitGeneric
	}
	l, err := translog.OpenLog(path, *logID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	hits := l.FindByDigest(digest)
	if len(hits) == 0 {
		fmt.Fprintf(stderr, "translog: no logged event with digest %s\n", digest)
		return exitGeneric
	}
	idx := hits[0]
	entry, err := l.EntryAt(idx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	proof, size, _, err := l.ProveInclusion(idx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	priv, err := signing.LoadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	sth, err := l.SignHead(priv, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	receipt := translog.NewReceipt(entry, idx, size, proof, sth)
	data, err := receipt.JSON()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, append(data, '\n'), 0o644); err != nil { //nolint:gosec // receipt is public
			fmt.Fprintln(stderr, err)
			return exitGeneric
		}
		fmt.Fprintf(stdout, "wrote inclusion receipt for index %d to %s\n", idx, *outPath)
		return exitOK
	}
	fmt.Fprintln(stdout, string(data))
	return exitOK
}

func runTranslogVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("translog verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	receiptPath := fs.String("receipt", "", "Inclusion receipt JSON (from `prove`). Required.")
	pubPath := fs.String("log-pubkey", "", "Pinned log ed25519 public key (PEM SPKI). Required.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl translog verify --receipt FILE --log-pubkey PATH.pub")
		fmt.Fprintln(stderr, "Offline inclusion check. Exit: 0 ok | 23 not-included | 1 other | 2 usage.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *receiptPath == "" || *pubPath == "" {
		fs.Usage()
		return exitUsage
	}
	data, err := os.ReadFile(*receiptPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	receipt, err := translog.ParseReceipt(data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitTranslogNotIncluded
	}
	pub, err := signing.LoadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if err := receipt.VerifyOffline(ed25519.PublicKey(pub)); err != nil {
		fmt.Fprintf(stderr, "NOT INCLUDED: %v\n", err)
		return exitTranslogNotIncluded
	}
	fmt.Fprintf(stdout, "OK: event included under signed tree head (size %d, log %s).\n",
		receipt.STH.TreeSize, receipt.STH.LogID)
	fmt.Fprintln(stdout, "note: this proves the event is committed under a head you trust;")
	fmt.Fprintln(stdout, "it makes later withholding/equivocation detectable, not impossible.")
	return exitOK
}

func runTranslogConsistency(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("translog consistency", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sth1Path := fs.String("sth1", "", "Earlier (smaller) STH JSON. Required.")
	sth2Path := fs.String("sth2", "", "Later (larger) STH JSON. Required.")
	proofPath := fs.String("proof", "", "Consistency proof JSON (array of hex hashes). Required.")
	pubPath := fs.String("log-pubkey", "", "Pinned log ed25519 public key (PEM SPKI). Required.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl translog consistency --sth1 F --sth2 F --proof F --log-pubkey PATH.pub")
		fmt.Fprintln(stderr, "Verifies the later head is a pure append of the earlier (anti-rewrite).")
		fmt.Fprintln(stderr, "Exit: 0 ok | 25 rewrite-detected | 1 other | 2 usage.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *sth1Path == "" || *sth2Path == "" || *proofPath == "" || *pubPath == "" {
		fs.Usage()
		return exitUsage
	}
	pub, err := signing.LoadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	s1, err := readSTHFile(*sth1Path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	s2, err := readSTHFile(*sth2Path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	// Both heads must be authentic (signed by the pinned key) before we
	// trust their roots.
	if err := translog.VerifySTH(ed25519.PublicKey(pub), s1); err != nil {
		fmt.Fprintf(stderr, "sth1 invalid: %v\n", err)
		return exitGeneric
	}
	if err := translog.VerifySTH(ed25519.PublicKey(pub), s2); err != nil {
		fmt.Fprintf(stderr, "sth2 invalid: %v\n", err)
		return exitGeneric
	}
	proof, err := readProofFile(*proofPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	r1, err := s1.RootBytes()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	r2, err := s2.RootBytes()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if err := translog.VerifyConsistency(s1.TreeSize, s2.TreeSize, r1, r2, proof); err != nil {
		fmt.Fprintf(stderr, "REWRITE DETECTED: the later head is NOT a pure append: %v\n", err)
		return exitTranslogRewrite
	}
	fmt.Fprintf(stdout, "OK: size %d -> %d is append-only (no entry was dropped or rewritten).\n", s1.TreeSize, s2.TreeSize)
	return exitOK
}

func runTranslogWitness(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("translog witness", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sthsPath := fs.String("sths", "", "JSON array of STHs from different witnesses. Required.")
	pubPath := fs.String("log-pubkey", "", "Pinned log ed25519 public key (PEM SPKI). Required.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl translog witness --sths FILE --log-pubkey PATH.pub")
		fmt.Fprintln(stderr, "Cross-witness STHs for a split view (equivocation).")
		fmt.Fprintln(stderr, "Exit: 0 consistent | 24 split-view-detected | 1 other | 2 usage.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *sthsPath == "" || *pubPath == "" {
		fs.Usage()
		return exitUsage
	}
	data, err := os.ReadFile(*sthsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	var sths []translog.STH
	if err := json.Unmarshal(data, &sths); err != nil {
		fmt.Fprintf(stderr, "translog: parse STH array: %v\n", err)
		return exitGeneric
	}
	pub, err := signing.LoadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	// Verify each STH against the pinned key — an unsigned/unpinned head is
	// not admissible evidence and could otherwise hide or fabricate a split.
	for i, s := range sths {
		if err := translog.VerifySTH(ed25519.PublicKey(pub), s); err != nil {
			fmt.Fprintf(stderr, "witness[%d] STH invalid under pinned key: %v\n", i, err)
			return exitGeneric
		}
	}
	conflict, err := translog.VerifyWitnessConsistency(sths)
	if errors.Is(err, translog.ErrSplitView) {
		fmt.Fprintf(stderr, "SPLIT VIEW DETECTED: %v\n", conflict)
		fmt.Fprintln(stderr, "The log equivocated: two heads at the same size with different roots.")
		fmt.Fprintln(stderr, "Both STHs are independently signed = non-repudiable evidence.")
		return exitTranslogSplitView
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "OK: %d witnessed STH(s) are consistent — no split view detected.\n", len(sths))
	fmt.Fprintln(stdout, "note: L1 detects equivocation; only L2 (deferred BFT ledger) prevents it.")
	return exitOK
}

// readSTHFile loads and JSON-decodes a single STH.
func readSTHFile(path string) (translog.STH, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return translog.STH{}, err
	}
	var s translog.STH
	if err := json.Unmarshal(data, &s); err != nil {
		return translog.STH{}, fmt.Errorf("parse STH %s: %w", path, err)
	}
	return s, nil
}

// readProofFile loads a JSON array of hex hashes into fixed-size nodes.
func readProofFile(path string) ([][translog.HashSize]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	var hexes []string
	if err := json.Unmarshal(data, &hexes); err != nil {
		return nil, fmt.Errorf("parse proof %s: %w", path, err)
	}
	out := make([][translog.HashSize]byte, len(hexes))
	for i, h := range hexes {
		raw, err := decodeHex32(h)
		if err != nil {
			return nil, fmt.Errorf("proof[%d]: %w", i, err)
		}
		out[i] = raw
	}
	return out, nil
}
