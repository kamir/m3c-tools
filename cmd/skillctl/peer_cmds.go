package main

// `skillctl peer`: SPEC-0359 D2 peer discovery + trust pinning.
//
//	peer add <name> <locator> --pubkey <b64> --pin sha256:<hex> [--floor green|yellow]
//	                          [--signer <reviewer-id>:<b64>]... [--quorum <n>]
//	peer ls
//	peer verify <name>          # dry-run the §7 gauntlet against the peer's pinned key
//	peer rm <name>
//
// A peer is a named pinned trust-root keyed by its registry locator. `pull
// --registry <locator>` then verifies against the peer's key. Fingerprint is
// REQUIRED (no trust-on-first-use): the operator confirms the sha256:hex pin
// out-of-band, and add refuses unless sha256(pubkey) matches it.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// peersConfigPath overrides the peer-store location in tests ("" → default).
var peersConfigPath string

func runPeer(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printPeerUsage(stderr)
		return 2
	}
	switch args[0] {
	case "add":
		return runPeerAdd(args[1:], stdout, stderr)
	case "ls", "list":
		return runPeerLs(args[1:], stdout, stderr)
	case "verify":
		return runPeerVerify(args[1:], stdout, stderr)
	case "rm", "remove":
		return runPeerRm(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printPeerUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "peer: unknown subcommand %q\n", args[0])
		printPeerUsage(stderr)
		return 2
	}
}

func printPeerUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl peer <add|ls|verify|rm>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  add <name> <locator> --pubkey <b64> --pin sha256:<hex> [--floor green|yellow]")
	fmt.Fprintln(w, "        Pin a peer's registry + signing key. The pin is verified out-of-band;")
	fmt.Fprintln(w, "        add refuses unless sha256(pubkey) == the pin (no trust-on-first-use).")
	fmt.Fprintln(w, "  ls    List pinned peers (name, locator, fingerprint, floor).")
	fmt.Fprintln(w, "  verify <name>")
	fmt.Fprintln(w, "        Dry-run the §7 gauntlet against the peer's registry + pinned key;")
	fmt.Fprintln(w, "        report what would pass/fail. Installs nothing.")
	fmt.Fprintln(w, "  rm <name>   Remove a pinned peer.")
}

func runPeerAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("peer add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubB64 := fs.String("pubkey", "", "Peer's ed25519 public key, base64 (raw 32 bytes).")
	pin := fs.String("pin", "", "Peer's trust-root fingerprint sha256:<hex> (verified out-of-band; REQUIRED).")
	floor := fs.String("floor", "green", "governance_minimum for this peer: green | yellow.")
	contributes := fs.Bool("contributes-revokes", false, "Union this peer's SIGNED revoke events into the local revoked set (`revoke feed --gossip`). Set ONLY for a governance-trusted peer: bounds revoke-DoS.")
	var signers multiFlag
	fs.Var(&signers, "signer", "Reviewer whose attestations count for this peer, as <reviewer-id>:<pubkey_b64> (repeatable). Omit when the publisher and the reviewer are the same key.")
	quorum := fs.Int("quorum", 0, "Number of DISTINCT pinned signers that must attest at or above the floor (default 1). Requires at least that many --signer entries.")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(stderr, "peer add: <name> and <locator> are required")
		printPeerUsage(stderr)
		return 2
	}
	name, locator := fs.Arg(0), fs.Arg(1)
	if registry.IsER1Registry(locator) || locator == "self" {
		// er1://… and `self` always verify against your OWN trust-roots
		// (resolvePullTrustRoots sends them to LoadSelfTrustRoots verbatim), so a
		// peer pin there would be a silent no-op, reject it rather than mislead.
		fmt.Fprintln(stderr, "peer add: er1://… and \"self\" are not peers, they always verify against your own trust-roots. Pin a gitlab://, github://, local:// or oci:// registry instead.")
		return 2
	}
	if artifact.SchemeOf(locator) == "" {
		fmt.Fprintf(stderr, "peer add: %q is not a recognized registry locator (gitlab://…, github://…, local://…, oci://…)\n", locator)
		return 2
	}
	if strings.TrimSpace(*pubB64) == "" || strings.TrimSpace(*pin) == "" {
		fmt.Fprintln(stderr, "peer add: --pubkey and --pin are both required (fingerprint-required, no TOFU)")
		return 2
	}
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "peer add: %v\n", err)
		return 1
	}
	parsed, perr := parseSignerFlags(signers)
	if perr != nil {
		fmt.Fprintf(stderr, "peer add: %v\n", perr)
		return 2
	}
	if *quorum > 1 && len(parsed) < *quorum {
		fmt.Fprintf(stderr, "peer add: --quorum %d needs at least %d --signer entries, got %d\n", *quorum, *quorum, len(parsed))
		return 2
	}
	pe := registry.Peer{
		Name: name, Locator: locator, PubKeyB64: *pubB64, Fingerprint: *pin,
		GovernanceMinimum: *floor, ContributesRevokes: *contributes,
		GovernanceQuorum: *quorum, Signers: parsed,
	}
	if err := peers.AddPeer(pe); err != nil {
		fmt.Fprintf(stderr, "peer add: %v\n", err)
		return 1
	}
	if err := peers.Save(peersConfigPath); err != nil {
		fmt.Fprintf(stderr, "peer add: save: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "pinned peer %q → %s\n", name, locator)
	fmt.Fprintf(stdout, "  fingerprint: %s (matched)\n", pe.Fingerprint)
	if len(pe.Signers) > 0 {
		for _, sg := range pe.Signers {
			fmt.Fprintf(stdout, "  signer:      %s\n", sg.ReviewerID)
		}
		fmt.Fprintf(stdout, "  quorum:      %d of %d pinned signer(s)\n", maxInt(pe.GovernanceQuorum, 1), len(pe.Signers))
	} else {
		fmt.Fprintln(stdout, "  signer:      (none pinned: only this registry key may attest)")
	}
	fmt.Fprintf(stdout, "  pull with:   skillctl pull --registry %s\n", locator)
	return 0
}

// parseSignerFlags turns --signer <reviewer-id>:<pubkey_b64> into pinned signers.
// The id is split on the LAST colon, because a reviewer id legitimately carries
// one (id:alice@org) while base64 never does.
func parseSignerFlags(raw []string) ([]registry.Signer, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]registry.Signer, 0, len(raw))
	for _, r := range raw {
		i := strings.LastIndex(r, ":")
		if i <= 0 || i == len(r)-1 {
			return nil, fmt.Errorf("--signer %q is not <reviewer-id>:<pubkey_b64>", r)
		}
		id, key := strings.TrimSpace(r[:i]), strings.TrimSpace(r[i+1:])
		if id == "" || key == "" {
			return nil, fmt.Errorf("--signer %q is not <reviewer-id>:<pubkey_b64>", r)
		}
		out = append(out, registry.Signer{ReviewerID: id, PubKeyB64: key})
	}
	return out, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func runPeerLs(args []string, stdout, stderr io.Writer) int {
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "peer ls: %v\n", err)
		return 1
	}
	if len(peers.Peers) == 0 {
		fmt.Fprintln(stdout, "(no pinned peers: add one with `skillctl peer add`)")
		return 0
	}
	fmt.Fprintf(stdout, "%-16s %-40s %-8s %s\n", "name", "locator", "floor", "fingerprint")
	fmt.Fprintln(stdout, strings.Repeat("-", 110))
	for _, pe := range peers.Peers {
		fmt.Fprintf(stdout, "%-16s %-40s %-8s %s\n", pe.Name, pe.Locator, strOr(pe.GovernanceMinimum, "green"), pe.Fingerprint)
		for _, sg := range pe.Signers {
			fmt.Fprintf(stdout, "%-16s   signer %s\n", "", sg.ReviewerID)
		}
	}
	return 0
}

func runPeerVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "peer verify: <name> required")
		return 2
	}
	name := args[0]
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "peer verify: %v\n", err)
		return 1
	}
	pe, ok := peers.FindPeerByName(name)
	if !ok {
		fmt.Fprintf(stderr, "peer verify: no peer named %q\n", name)
		return 1
	}
	tr, err := pe.AsTrustRoots()
	if err != nil {
		fmt.Fprintf(stderr, "peer verify: %v\n", err)
		return 1
	}
	be, err := artifact.Open(pe.Locator, artifact.OpenOptions{Creds: artifactauth.New()})
	if err != nil {
		fmt.Fprintf(stderr, "peer verify: open %s: %v\n", pe.Locator, err)
		return 1
	}
	defer be.Close()
	res, err := registry.PullBundlesFromBackend(context.Background(), be, tr, registry.PullOpts{})
	if err != nil {
		fmt.Fprintf(stderr, "peer verify: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "peer %q (%s)  gov-min=%s  fp=%s\n", pe.Name, pe.Locator, tr.GovernanceMinimum, pe.Fingerprint)
	fmt.Fprintf(stdout, "  would-verify (pass §7 gauntlet): %d\n", len(res.Staged))
	for _, s := range res.Staged {
		fmt.Fprintf(stdout, "    ✓ %s@%s  gov=%s\n", s.Name, s.Version, s.Governance)
	}
	if len(res.Skipped) > 0 {
		fmt.Fprintf(stdout, "  rejected: %d\n", len(res.Skipped))
		for _, sk := range res.Skipped {
			fmt.Fprintf(stdout, "    ✗ %s@%s  %v: %s\n", sk.Name, sk.Version, sk.Gate, sk.Detail)
		}
	}
	if len(res.Staged) == 0 {
		return 1 // nothing verified against this peer's key
	}
	return 0
}

func runPeerRm(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "peer rm: <name> required")
		return 2
	}
	name := args[0]
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "peer rm: %v\n", err)
		return 1
	}
	if !peers.RemovePeer(name) {
		fmt.Fprintf(stderr, "peer rm: no peer named %q\n", name)
		return 1
	}
	if err := peers.Save(peersConfigPath); err != nil {
		fmt.Fprintf(stderr, "peer rm: save: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "removed peer %q\n", name)
	return 0
}
