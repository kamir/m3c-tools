package main

// `skillctl peer` — SPEC-0359 D2 peer discovery + trust pinning.
//
//	peer add <name> <locator> --pubkey <b64> --pin sha256:<hex> [--floor green|yellow]
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
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(stderr, "peer add: <name> and <locator> are required")
		printPeerUsage(stderr)
		return 2
	}
	name, locator := fs.Arg(0), fs.Arg(1)
	if artifact.SchemeOf(locator) == "" && !registry.IsER1Registry(locator) {
		fmt.Fprintf(stderr, "peer add: %q is not a recognized registry locator (gitlab://…, github://…, local://…, er1://…)\n", locator)
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
	pe := registry.Peer{Name: name, Locator: locator, PubKeyB64: *pubB64, Fingerprint: *pin, GovernanceMinimum: *floor}
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
	fmt.Fprintf(stdout, "  pull with:   skillctl pull --registry %s\n", locator)
	return 0
}

func runPeerLs(args []string, stdout, stderr io.Writer) int {
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "peer ls: %v\n", err)
		return 1
	}
	if len(peers.Peers) == 0 {
		fmt.Fprintln(stdout, "(no pinned peers — add one with `skillctl peer add`)")
		return 0
	}
	fmt.Fprintf(stdout, "%-16s %-40s %-8s %s\n", "name", "locator", "floor", "fingerprint")
	fmt.Fprintln(stdout, strings.Repeat("-", 110))
	for _, pe := range peers.Peers {
		fmt.Fprintf(stdout, "%-16s %-40s %-8s %s\n", pe.Name, pe.Locator, strOr(pe.GovernanceMinimum, "green"), pe.Fingerprint)
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
			fmt.Fprintf(stdout, "    ✗ %s@%s  %v — %s\n", sk.Name, sk.Version, sk.Gate, sk.Detail)
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
