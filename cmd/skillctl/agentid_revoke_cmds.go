package main

// agentid_revoke_cmds.go — SPEC-0277 P1 `skillctl agentid revoke`.
//
// Writes/updates a SPEC-0276-style SIGNED revocation list keyed agent:<id>,
// reusing verify.NewSignedAgentRevocationList (the same canonical+epoch+ed25519
// machinery as the bundle list). The list is a LOCAL FILE — offline by
// construction: every `agentid verify --revocations` and every runtime gate that
// loads it enforces it with NO network, so one API-free write kills the agent
// everywhere the list reaches (SPEC-0277 §4 step 5).
//
// The signing key is the registry private key whose pubkey is PINNED in
// trust-roots (the SAME key that admits bundles / signs the bundle revocation
// list). On update we read any existing list at --out, merge the new agent id,
// and BUMP the epoch so the rollback floor (SPEC-0279 R1) cannot be defeated by
// substituting an older signed list.

import (
	"encoding/json"
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

func runAgentIDRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agentid revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reason := fs.String("reason", "", "Human-readable revocation reason (recorded in the list's issued_at metadata note; required).")
	registryURL := fs.String("registry", "", "Registry URL this list speaks for (required; matched against the pinned root).")
	keyPath := fs.String("key", "", "Registry ed25519 private key (PEM PKCS#8) to sign the list. Default: ~/.claude/skillctl-keys/author.key.")
	out := fs.String("out", "agent-revocations.json", "Path to the signed agent-revocation list (created or updated).")
	epoch := fs.Int("epoch", 0, "Epoch to stamp. 0 = auto (bump the existing list's epoch by 1, or start at 1).")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl agentid revoke <agent-id> --reason <text> --registry <url> [--key <path>] [--out <list.json>] [--epoch N]")
	}

	agentArg, rest := extractFirstPositional(args)
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	agentArg = strings.TrimSpace(agentArg)
	if agentArg == "" {
		fmt.Fprintln(stderr, "skillctl agentid revoke: <agent-id> positional argument is required.")
		fs.Usage()
		return exitUsage
	}
	// Accept either "agent:xyz" or a bare "xyz" (normalize to the scheme).
	if !strings.HasPrefix(strings.ToLower(agentArg), "agent:") {
		agentArg = "agent:" + agentArg
	}
	if strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "skillctl agentid revoke: --reason is required.")
		return exitUsage
	}
	if strings.TrimSpace(*registryURL) == "" {
		fmt.Fprintln(stderr, "skillctl agentid revoke: --registry is required (the list is bound to one registry, signed).")
		return exitUsage
	}
	if err := validateRegistryURL(strings.TrimSpace(*registryURL)); err != nil {
		fmt.Fprintf(stderr, "skillctl agentid revoke: %v\n", err)
		return exitUsage
	}

	keyFile := strings.TrimSpace(*keyPath)
	if keyFile == "" {
		keyFile = defaultAuthorKeyPath()
	}
	priv, err := signing.LoadPrivateKey(keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid revoke: load registry key %s: %v\n", keyFile, err)
		return exitGeneric
	}

	// Merge with any existing list at --out, then bump the epoch.
	existingAgents, existingEpoch := readExistingAgentRevocations(*out)
	merged := mergeAgentIDs(existingAgents, agentArg)
	newEpoch := *epoch
	if newEpoch == 0 {
		newEpoch = existingEpoch + 1
	}

	list, err := verify.NewSignedAgentRevocationList(
		strings.TrimSpace(*registryURL),
		signing.FormatAttestationTimestamp(time.Now()),
		newEpoch,
		merged,
		priv,
	)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid revoke: sign list: %v\n", err)
		return exitGeneric
	}

	blob, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "skillctl agentid revoke: marshal: %v\n", err)
		return exitGeneric
	}
	if err := os.WriteFile(*out, append(blob, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "skillctl agentid revoke: write %s: %v\n", *out, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "revoked %s (reason: %s) — list now has %d agent(s), epoch %d → %s\n",
		agentid.NormalizeID(agentArg), strings.TrimSpace(*reason), len(merged), newEpoch, *out)
	fmt.Fprintln(stdout, "enforced OFFLINE by `agentid verify --revocations` and the SPEC-0247 runtime gate.")
	return exitOK
}

// readExistingAgentRevocations reads the revoked agents + epoch from an existing
// list file. A missing/unparseable file is a fresh start (nil, 0) — we don't
// fail revocation because the operator pointed at a new path.
func readExistingAgentRevocations(path string) ([]string, int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0
	}
	var list verify.AgentRevocationList
	if json.Unmarshal(data, &list) != nil {
		return nil, 0
	}
	return list.RevokedAgents, list.Epoch
}

// mergeAgentIDs appends id to agents (de-dup happens in the canonical normalizer).
func mergeAgentIDs(agents []string, id string) []string {
	return append(append([]string{}, agents...), id)
}
