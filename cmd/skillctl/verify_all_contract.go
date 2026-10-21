package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const sweepResultSchema = "m3c.skillctl.sweep-result/v1"

type sweepCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type sweepEntry struct {
	Skill              string       `json:"skill"`
	State              string       `json:"state"`
	Status             string       `json:"status"`
	Disposition        string       `json:"disposition"`
	Complete           bool         `json:"complete"`
	Exit               int          `json:"exit"`
	Reason             string       `json:"reason"`
	Scope              string       `json:"check_scope"`
	RevocationSource   string       `json:"revocation_source"`
	Checks             []sweepCheck `json:"checks"`
	GovernanceVerified bool         `json:"governance_verified"`
	SelfAttested       *bool        `json:"self_attested"`
	Digest             string       `json:"digest,omitempty"`
	DigestSource       string       `json:"digest_source,omitempty"`
	DigestVerified     bool         `json:"digest_verified"`
	QuarantinePath     string       `json:"quarantine_path,omitempty"`
	ActionError        string       `json:"action_error,omitempty"`
}

type sweepReport struct {
	Schema                string       `json:"schema"`
	Operation             string       `json:"operation"`
	OK                    bool         `json:"ok"`
	Complete              bool         `json:"complete"`
	ExitCode              int          `json:"exit_code"`
	SkillsDir             string       `json:"skills_dir"`
	Total                 int          `json:"total"`
	Verified              int          `json:"verified"`
	Invalid               int          `json:"invalid"`
	Quarantined           int          `json:"quarantined"`
	QuarantineCandidates  int          `json:"quarantine_candidates"`
	Unverified            int          `json:"unverified"`
	Skipped               int          `json:"skipped"`
	RootsError            string       `json:"roots_error,omitempty"`
	RevocationUnavailable string       `json:"revocation_unavailable,omitempty"`
	Error                 string       `json:"error,omitempty"`
	Entries               []sweepEntry `json:"entries"`
}

func newSweepEntry(name, source string) sweepEntry {
	return sweepEntry{Skill: name, State: "unverified", Status: "incomplete", Disposition: "unchanged", Scope: "not_checked", RevocationSource: source, Checks: []sweepCheck{
		{"content_binding", "not_checked"}, {"trust_chain", "not_checked"}, {"governance", "not_checked"}, {"dependencies", "not_checked"}, {"revocation", "not_checked"},
	}}
}

func setSweepCheck(entry *sweepEntry, name, status string) {
	for i := range entry.Checks {
		if entry.Checks[i].Name == name {
			entry.Checks[i].Status = status
			return
		}
	}
}

// inspectSweepBundle identifies actual bytes only. Authentication happens later.
func inspectSweepBundle(path string) (string, map[string]any, error) {
	raw, err := signing.ComputeBundleDigest(path)
	if err != nil {
		return "", nil, err
	}
	digest := "sha256:" + hex.EncodeToString(raw[:])
	manifest, err := verify.ReadDigestVerifiedManifest(path, digest)
	return digest, manifest, err
}

func sweepRevocationSource(home string, online bool, err error) string {
	if err != nil {
		return "unavailable"
	}
	if online {
		return "online"
	}
	cached, fresh := readRevokedCache(home, revokedCacheTTL)
	if fresh && graceAuthenticated(home, cached) {
		return "cached"
	}
	// Gossip can deny a digest, but absence from gossip proves no clean state.
	return "unconfirmed"
}

func completeSweepVerification(entry *sweepEntry, verdict sweepVerification, manifest map[string]any) {
	entry.State, entry.Scope, entry.Exit = "verified", verdict.scope, exitOK
	entry.Status, entry.Complete = "valid", true
	entry.Reason = "verified under " + verdict.scope
	switch verdict.scope {
	case "online_trust_chain", "offline_trust_chain":
		if verdict.result == nil || verdict.result.Digest != entry.Digest {
			entry.Status, entry.Complete, entry.Exit = "incomplete", false, exitGeneric
			entry.Reason = "verifier result does not bind the observed bundle digest"
			setSweepCheck(entry, "trust_chain", "unconfirmed")
		} else {
			setSweepCheck(entry, "content_binding", "pass")
			setSweepCheck(entry, "governance", "pass")
			entry.DigestVerified = true
			entry.GovernanceVerified = verdict.result.GovernanceVerified
			entry.SelfAttested = verdict.result.SelfAttested
			entry.Reason = verdict.result.ChainSummary
			if verdict.scope == "offline_trust_chain" {
				entry.Reason = "verified offline: " + entry.Reason
			}
			setSweepCheck(entry, "trust_chain", "pass")
		}
	case "sidecar_reanchored":
		setSweepCheck(entry, "content_binding", "pass")
		setSweepCheck(entry, "governance", "pass")
		entry.DigestVerified, entry.GovernanceVerified = true, true
		setSweepCheck(entry, "trust_chain", "pass")
	case "sidecar_legacy":
		setSweepCheck(entry, "content_binding", "pass")
		entry.Status, entry.Complete = "incomplete", false
		entry.Reason = "legacy sidecar content binding only; trust and signed governance unconfirmed"
		setSweepCheck(entry, "trust_chain", "unconfirmed")
		setSweepCheck(entry, "governance", "unconfirmed")
	default:
		entry.Status, entry.Complete = "incomplete", false
		setSweepCheck(entry, "trust_chain", "unconfirmed")
	}
	deps, hasDeps := manifest["depends_on"]
	list, isList := deps.([]any)
	if entry.DigestVerified && ((!hasDeps || deps == nil) || (isList && len(list) == 0)) {
		setSweepCheck(entry, "dependencies", "pass")
	} else {
		setSweepCheck(entry, "dependencies", "unconfirmed")
		entry.Status, entry.Complete = "incomplete", false
		entry.Reason += "; declared dependencies are not resolved"
	}
	if entry.RevocationSource == "online" || entry.RevocationSource == "cached" {
		setSweepCheck(entry, "revocation", "pass")
	} else {
		setSweepCheck(entry, "revocation", "unconfirmed")
		entry.Status, entry.Complete = "incomplete", false
		entry.Reason += "; revocation not confirmed"
	}
}

func sweepQuarantine(entry sweepEntry, home string, move bool, reason string, code int) sweepEntry {
	entry.State, entry.Status, entry.Complete, entry.Exit = "quarantined", "invalid", true, code
	entry.Reason = reason
	if entry.Scope == "not_checked" {
		setSweepCheck(&entry, "content_binding", "fail")
	} else if entry.Scope != "unmanaged_policy" && entry.Scope != "revocation_policy" {
		check := "trust_chain"
		switch code {
		case verify.ExitDigestMismatch:
			check = "content_binding"
		case verify.ExitGovernanceBelowMin, verify.ExitTenantBlocked:
			check = "governance"
		case verify.ExitDepsUnsatisfied:
			check = "dependencies"
		case exitBundleRevoked, exitRevocationStale:
			check = "revocation"
		}
		setSweepCheck(&entry, check, "fail")
	}
	entry.Disposition = "would_quarantine"
	if !move {
		entry.Reason += " (report-only; pass --quarantine to move it out)"
		return entry
	}
	dest, err := quarantineSkill(home, entry.Skill, reason, code)
	entry.QuarantinePath = dest
	if dest != "" {
		entry.Disposition = "quarantined"
	} else {
		entry.Disposition = "quarantine_failed"
	}
	if err != nil {
		entry.Complete = false
		entry.ActionError = err.Error()
		entry.Reason = "FAILED to complete quarantine: " + err.Error() + " (" + reason + ")"
	}
	return entry
}

func finishSweep(rep *sweepReport, jsonOut, quarantine bool, code *int, diagnostic string, stdout, stderr io.Writer) {
	rep.Schema, rep.Operation = sweepResultSchema, "verify_all"
	rep.Complete = *code == exitOK
	if rep.Entries == nil {
		rep.Entries = []sweepEntry{}
	}
	for _, entry := range rep.Entries {
		rep.Total++
		switch entry.Status {
		case "valid":
			rep.Verified++
		case "invalid":
			rep.Invalid++
		case "skipped":
			rep.Skipped++
		default:
			rep.Unverified++
		}
		if entry.Disposition != "unchanged" {
			rep.QuarantineCandidates++
		}
		if entry.Disposition == "quarantined" {
			rep.Quarantined++
		}
		if !entry.Complete {
			rep.Complete = false
		}
	}
	if *code != exitOK {
		rep.Error = strings.TrimSpace(diagnostic)
		if rep.Error == "" {
			rep.Error = "sweep could not complete"
		}
	}
	rep.OK = *code == exitOK && rep.Complete && rep.Invalid == 0 && rep.Unverified == 0 && rep.Skipped == 0
	if !rep.OK && *code == exitOK {
		*code = exitGeneric
	}
	if !rep.OK && rep.Error == "" {
		rep.Error = fmt.Sprintf("sweep has %d invalid, %d incomplete and %d skipped skills", rep.Invalid, rep.Unverified, rep.Skipped)
	}
	rep.ExitCode = *code
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "verify --all: write JSON result: %v\n", err)
			*code = exitGeneric
		}
		return
	}
	if rep.Total == 0 && rep.Error == "" {
		if _, err := fmt.Fprintf(stdout, "skillctl verify --all: no installed skills at %s (nothing to sweep)\n", rep.SkillsDir); err != nil {
			*code = exitGeneric
			fmt.Fprintf(stderr, "verify --all: write report: %v\n", err)
		}
		return
	}
	var text strings.Builder
	printSweepHuman(&text, *rep, quarantine)
	if _, err := io.WriteString(stdout, text.String()); err != nil {
		*code = exitGeneric
		fmt.Fprintf(stderr, "verify --all: write report: %v\n", err)
	}
}
