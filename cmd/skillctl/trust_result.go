package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const trustResultSchema = "m3c.skillctl.trust-result/v1"

// bundleVerifyResult is the shared install/verify --json shape. Stable field names so CI scripts can
// branch on `.ok` / `.exit_code` without parsing human text.
type bundleVerifyResult struct {
	Schema        string `json:"schema"`
	Operation     string `json:"operation"`
	InstallPath   string `json:"install_path,omitempty"`
	ArchivedPath  string `json:"archived_path,omitempty"`
	OK            bool   `json:"ok"`
	Digest        string `json:"digest,omitempty"`
	Author        string `json:"author_identity,omitempty"`
	RegistryKeyID string `json:"registry_key_id,omitempty"`
	Governance    string `json:"governance_level,omitempty"`
	// GovernanceVerified distinguishes signed verification from an advisory level.
	GovernanceVerified bool `json:"governance_verified"`
	// SelfAttested is nullable; false alone does not establish reviewer independence.
	SelfAttested *bool `json:"self_attested"`
	// DataScopes retains the verifier's provenance for each declaration.
	DataScopes   []verify.DeclaredScope `json:"data_scopes,omitempty"`
	ChainSummary string                 `json:"chain_summary,omitempty"`
	// Freshness is absent when no freshness policy was evaluated.
	Freshness *verify.FreshnessDecision `json:"freshness,omitempty"`
	Error     string                    `json:"error,omitempty"`
	ExitCode  int                       `json:"exit_code"`
}

func (out *bundleVerifyResult) setVerified(res *verify.VerifyResult) {
	out.Digest = res.Digest
	out.Author = res.AuthorIdentity
	out.RegistryKeyID = res.RegistryKeyID
	out.Governance = res.GovernanceLevel
	out.GovernanceVerified = res.GovernanceVerified
	out.SelfAttested = res.SelfAttested
	out.DataScopes = res.DataScopes
	out.ChainSummary = res.ChainSummary
}

// renderTrustResult is deferred before execution so early failures share the contract.
func renderTrustResult(enabled *bool, out *bundleVerifyResult, operation string, code *int, diagnostic *strings.Builder, stdout, stderr io.Writer) {
	if !*enabled {
		return
	}
	out.Schema = trustResultSchema
	out.Operation = operation
	out.ExitCode = *code
	out.OK = *code == exitOK
	if out.OK && (out.Digest == "" || out.Author == "" || out.RegistryKeyID == "" || out.Governance == "" || (operation == "install" && out.InstallPath == "")) {
		*code = exitGeneric
		out.OK = false
		out.ExitCode = *code
		out.Error = "verification did not provide the machine trust result"
	}
	if !out.OK && out.Error == "" {
		out.Error = strings.TrimSpace(diagnostic.String())
		if out.Error == "" {
			out.Error = "skillctl command failed"
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "skillctl %s: write JSON result: %v\n", operation, err)
		*code = exitGeneric
	}
}

func machineTrustResult(enabled bool, result *bundleVerifyResult) *bundleVerifyResult {
	if enabled {
		return result
	}
	return nil
}
