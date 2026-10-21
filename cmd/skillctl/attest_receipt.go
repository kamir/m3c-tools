package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const attestReceiptSchema = "m3c.skillctl.attestation-receipt/v1"

// attestReceipt records registry acceptance of the actual signed POST message.
// It does not establish reviewer independence or verify the installed bundle.
type attestReceipt struct {
	Schema          string `json:"schema"`
	Operation       string `json:"operation"`
	OK              bool   `json:"ok"`
	ExitCode        int    `json:"exit_code"`
	AttestationID   string `json:"attestation_id,omitempty"`
	BundleDigest    string `json:"bundle_digest,omitempty"`
	GovernanceLevel string `json:"governance_level,omitempty"`
	ReviewerID      string `json:"reviewer_id,omitempty"`
	AttestedAt      string `json:"attested_at,omitempty"`
	Error           string `json:"error,omitempty"`
}

func renderAttestReceipt(enabled *bool, receipt *attestReceipt, code *int, diagnostic *strings.Builder, stdout, stderr io.Writer) {
	if !*enabled {
		return
	}
	receipt.Schema = attestReceiptSchema
	receipt.Operation = "attest"
	receipt.ExitCode = *code
	receipt.OK = *code == exitOK
	if !receipt.OK {
		receipt.Error = strings.TrimSpace(diagnostic.String())
		if receipt.Error == "" {
			receipt.Error = "attestation submission failed"
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(receipt); err != nil {
		fmt.Fprintf(stderr, "skillctl attest: write JSON receipt: %v\n", err)
		*code = exitGeneric
	}
}

// decodeAttestResponse rejects ambiguous receipts while retaining optional server fields.
func decodeAttestResponse(raw []byte) (attestResponse, error) {
	var response attestResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return response, fmt.Errorf("expected registry response object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return response, err
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return response, fmt.Errorf("invalid or duplicate registry response field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return response, err
		}
		if name == "attestation_id" {
			if err := json.Unmarshal(value, &response.AttestationID); err != nil {
				return response, err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return response, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return response, fmt.Errorf("trailing registry response data")
	}
	return response, nil
}
