//go:build darwin

// healthcheck_classifier_test.go — BUG-0124 Layer 3.
//
// Tests for classifyPLMHealthCheckError, which converts a PLM HealthCheck
// error into a short user-facing diagnostic for the menubar Projects submenu.
package main

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyPLMHealthCheckError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantSubs string // substring expected in the result
	}{
		{
			name:     "nil_error_returns_empty",
			err:      nil,
			wantSubs: "",
		},
		{
			name:     "401_invalid_key",
			err:      errors.New("ER1 API key is invalid or expired (HTTP 401)"),
			wantSubs: "ER1 key invalid (401)",
		},
		{
			name:     "403_rejected_key",
			err:      errors.New("ER1 API key is rejected (HTTP 403)"),
			wantSubs: "ER1 key rejected (403)",
		},
		{
			name:     "no_such_host",
			err:      errors.New("dial tcp: lookup onboarding.guide: no such host"),
			wantSubs: "Server unreachable",
		},
		{
			name:     "connection_refused",
			err:      errors.New("dial tcp 127.0.0.1:8081: connect: connection refused"),
			wantSubs: "Server unreachable",
		},
		{
			name:     "i/o_timeout",
			err:      errors.New("Get https://onboarding.guide/api/plm/projects: net/http: request canceled (i/o timeout)"),
			wantSubs: "Server timeout",
		},
		{
			name:     "context_deadline_exceeded",
			err:      errors.New("context deadline exceeded"),
			wantSubs: "Server timeout",
		},
		{
			name:     "x509_cert_error",
			err:      errors.New("x509: certificate signed by unknown authority"),
			wantSubs: "TLS certificate error",
		},
		{
			name:     "unknown_error_falls_through",
			err:      errors.New("something weird went wrong"),
			wantSubs: "see log",
		},
		{
			name:     "generic_5xx",
			err:      errors.New("ER1 health check returned HTTP 503"),
			wantSubs: "see log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPLMHealthCheckError(tt.err)
			if tt.err == nil {
				if got != "" {
					t.Errorf("classifyPLMHealthCheckError(nil) = %q, want empty", got)
				}
				return
			}
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.wantSubs)) {
				t.Errorf("classifyPLMHealthCheckError(%q) = %q, want substring %q",
					tt.err.Error(), got, tt.wantSubs)
			}
		})
	}
}

// TestClassifyPLMHealthCheckError_ConsistentWithPLMClient documents the
// strings the classifier matches against. If pkg/timetracking/plmclient.go's
// HealthCheck error formats change, this list must be updated AND the
// classifier's switch arms reviewed.
//
// Source-of-truth strings (as of 2026-05-08):
//   - "ER1 API key is invalid or expired (HTTP 401)"
//   - "ER1 API key is rejected (HTTP 403)"
//   - "ER1 health check returned HTTP %d"
//   - "health check request failed: %w" (wraps net errors)
func TestClassifyPLMHealthCheckError_ConsistentWithPLMClient(t *testing.T) {
	// These are the literal error strings PLMClient.HealthCheck() emits.
	// If any return "PLM auth check failed — see log" instead of a
	// targeted message, the classifier has drifted from its source.
	cases := map[string]string{
		"ER1 API key is invalid or expired (HTTP 401)": "ER1 key invalid (401)",
		"ER1 API key is rejected (HTTP 403)":           "ER1 key rejected (403)",
	}
	for input, wantSubs := range cases {
		got := classifyPLMHealthCheckError(errors.New(input))
		if !strings.Contains(got, wantSubs) {
			t.Errorf("classifier drift: input=%q got=%q want substring=%q "+
				"— update classifyPLMHealthCheckError in cmd/m3c-tools/main.go",
				input, got, wantSubs)
		}
	}
}