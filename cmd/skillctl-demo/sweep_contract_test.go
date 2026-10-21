package main

import (
	"encoding/json"
	"errors"
	"testing"
)

func sweepContractResult(t *testing.T, change func(map[string]any)) RunResult {
	t.Helper()
	payload := map[string]any{
		"schema": "m3c.skillctl.sweep-result/v1", "operation": "verify_all", "ok": false, "complete": false, "exit_code": 1,
		"entries": []any{map[string]any{"skill": demoSkillName, "state": "quarantined", "status": "invalid", "disposition": "quarantined", "complete": true, "exit": 10, "quarantine_path": "/synthetic/quarantine/skill"}},
	}
	if change != nil {
		change(payload)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return RunResult{Stdout: string(raw), ExitCode: 1}
}

func TestSweepVerdictAcceptsActualQuarantineAndAggregateExit(t *testing.T) {
	result := sweepContractResult(t, nil)
	state, code, ok := sweepVerdict(result, demoSkillName)
	if !ok || state != "quarantined" || code != 10 {
		t.Fatalf("state%s code%d found%v", state, code, ok)
	}
	kata := KataByID("K2")
	if got := kata.observe(result); got != 10 {
		t.Fatalf("K2 observed%d", got)
	}
}

func TestSweepVerdictRefusesUnconfirmedQuarantine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"report-only", func(p map[string]any) { p["entries"].([]any)[0].(map[string]any)["disposition"] = "would_quarantine" }},
		{"failed-move", func(p map[string]any) { p["entries"].([]any)[0].(map[string]any)["disposition"] = "quarantine_failed" }},
		{"no-destination", func(p map[string]any) { delete(p["entries"].([]any)[0].(map[string]any), "quarantine_path") }},
		{"unverified", func(p map[string]any) { p["entries"].([]any)[0].(map[string]any)["status"] = "incomplete" }},
		{"incomplete-entry", func(p map[string]any) { p["entries"].([]any)[0].(map[string]any)["complete"] = false }},
		{"missing-entry-complete", func(p map[string]any) { delete(p["entries"].([]any)[0].(map[string]any), "complete") }},
		{"missing-entry-exit", func(p map[string]any) { delete(p["entries"].([]any)[0].(map[string]any), "exit") }},
		{"wrong-schema", func(p map[string]any) { p["schema"] = "legacy" }},
		{"wrong-operation", func(p map[string]any) { p["operation"] = "verify" }},
		{"missing-complete", func(p map[string]any) { delete(p, "complete") }},
		{"false-success", func(p map[string]any) { p["ok"] = true }},
		{"mismatched-exit", func(p map[string]any) { p["exit_code"] = 0 }},
		{"duplicate-entry", func(p map[string]any) { p["entries"] = append(p["entries"].([]any), p["entries"].([]any)[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := sweepContractResult(t, tc.change)
			if _, _, ok := sweepVerdict(result, demoSkillName); ok {
				t.Fatal("unconfirmed move accepted")
			}
			if got := KataByID("K2").observe(result); got != -1 {
				t.Fatalf("K2 recorded unconfirmed beat%d", got)
			}
		})
	}
}

func TestSweepVerdictRefusesLegacyProcessSuccessAndExecFailures(t *testing.T) {
	for _, result := range []RunResult{
		{ExitCode: 0, Stdout: sweepContractResult(t, nil).Stdout},
		{ExitCode: 2, Stdout: sweepContractResult(t, nil).Stdout},
		{ExitCode: 1, Stdout: sweepContractResult(t, nil).Stdout, Err: errors.New("synthetic exec failure")},
		{ExitCode: 1, Stdout: `{"entries":[{"skill":"` + demoSkillName + `","state":"quarantined","exit":10}]}`},
		{ExitCode: 1, Stdout: "human output before JSON"},
	} {
		if _, _, ok := sweepVerdict(result, demoSkillName); ok {
			t.Fatal("incompatible process/protocol accepted")
		}
	}
}
