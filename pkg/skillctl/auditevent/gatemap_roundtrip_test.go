package auditevent

import (
	"encoding/json"
	"testing"
)

// FromGateEvent then ToGateEvent is a lossless round-trip: the gate view that
// gate-stats reconstructs equals the recorded gate line (the O6 clean-cut reader
// loses nothing).
func TestToGateEvent_RoundTrip(t *testing.T) {
	in := GateEvent{
		Ts: "2026-09-03T21:41:22Z", Source: "hook", Skill: "compliance-review",
		Decision: "deny", Reason: "revoked bundle", ExitCode: 2,
		ContentDigest: "sha256:abc", Online: true, CacheHit: false, SessionID: "sess_9",
	}
	e, err := FromGateEvent(in, "skillctl/0.4.0")
	if err != nil {
		t.Fatalf("FromGateEvent: %v", err)
	}
	got, ok := ToGateEvent(e)
	if !ok {
		t.Fatal("ToGateEvent returned ok=false for a gate event")
	}
	if got != in {
		t.Fatalf("round-trip mismatch:\n in=%+v\n got=%+v", in, got)
	}
}

// The clean-cut reader accepts every gate decision verdict and preserves the
// source vocabulary in policy.decision.
func TestToGateEvent_AllDecisions(t *testing.T) {
	for _, dec := range []string{"allow", "deny", "quarantine", "leave"} {
		e, err := FromGateEvent(GateEvent{Ts: "2026-09-03T21:41:22Z", Source: "sweep", Skill: "s", Decision: dec}, "skillctl/x")
		if err != nil {
			t.Fatalf("FromGateEvent(%s): %v", dec, err)
		}
		g, ok := ToGateEvent(e)
		if !ok || g.Decision != dec {
			t.Fatalf("decision %q did not round-trip: ok=%v got=%q", dec, ok, g.Decision)
		}
	}
}

// ToGateEvent abandons non-gate envelopes AND old flat pre-FR-0110a lines (O6).
func TestToGateEvent_RejectsNonGateAndLegacy(t *testing.T) {
	if _, ok := ToGateEvent(New(EventSkillVerify, OutcomeSuccess, SeverityInfo, "skillctl/x")); ok {
		t.Fatal("a non-gate event must not map to a GateEvent")
	}
	var flat Event
	if err := json.Unmarshal([]byte(`{"ts":"2026-09-03T00:00:00Z","decision":"allow","source":"hook"}`), &flat); err != nil {
		t.Fatal(err)
	}
	if _, ok := ToGateEvent(&flat); ok {
		t.Fatal("an old flat gate line must be abandoned by ToGateEvent (O6 clean-cut)")
	}
	if _, ok := ToGateEvent(nil); ok {
		t.Fatal("nil must be rejected")
	}
}
