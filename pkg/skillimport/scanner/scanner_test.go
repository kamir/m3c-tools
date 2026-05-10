package scanner

import (
	"path/filepath"
	"testing"
)

func mustScan(t *testing.T, fixture string) *Report {
	t.Helper()
	dir := filepath.Join("testdata", fixture)
	rep, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan(%s): %v", dir, err)
	}
	if rep == nil {
		t.Fatalf("Scan returned nil report")
	}
	return rep
}

func hasRule(rep *Report, rule string) bool {
	for _, f := range rep.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestScan_Clean(t *testing.T) {
	rep := mustScan(t, "clean")
	if rep.Verdict != VerdictClean {
		t.Errorf("Verdict = %q, want clean (%v)", rep.Verdict, rep.Findings)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(rep.Findings), rep.Findings)
	}
}

func TestScan_R101_MissingGovernance(t *testing.T) {
	rep := mustScan(t, "r101-violator")
	if !hasRule(rep, "R-101") {
		t.Errorf("expected R-101 finding; got %v", rep.Findings)
	}
	if rep.Verdict != VerdictWarn {
		t.Errorf("Verdict = %q, want warn (R-101 is high)", rep.Verdict)
	}
}

func TestScan_R102_LongDescription(t *testing.T) {
	rep := mustScan(t, "r102-violator")
	if !hasRule(rep, "R-102") {
		t.Errorf("expected R-102 finding; got %v", rep.Findings)
	}
	// R-102 is medium → should NOT push above clean unless paired with high.
	// This fixture has valid governance so the only finding is R-102.
	if rep.Verdict != VerdictClean {
		t.Errorf("Verdict = %q, want clean (R-102 alone is medium)", rep.Verdict)
	}
}

func TestScan_R201_DangerousSideEffect(t *testing.T) {
	rep := mustScan(t, "r201-violator")
	if !hasRule(rep, "R-201") {
		t.Errorf("expected R-201 finding; got %v", rep.Findings)
	}
	if rep.Verdict != VerdictRefuse {
		t.Errorf("Verdict = %q, want refuse (R-201 is critical)", rep.Verdict)
	}
	if !rep.HasRefuse() {
		t.Errorf("HasRefuse() = false, want true")
	}
}

func TestScan_R202_SuspiciousDep(t *testing.T) {
	rep := mustScan(t, "r202-violator")
	if !hasRule(rep, "R-202") {
		t.Errorf("expected R-202 finding; got %v", rep.Findings)
	}
	if rep.Verdict != VerdictRefuse {
		t.Errorf("Verdict = %q, want refuse (R-202 is critical)", rep.Verdict)
	}
}

func TestScan_R301_UnregisteredSource(t *testing.T) {
	rep := mustScan(t, "r301-violator")
	if !hasRule(rep, "R-301") {
		t.Errorf("expected R-301 finding; got %v", rep.Findings)
	}
	// R-301 is medium → verdict stays clean if no other findings.
	if rep.Verdict != VerdictClean {
		t.Errorf("Verdict = %q, want clean (R-301 alone is medium)", rep.Verdict)
	}
}

func TestScan_Empty(t *testing.T) {
	rep := mustScan(t, "empty")
	if rep.Verdict != VerdictClean {
		t.Errorf("Verdict = %q, want clean", rep.Verdict)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(rep.Findings))
	}
}

func TestScan_Errors(t *testing.T) {
	if _, err := Scan(""); err == nil {
		t.Errorf("Scan(\"\") = nil error, want error")
	}
	if _, err := Scan("/non/existent/path/nope"); err == nil {
		t.Errorf("Scan(non-existent) = nil error, want error")
	}
}

func TestComputeVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   []Finding
		want string
	}{
		{"empty", nil, VerdictClean},
		{"single low", []Finding{{Severity: SevLow}}, VerdictClean},
		{"single medium", []Finding{{Severity: SevMedium}}, VerdictClean},
		{"single high", []Finding{{Severity: SevHigh}}, VerdictWarn},
		{"single critical", []Finding{{Severity: SevCritical}}, VerdictRefuse},
		{"high+critical", []Finding{{Severity: SevHigh}, {Severity: SevCritical}}, VerdictRefuse},
	}
	for _, tc := range cases {
		if got := computeVerdict(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
