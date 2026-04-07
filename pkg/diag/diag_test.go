package diag

import "testing"

func TestStatusSymbols(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{OK, "\u2713"},
		{Fail, "\u2717"},
		{Warn, "!"},
		{Skipped, "\u00b7"},
	}
	for _, tt := range tests {
		if got := tt.status.Symbol(); got != tt.want {
			t.Errorf("Status(%d).Symbol() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestSectionHasFailures(t *testing.T) {
	passing := Section{
		Title: "test",
		Checks: []Check{
			{Name: "a", Status: OK, Detail: "good"},
			{Name: "b", Status: Warn, Detail: "ok-ish"},
			{Name: "c", Status: Skipped, Detail: "n/a"},
		},
	}
	if passing.HasFailures() {
		t.Error("section with OK/Warn/Skipped should not report failures")
	}

	failing := Section{
		Title: "test",
		Checks: []Check{
			{Name: "a", Status: OK, Detail: "good"},
			{Name: "b", Status: Fail, Detail: "broken"},
		},
	}
	if !failing.HasFailures() {
		t.Error("section with Fail check should report failures")
	}
}

func TestReportHasFailures(t *testing.T) {
	r := Report{
		Sections: []Section{
			{Title: "s1", Checks: []Check{{Status: OK}}},
			{Title: "s2", Checks: []Check{{Status: Warn}}},
		},
	}
	if r.HasFailures() {
		t.Error("report with only OK/Warn should not report failures")
	}

	r.Sections = append(r.Sections, Section{
		Title:  "s3",
		Checks: []Check{{Status: Fail}},
	})
	if !r.HasFailures() {
		t.Error("report with a Fail check should report failures")
	}
}

func TestCheckString(t *testing.T) {
	c := Check{Name: "DNS", Status: OK, Detail: "resolved"}
	s := c.String()
	if s == "" {
		t.Error("Check.String() should not be empty")
	}
	// Should contain the check mark symbol
	if !containsStr(s, "\u2713") {
		t.Errorf("Check.String() should contain check mark, got: %q", s)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
