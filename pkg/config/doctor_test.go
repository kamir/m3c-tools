package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func issueByCode(issues []Issue, code string) *Issue {
	for i := range issues {
		if issues[i].Code == code {
			return &issues[i]
		}
	}
	return nil
}

func TestValidateProfile_Healthy(t *testing.T) {
	p := &Profile{
		Name: "good",
		Vars: map[string]string{
			"ER1_API_URL":    "https://onboarding.guide/upload_2",
			"ER1_API_KEY":    "e25ce814-5bb6-4f99-9f08-88d603db391c",
			"ER1_CONTEXT_ID": "107677460544181387647___mft",
		},
	}
	if issues := ValidateProfile(p); len(issues) != 0 {
		t.Fatalf("expected zero issues, got %d: %+v", len(issues), issues)
	}
}

func TestValidateProfile_PlaceholderKey(t *testing.T) {
	p := &Profile{
		Name: "once-test",
		Vars: map[string]string{
			"ER1_API_URL":    "https://onboarding.guide/upload_2",
			"ER1_API_KEY":    "once-only",
			"ER1_CONTEXT_ID": "107677460544181387647___mft",
		},
	}
	got := ValidateProfile(p)
	hit := issueByCode(got, "key-placeholder")
	if hit == nil {
		t.Fatalf("want key-placeholder issue, got %+v", got)
	}
	if hit.Severity != SevFail {
		t.Errorf("placeholder must FAIL, got %s", hit.Severity)
	}
}

func TestValidateProfile_MissingContextID(t *testing.T) {
	// This is the exact shape of the broken cloud/once-test/test-customer
	// profiles in the field. ER1_CONTEXT_ID missing is a FAIL because the
	// runtime falls through to preferences.env and silently papers over it.
	p := &Profile{
		Name: "cloud",
		Vars: map[string]string{
			"ER1_API_URL": "https://onboarding.guide/upload_2",
			"ER1_API_KEY": "real-looking-key-1234567890",
		},
	}
	got := ValidateProfile(p)
	hit := issueByCode(got, "missing-required")
	if hit == nil || hit.Key != "ER1_CONTEXT_ID" {
		t.Fatalf("want missing-required for ER1_CONTEXT_ID, got %+v", got)
	}
}

func TestValidateProfile_MalformedURL(t *testing.T) {
	p := &Profile{
		Name: "broken",
		Vars: map[string]string{
			"ER1_API_URL":    "not a url",
			"ER1_API_KEY":    "real-looking-key-1234567890",
			"ER1_CONTEXT_ID": "abc___mft",
		},
	}
	got := ValidateProfile(p)
	if hit := issueByCode(got, "url-malformed"); hit == nil {
		t.Fatalf("want url-malformed issue, got %+v", got)
	}
}

func TestValidateProfile_URLSuffix(t *testing.T) {
	p := &Profile{
		Name: "wrongpath",
		Vars: map[string]string{
			"ER1_API_URL":    "https://onboarding.guide/api/v1",
			"ER1_API_KEY":    "real-looking-key-1234567890",
			"ER1_CONTEXT_ID": "abc___mft",
		},
	}
	got := ValidateProfile(p)
	hit := issueByCode(got, "url-suffix")
	if hit == nil {
		t.Fatalf("want url-suffix warn, got %+v", got)
	}
	if hit.Severity != SevWarn {
		t.Errorf("url-suffix must be WARN, got %s", hit.Severity)
	}
}

func TestValidateProfile_LoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loose.env")
	if err := os.WriteFile(path, []byte("ER1_API_URL=https://x/upload_2\nER1_API_KEY=real-looking-key-1234567890\nER1_CONTEXT_ID=a___b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Profile{
		Name: "loose",
		Path: path,
		Vars: map[string]string{
			"ER1_API_URL":    "https://x/upload_2",
			"ER1_API_KEY":    "real-looking-key-1234567890",
			"ER1_CONTEXT_ID": "a___b",
		},
	}
	got := ValidateProfile(p)
	if hit := issueByCode(got, "perms-loose"); hit == nil {
		t.Fatalf("want perms-loose, got %+v", got)
	}
}

func TestValidateAll_NoActive(t *testing.T) {
	rep := ValidateAll(nil, "")
	if !rep.HasFail() {
		t.Fatalf("empty + no active should FAIL, got %+v", rep)
	}
	found := false
	for _, i := range rep.CrossIssues {
		if i.Code == "no-active" {
			found = true
		}
	}
	if !found {
		t.Errorf("want no-active cross issue")
	}
}

func TestValidateAll_ActiveMissing(t *testing.T) {
	profiles := []Profile{{
		Name: "dev",
		Vars: map[string]string{
			"ER1_API_URL":    "https://x/upload_2",
			"ER1_API_KEY":    "real-looking-key-1234567890",
			"ER1_CONTEXT_ID": "a___b",
		},
	}}
	rep := ValidateAll(profiles, "ghost")
	found := false
	for _, i := range rep.CrossIssues {
		if i.Code == "active-missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want active-missing cross issue, got %+v", rep.CrossIssues)
	}
}

func TestValidateAll_DuplicateKey(t *testing.T) {
	shared := "real-looking-key-1234567890"
	profiles := []Profile{
		{Name: "a", Vars: map[string]string{"ER1_API_URL": "https://x/upload_2", "ER1_API_KEY": shared, "ER1_CONTEXT_ID": "a___b"}},
		{Name: "b", Vars: map[string]string{"ER1_API_URL": "https://y/upload_2", "ER1_API_KEY": shared, "ER1_CONTEXT_ID": "a___b"}},
	}
	rep := ValidateAll(profiles, "a")
	found := false
	for _, i := range rep.CrossIssues {
		if i.Code == "key-duplicate" {
			found = true
			if !strings.Contains(i.Message, "a") || !strings.Contains(i.Message, "b") {
				t.Errorf("duplicate message should mention both owners, got %q", i.Message)
			}
		}
	}
	if !found {
		t.Fatalf("want key-duplicate cross issue, got %+v", rep.CrossIssues)
	}
}

// TestValidateAll_ReproducesFieldBug locks in the *current* failure mode the
// user reported: active profile with placeholder key + missing context_id.
// If someone "fixes" the profile in the future, this test will pass — but if
// someone re-introduces the bug shape it will fire.
func TestValidateProfile_FieldBugShape(t *testing.T) {
	// once-test.env shape from ~/.m3c-tools/profiles
	p := &Profile{
		Name: "once-test",
		Vars: map[string]string{
			"ER1_API_URL":      "https://onboarding.guide/upload_2",
			"ER1_API_KEY":      "once-only",
			"ER1_CONTENT_TYPE": "YouTube-Video-Impression",
			"ER1_VERIFY_SSL":   "true",
		},
	}
	got := ValidateProfile(p)
	wantCodes := []string{"missing-required", "key-placeholder"}
	for _, want := range wantCodes {
		if issueByCode(got, want) == nil {
			t.Errorf("expected issue %q, got %+v", want, got)
		}
	}
}
