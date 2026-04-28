package config

import (
	"fmt"
	neturl "net/url"
	"os"
	"sort"
	"strings"
)

// Severity ranks doctor issues so callers can colour them or gate exit codes.
type Severity int

const (
	SevInfo Severity = iota
	SevWarn
	SevFail
)

func (s Severity) String() string {
	switch s {
	case SevFail:
		return "FAIL"
	case SevWarn:
		return "WARN"
	default:
		return "INFO"
	}
}

// Issue is a single finding the doctor produces about a profile (or a
// cross-profile relationship).
type Issue struct {
	Profile  string   // empty for cross-profile checks
	Key      string   // env var key the issue is about, if any
	Severity Severity
	Code     string // short stable identifier
	Message  string // human-readable description
}

// ProfileReport groups issues for a single profile.
type ProfileReport struct {
	Profile *Profile
	Issues  []Issue
}

// HasFail reports whether this profile has any blocking issues.
func (pr ProfileReport) HasFail() bool {
	for _, i := range pr.Issues {
		if i.Severity == SevFail {
			return true
		}
	}
	return false
}

// DoctorReport is the full output of a doctor run.
type DoctorReport struct {
	ActiveProfile string
	Profiles      []ProfileReport
	CrossIssues   []Issue
}

// HasFail reports whether the report contains any blocking issues.
func (r DoctorReport) HasFail() bool {
	for _, p := range r.Profiles {
		if p.HasFail() {
			return true
		}
	}
	for _, i := range r.CrossIssues {
		if i.Severity == SevFail {
			return true
		}
	}
	return false
}

// requiredKeys lists keys that every account-scoped profile MUST set.
// ER1_CONTEXT_ID is required because PLM/upload paths depend on it; if
// missing, the runtime falls through to preferences.env which silently
// papers over the gap and produces hard-to-diagnose surprises.
var requiredKeys = []string{
	"ER1_API_URL",
	"ER1_API_KEY",
	"ER1_CONTEXT_ID",
}

// placeholderKeys are values shipped in the "init template" / examples that
// will never authenticate. They are the #1 cause of silent menubar failure.
var placeholderKeys = map[string]struct{}{
	"once-only":                 {},
	"minimal-key":               {},
	"test-key-abc123":           {},
	"democredential-er1-api-key": {},
	"your-api-key-here":         {},
	"changeme":                  {},
	"":                          {},
}

// ValidateProfile inspects a single profile and returns its issues.
//
// Pure (no network) — wires up against ValidateAll, which adds cross-profile
// checks. Live HTTP probes belong in a separate function so unit tests stay
// hermetic.
func ValidateProfile(p *Profile) []Issue {
	if p == nil {
		return nil
	}
	var issues []Issue

	for _, k := range requiredKeys {
		v, ok := p.Vars[k]
		if !ok || strings.TrimSpace(v) == "" {
			sev := SevFail
			// dev profile pointed at localhost is allowed to omit a real key
			// for the upload key — but it must still be present.
			issues = append(issues, Issue{
				Profile:  p.Name,
				Key:      k,
				Severity: sev,
				Code:     "missing-required",
				Message:  fmt.Sprintf("%s is missing or empty", k),
			})
		}
	}

	if u := strings.TrimSpace(p.Vars["ER1_API_URL"]); u != "" {
		parsed, err := neturl.Parse(u)
		switch {
		case err != nil || parsed.Scheme == "" || parsed.Host == "":
			issues = append(issues, Issue{
				Profile: p.Name, Key: "ER1_API_URL",
				Severity: SevFail, Code: "url-malformed",
				Message: fmt.Sprintf("ER1_API_URL is not a valid URL: %q", u),
			})
		case !strings.HasSuffix(parsed.Path, "/upload_2"):
			issues = append(issues, Issue{
				Profile: p.Name, Key: "ER1_API_URL",
				Severity: SevWarn, Code: "url-suffix",
				Message: fmt.Sprintf("ER1_API_URL should end with /upload_2 (got path %q)", parsed.Path),
			})
		}
	}

	if k := strings.TrimSpace(p.Vars["ER1_API_KEY"]); k != "" {
		if _, isPlaceholder := placeholderKeys[k]; isPlaceholder {
			issues = append(issues, Issue{
				Profile: p.Name, Key: "ER1_API_KEY",
				Severity: SevFail, Code: "key-placeholder",
				Message: fmt.Sprintf("ER1_API_KEY is a known placeholder (%q) — replace with a real key", k),
			})
		} else if len(k) < 16 {
			issues = append(issues, Issue{
				Profile: p.Name, Key: "ER1_API_KEY",
				Severity: SevWarn, Code: "key-short",
				Message: fmt.Sprintf("ER1_API_KEY is suspiciously short (%d chars)", len(k)),
			})
		}
	}

	if ctx := strings.TrimSpace(p.Vars["ER1_CONTEXT_ID"]); ctx != "" {
		// Expected shape: "<digits>___<suffix>". Tolerate the bare digits form
		// because some flows strip the suffix internally.
		if !strings.Contains(ctx, "___") {
			issues = append(issues, Issue{
				Profile: p.Name, Key: "ER1_CONTEXT_ID",
				Severity: SevWarn, Code: "ctx-shape",
				Message: fmt.Sprintf("ER1_CONTEXT_ID has unusual shape (no '___' suffix): %q", ctx),
			})
		}
	}

	if p.Path != "" {
		if info, err := os.Stat(p.Path); err == nil {
			perm := info.Mode().Perm()
			if perm&0o077 != 0 {
				issues = append(issues, Issue{
					Profile: p.Name, Key: "",
					Severity: SevWarn, Code: "perms-loose",
					Message: fmt.Sprintf("profile file is world/group readable (%04o) — chmod 600 %s", perm, p.Path),
				})
			}
		}
	}

	return issues
}

// ValidateAll runs ValidateProfile on every profile and adds cross-profile
// checks (active-profile pointer health, duplicate keys, etc).
func ValidateAll(profiles []Profile, active string) DoctorReport {
	rep := DoctorReport{ActiveProfile: active}

	byName := make(map[string]*Profile, len(profiles))
	for i := range profiles {
		byName[profiles[i].Name] = &profiles[i]
	}

	// Sort for deterministic output.
	names := make([]string, 0, len(profiles))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		p := byName[n]
		rep.Profiles = append(rep.Profiles, ProfileReport{
			Profile: p,
			Issues:  ValidateProfile(p),
		})
	}

	// Cross-profile: active profile must exist.
	if active == "" {
		rep.CrossIssues = append(rep.CrossIssues, Issue{
			Severity: SevFail, Code: "no-active",
			Message: "no active profile set — run: m3c-tools config switch <name>",
		})
	} else if _, ok := byName[active]; !ok {
		rep.CrossIssues = append(rep.CrossIssues, Issue{
			Severity: SevFail, Code: "active-missing",
			Message: fmt.Sprintf("active profile %q does not exist in profiles dir", active),
		})
	}

	// Cross-profile: duplicate non-placeholder API keys point at copy-paste mistakes.
	keyOwners := map[string][]string{}
	for _, p := range byName {
		k := strings.TrimSpace(p.Vars["ER1_API_KEY"])
		if k == "" {
			continue
		}
		if _, isPlaceholder := placeholderKeys[k]; isPlaceholder {
			continue
		}
		keyOwners[k] = append(keyOwners[k], p.Name)
	}
	for k, owners := range keyOwners {
		if len(owners) > 1 {
			sort.Strings(owners)
			rep.CrossIssues = append(rep.CrossIssues, Issue{
				Severity: SevWarn, Code: "key-duplicate",
				Key:     "ER1_API_KEY",
				Message: fmt.Sprintf("API key (last4=%s) is reused across profiles: %s",
					last4(k), strings.Join(owners, ", ")),
			})
		}
	}

	return rep
}

func last4(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[len(s)-4:]
}
