package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateProfileName_RejectsTraversal pins the allow-list. A profile name
// becomes a filename, so anything that can leave the profiles directory, name a
// hidden file or carry a control character has to be refused.
func TestValidateProfileName_RejectsTraversal(t *testing.T) {
	bad := []string{
		"",
		".",
		"..",
		"../evil",
		"../../tmp/evil",
		"..\\evil",
		"sub/dir",
		"sub\\dir",
		"/absolute",
		"C:name",
		".hidden",
		"name\x00null",
		"name\nnewline",
		"na me",
		"name;rm",
		strings.Repeat("x", maxProfileNameLen+1),
	}
	for _, name := range bad {
		if err := ValidateProfileName(name); err == nil {
			t.Errorf("ValidateProfileName(%q) = nil, want an error", name)
		} else if !errors.Is(err, ErrInvalidProfileName) {
			t.Errorf("ValidateProfileName(%q) error %v, want ErrInvalidProfileName", name, err)
		}
	}
}

// TestValidateProfileName_AcceptsRealNames keeps the rule permissive enough for
// every name the tool has ever written, so no existing profile is orphaned.
func TestValidateProfileName_AcceptsRealNames(t *testing.T) {
	good := []string{
		"default", "dev", "prod", "stage", "local",
		"kup-berlin", "customer_001", "v1.2", "A", "0",
		strings.Repeat("x", maxProfileNameLen),
	}
	for _, name := range good {
		if err := ValidateProfileName(name); err != nil {
			t.Errorf("ValidateProfileName(%q) = %v, want nil", name, err)
		}
	}
}

// TestProfileOperations_RefuseTraversal is the end-to-end version: no profile
// operation may touch a file outside the profiles directory.
func TestProfileOperations_RefuseTraversal(t *testing.T) {
	base := t.TempDir()
	pm := &ProfileManager{BaseDir: base}

	// A file the traversal name would resolve to, one level above the
	// profiles directory. It must survive every operation below.
	victim := filepath.Join(base, "victim.env")
	if err := os.WriteFile(victim, []byte("# M3C Profile: victim\nER1_API_KEY=keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const escape = "../victim"

	if _, err := pm.GetProfile(escape); err == nil {
		t.Error("GetProfile must refuse a traversal name")
	}
	if err := pm.CreateProfile(escape, "pwned", map[string]string{"X": "1"}); err == nil {
		t.Error("CreateProfile must refuse a traversal name")
	}
	if err := pm.DeleteProfile(escape); err == nil {
		t.Error("DeleteProfile must refuse a traversal name")
	}
	if err := pm.ImportProfile(escape, victim); err == nil {
		t.Error("ImportProfile must refuse a traversal name")
	}
	if err := pm.SwitchProfile(escape); err == nil {
		t.Error("SwitchProfile must refuse a traversal name")
	}

	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("the file outside the profiles dir was removed: %v", err)
	}
	if !strings.Contains(string(data), "keep-me") {
		t.Fatalf("the file outside the profiles dir was overwritten: %q", string(data))
	}
}

// TestActiveProfileName_RejectsPoisonedFile: the active-profile file is plain
// text on disk. A traversal name written into it must not be handed back as a
// trusted profile name.
func TestActiveProfileName_RejectsPoisonedFile(t *testing.T) {
	base := t.TempDir()
	pm := &ProfileManager{BaseDir: base}
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, ActiveProfileFile), []byte("../../etc/passwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := pm.ActiveProfileName(); got != "" {
		t.Errorf("ActiveProfileName() = %q, want \"\" for a poisoned active-profile file", got)
	}
}

// TestParseEnvFile_StripsControlCharsFromHeader: an imported .env is foreign
// content. Its declared name and description are echoed into log lines and the
// CLI listing, so a carriage return in the header must not survive to forge a
// line.
func TestParseEnvFile_StripsControlCharsFromHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "imported.env")
	body := "# M3C Profile: ok\rFAKE [config] SECURITY: all clear\n" +
		"# Description: desc\rforged\n" +
		"ER1_API_KEY=x\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := ParseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{p.Name, p.Description} {
		if strings.ContainsAny(s, "\r\n\x00") {
			t.Errorf("control character survived into %q", s)
		}
	}
	if p.Name != "okFAKE [config] SECURITY: all clear" {
		t.Errorf("Name = %q, want the header text with the CR removed", p.Name)
	}
}
