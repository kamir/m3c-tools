package capture

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// TestBuiltinProfiles: every embedded profile parses strictly, its id
// matches its file, walking-skeleton requires exactly common.identity, and
// the probe lists of SPEC-0467 section 5.6 are present.
func TestBuiltinProfiles(t *testing.T) {
	ids := BuiltinProfileIDs()
	if strings.Join(ids, ",") != "agentic-workstation,macos-workstation,ubuntu-bastion,walking-skeleton,windows-wsl-workstation" {
		t.Fatalf("built-in profiles %v", ids)
	}
	for _, id := range ids {
		p, err := BuiltinProfile(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		raw, err := builtinProfiles.ReadFile("profiles/" + id + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		if p.Digest() != trustfreeze.Digest(raw) || p.Ref().ID != id || !p.IsRequired("common.identity") {
			t.Fatalf("%s: %+v", id, p.Ref())
		}
	}
	ws, _ := BuiltinProfile("walking-skeleton")
	if strings.Join(ws.Required, ",") != "common.identity" || len(ws.Optional) != 0 {
		t.Fatalf("walking-skeleton %+v", ws)
	}
	ub, _ := BuiltinProfile("ubuntu-bastion")
	if strings.Join(ub.Required, ",") != "common.identity,linux.packages,linux.users,linux.sudo,linux.ssh,linux.systemd,linux.executables,linux.network.listeners,linux.network.routes,linux.dns,linux.firewall,linux.mounts" {
		t.Fatalf("ubuntu-bastion required %v", ub.Required)
	}
	if strings.Join(ub.Optional, ",") != "common.git,common.claude,linux.containers" {
		t.Fatalf("ubuntu-bastion optional %v", ub.Optional)
	}
	aw, _ := BuiltinProfile("agentic-workstation")
	if len(aw.Required) != 9 || len(aw.Optional) != 5 {
		t.Fatalf("agentic-workstation %v %v", aw.Required, aw.Optional)
	}
	for _, bad := range []string{"", "Walking", "../x", "nope"} {
		if _, err := BuiltinProfile(bad); !errors.Is(err, ErrUnknownProfile) {
			t.Errorf("BuiltinProfile(%q) = %v", bad, err)
		}
	}
}

// TestParseProfileStrict: unknown fields, unknown schema, an unimplemented
// redaction policy, fail_if_required_missing false, duplicates, bad ids and
// a second document are all refused.
func TestParseProfileStrict(t *testing.T) {
	good := "schema_version: trust-freeze/profile/v1\nid: p\nversion: \"1\"\nrequired: [common.identity]\noptional: [linux.users]\nfail_if_required_missing: true\nredaction_policy: default-v1\n"
	if _, err := ParseProfile([]byte(good)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unknown_field": good + "extra: 1\n",
		"schema":        strings.Replace(good, "profile/v1", "profile/v2", 1),
		"policy":        strings.Replace(good, "default-v1", "employee-workstation-v1", 1),
		"fail_false":    strings.Replace(good, "fail_if_required_missing: true", "fail_if_required_missing: false", 1),
		"no_required":   strings.Replace(good, "required: [common.identity]", "required: []", 1),
		"duplicate":     strings.Replace(good, "optional: [linux.users]", "optional: [common.identity]", 1),
		"bad_probe_id":  strings.Replace(good, "linux.users", "Linux/Users", 1),
		"bad_id":        strings.Replace(good, "id: p\n", "id: P_1\n", 1),
		"no_version":    strings.Replace(good, "version: \"1\"\n", "", 1),
		"two_docs":      good + "---\nid: q\n",
		"not_yaml":      "{{{",
	}
	for name, y := range cases {
		if _, err := ParseProfile([]byte(y)); !errors.Is(err, ErrInvalidProfile) && !errors.Is(err, trustfreeze.ErrUnknownSchema) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestNoSealImport: the guard of SPEC-0470 section 4.8. The capture path, the
// probe seam, the platform probes, the redactor and the core do not import the
// seal package, so a capture cannot approve or sign (SPEC-0470 TF05-R2, R6). The
// scan covers every non-test file of these packages; they import each other
// only, so a direct scan is a transitive one.
func TestNoSealImport(t *testing.T) {
	root := filepath.Join("..")
	dirs := []string{"capture", "probe", "redact", filepath.Join("platform", "common"), "."}
	scanned := 0
	for _, d := range dirs {
		dir := filepath.Join(root, d)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			scanned++
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.Contains(p, "/trustfreeze/seal") {
					t.Fatalf("%s/%s imports %s", d, name, p)
				}
				if strings.HasPrefix(p, "github.com/kamir/m3c-tools/") && !strings.HasPrefix(p, "github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze") {
					t.Fatalf("%s/%s imports %s outside the trustfreeze tree; the transitive scan would be incomplete", d, name, p)
				}
			}
		}
	}
	if scanned < 10 {
		t.Fatalf("scanned only %d files; the guard is not looking at the packages", scanned)
	}
}

// TestBuiltinProfileCommentsCiteSpecIDs: the profile bytes are digested into
// every capture, so their comments must be right from the first release.
// They cite requirement ids (SPEC-0358: a private document only by bare id,
// never by description), and only agentic-workstation claims the
// employee-workstation-v1 redaction policy, the only profile SPEC-0467
// section 5.6 names it for.
func TestBuiltinProfileCommentsCiteSpecIDs(t *testing.T) {
	for _, id := range BuiltinProfileIDs() {
		raw, err := builtinProfiles.ReadFile("profiles/" + id + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(raw))
		for _, phrase := range []string{"the order", "trust freeze order"} {
			if strings.Contains(text, phrase) {
				t.Errorf("%s: comment cites %q instead of a SPEC id", id, phrase)
			}
		}
		if id != "agentic-workstation" && strings.Contains(text, "employee-workstation-v1") {
			t.Errorf("%s: claims employee-workstation-v1, which no SPEC names for it", id)
		}
		if !strings.Contains(string(raw), "SPEC-04") {
			t.Errorf("%s: cites no SPEC id", id)
		}
	}
}
