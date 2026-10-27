package projectpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func nativeGitProfileCarrier(base string) map[string]any {
	return map[string]any{
		"kind": "git", "provider": "github", "api_base": base,
		"repository": "owner/repository", "object_format": "sha1",
		"commit_oid": strings.Repeat("a", 40), "root_tree_oid": strings.Repeat("b", 40),
		"tls": map[string]any{"mode": "system"}, "auth": map[string]any{"mode": "none"},
	}
}

func TestNativeGitProfileBinding(t *testing.T) {
	t.Run("immutableSelectionAndStableHistory", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		f.doc["schema"] = NativeGitSchema
		native := f.doc["native"].(map[string]any)
		native["carrier"] = nativeGitProfileCarrier(f.server.URL + "/api")
		original := f.load(t)
		selected := original.CarrierSelection()
		if selected.Kind != "git" || selected.Provider != "github" || selected.Repository != "owner/repository" || selected.CommitOID != strings.Repeat("a", 40) || selected.RootTreeOID != strings.Repeat("b", 40) || selected.ObjectFormat != "sha1" {
			t.Fatal("profile lost explicit Git source selection")
		}
		selected.Repository = "caller/mutation"
		if original.CarrierSelection().Repository != "owner/repository" {
			t.Fatal("caller mutated retained carrier")
		}
		for _, change := range []struct{ key, value string }{
			{"commit_oid", strings.Repeat("c", 40)}, {"root_tree_oid", strings.Repeat("d", 40)},
			{"repository", "owner/different"}, {"api_base", f.server.URL + "/different-prefix"},
			{"provider", "gitlab"},
		} {
			carrier := nativeGitProfileCarrier(f.server.URL + "/api")
			carrier[change.key] = change.value
			native["carrier"] = carrier
			changed := f.load(t)
			if changed.SelectionID() == original.SelectionID() {
				t.Fatalf("changed %s did not invalidate selection", change.key)
			}
			if changed.HistoryAuthorityID() != original.HistoryAuthorityID() {
				t.Fatalf("changed %s reset the existing authority history", change.key)
			}
		}
		if _, err := original.BeginGitAgentInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, registry.ErrNativeHistoryRequired) {
			t.Fatalf("agent source must require enrolled history before requests: %v", err)
		}
		if _, err := original.BeginGitSkillInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, registry.ErrNativeHistoryRequired) {
			t.Fatalf("skill source must require enrolled history before requests: %v", err)
		}
		if f.requests.Load() != 0 {
			t.Fatal("profile load or missing history contacted a carrier")
		}
	})
	t.Run("legacySelectionEncodingUnchanged", func(t *testing.T) {
		raw, err := json.Marshal(NativeCarrierSelection{Kind: "er1", Locator: "registry", BaseURL: "https://native.invalid:443", ContextID: "context"})
		const previous = `{"Kind":"er1","Locator":"registry","BaseURL":"https://native.invalid:443","ContextID":"context","AllowLoopbackHTTP":false}`
		if err != nil || string(raw) != previous {
			t.Fatalf("new Git metadata changed existing v2/v3/v4 selection encoding: %s (%v)", raw, err)
		}
	})
	t.Run("oldGitLocatorIsNotLiveAuthority", func(t *testing.T) {
		f := qaNewEvidenceFixture(t)
		f.doc["schema"] = NativeSchema
		native := f.doc["native"].(map[string]any)
		delete(native, "revocation_source")
		native["carrier"] = map[string]any{"kind": "git", "locator": "github://owner/repository"}
		p := f.load(t)
		if _, err := p.BeginGitAgentInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("old Git locator acquired a live grant: %v", err)
		}
		if _, err := p.BeginGitSkillInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("old Git locator acquired a SKILL live grant: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		want   error
	}{
		{"branch", func(c map[string]any) { c["commit_oid"] = "master" }, ErrInvalid},
		{"shortCommit", func(c map[string]any) { c["commit_oid"] = "abc123" }, ErrInvalid},
		{"upperCommit", func(c map[string]any) { c["commit_oid"] = strings.Repeat("A", 40) }, ErrInvalid},
		{"wrongTree", func(c map[string]any) { c["root_tree_oid"] = nil }, ErrInvalid},
		{"format", func(c map[string]any) { c["object_format"] = "sha256" }, ErrInvalid},
		{"ssh", func(c map[string]any) { c["api_base"] = "ssh://git.invalid" }, ErrInvalid},
		{"pathEscape", func(c map[string]any) { c["api_base"] = "https://git.invalid/api/../escape" }, ErrInvalid},
		{"repoEscape", func(c map[string]any) { c["repository"] = "owner/../project" }, ErrInvalid},
		{"repoAlias", func(c map[string]any) { c["repository"] = "owner/project.GIT" }, ErrInvalid},
		{"implicitHTTP", func(c map[string]any) { c["allow_loopback_http"] = true }, ErrInvalid},
		{"sourceKind", func(c map[string]any) { c["kind"] = "er1" }, ErrUnsupported},
		{"tlsAlias", func(c map[string]any) { c["tls"] = map[string]any{"mode": "system", "ca": nil} }, ErrInvalid},
		{"authFallback", func(c map[string]any) { c["auth"] = map[string]any{"mode": "auto"} }, ErrUnsupported},
		{"wrongFamily", func(c map[string]any) {
			c["auth"] = map[string]any{"mode": "external-env", "family": "gitlab-read-token", "origin": "https://git.invalid:443"}
		}, ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := qaNewEvidenceFixture(t)
			f.doc["schema"] = NativeGitSchema
			carrier := nativeGitProfileCarrier(f.server.URL + "/api")
			tc.change(carrier)
			f.doc["native"].(map[string]any)["carrier"] = carrier
			raw, err := json.Marshal(f.doc)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if p, err := LoadNative(f.path, f.project, f.home); p != nil || !errors.Is(err, tc.want) {
				t.Fatalf("malformed source must fail with %v, got %v / %v", tc.want, p != nil, err)
			}
			if f.requests.Load() != 0 {
				t.Fatal("invalid source profile made a request")
			}
		})
	}
}
