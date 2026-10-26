package projectpolicy

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// nativeGitBinding contains public source selection, never token values.
type nativeGitBinding struct {
	Provider, APIBase, Repository, CommitOID, RootTreeOID, ObjectFormat string
	AuthMode, AuthFamily, AuthOrigin, TLSMode, CASHA256                 string
}

func parseNativeGitSource(dir string, raw []byte) (*registry.NativeGitSource, nativeGitBinding, error) {
	var binding nativeGitBinding
	object, err := nativeObject(raw, "kind", "provider", "api_base", "repository", "object_format", "commit_oid", "root_tree_oid", "tls", "auth")
	if err != nil {
		return nil, binding, err
	}
	var kind string
	if json.Unmarshal(object["kind"], &kind) != nil || kind != "git" {
		return nil, binding, ErrUnsupported
	}
	for key, dst := range map[string]*string{
		"provider": &binding.Provider, "api_base": &binding.APIBase,
		"repository": &binding.Repository, "object_format": &binding.ObjectFormat,
		"commit_oid": &binding.CommitOID, "root_tree_oid": &binding.RootTreeOID,
	} {
		if json.Unmarshal(object[key], dst) != nil || !nativeText(*dst, 8192) {
			return nil, binding, ErrInvalid
		}
	}
	base, err := httpsafe.ParseAPIBase(binding.APIBase, false)
	if err != nil {
		return nil, binding, ErrInvalid
	}
	binding.APIBase = strings.TrimRight(base.URL, "/")
	ca, err := parseNativeGitTLS(dir, object["tls"], &binding)
	if err != nil {
		return nil, binding, err
	}
	if err = parseNativeGitAuth(object["auth"], &binding); err != nil {
		return nil, binding, err
	}
	source, err := registry.NewNativeGitSource(registry.NativeGitSourceOptions{
		Provider: binding.Provider, APIBase: binding.APIBase, Repository: binding.Repository,
		CommitOID: binding.CommitOID, RootTreeOID: binding.RootTreeOID, ObjectFormat: binding.ObjectFormat,
		AuthMode: binding.AuthMode, AuthFamily: binding.AuthFamily, AuthOrigin: binding.AuthOrigin,
		TLSMode: binding.TLSMode, CAPEM: ca,
	})
	if err != nil {
		return nil, binding, ErrInvalid
	}
	return source, binding, nil
}

func parseNativeGitTLS(dir string, raw []byte, binding *nativeGitBinding) ([]byte, error) {
	var header struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, ErrInvalid
	}
	binding.TLSMode = header.Mode
	switch header.Mode {
	case "system":
		_, err := nativeObject(raw, "mode")
		return nil, err
	case "pinned-pem":
		object, err := nativeObject(raw, "mode", "ca")
		if err != nil {
			return nil, err
		}
		if _, err = nativeObject(object["ca"], "path", "sha256"); err != nil {
			return nil, err
		}
		var ref fileRef
		if json.Unmarshal(object["ca"], &ref) != nil {
			return nil, ErrInvalid
		}
		ca, err := readNativeRef(dir, ref, maxProfileBytes)
		if err != nil {
			return nil, err
		}
		binding.CASHA256 = strings.ToLower(ref.SHA256)
		return ca, nil
	default:
		return nil, ErrUnsupported
	}
}

func parseNativeGitAuth(raw []byte, binding *nativeGitBinding) error {
	var auth struct {
		Mode   string `json:"mode"`
		Family string `json:"family"`
		Origin string `json:"origin"`
	}
	if json.Unmarshal(raw, &auth) != nil {
		return ErrInvalid
	}
	switch auth.Mode {
	case "none":
		if _, err := nativeObject(raw, "mode"); err != nil {
			return err
		}
	case "external-env":
		if _, err := nativeObject(raw, "mode", "family", "origin"); err != nil {
			return err
		}
		if (binding.Provider != "github" || auth.Family != "github-read-token") && (binding.Provider != "gitlab" || auth.Family != "gitlab-read-token") {
			return ErrUnsupported
		}
		if !nativeText(auth.Origin, 8192) {
			return ErrInvalid
		}
	default:
		return ErrUnsupported
	}
	binding.AuthMode, binding.AuthFamily, binding.AuthOrigin = auth.Mode, auth.Family, auth.Origin
	return nil
}

// BeginGitAgentInstall acquires and checks enrolled native history before the
// selected source can read a token or request the pinned repository snapshot.
func (p *NativePolicy) BeginGitAgentInstall(ctx context.Context, digest string) (*registry.NativeLiveAgentSession, error) {
	if p == nil || p.git == nil {
		return nil, ErrUnsupported
	}
	selected, err := p.OfflineInstallSelection()
	if err != nil {
		return nil, err
	}
	journal, err := registry.OpenNativeJournal(selected)
	if err != nil {
		return nil, err
	}
	return registry.NewNativeGitAgentSession(ctx, journal, p.git, digest)
}

// BeginGitSkillInstall uses the separate SKILL publisher under the same native
// journal trust boundary; it never enrolls, adopts or grants a generic mutation.
func (p *NativePolicy) BeginGitSkillInstall(ctx context.Context, digest string) (*registry.NativeLiveSkillSession, error) {
	if p == nil || p.git == nil {
		return nil, ErrUnsupported
	}
	selected, err := p.OfflineInstallSelection()
	if err != nil {
		return nil, err
	}
	journal, err := registry.OpenNativeJournal(selected)
	if err != nil {
		return nil, err
	}
	return registry.NewNativeGitSkillSession(ctx, journal, p.git, digest)
}
