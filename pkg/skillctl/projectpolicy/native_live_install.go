package projectpolicy

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// nativeLiveBinding is public configuration retained in the consent selection,
// not a credential or a claim of signed physical carrier origin.
type nativeLiveBinding struct {
	BaseURL, ContextID, AuthMode, AuthFamily, AuthOrigin, TLSMode, CASHA256 string
}

func parseNativeLiveSource(dir string, raw []byte) (*registry.NativeLiveAgentSource, nativeLiveBinding, error) {
	var binding nativeLiveBinding
	object, err := nativeObject(raw, "kind", "base_url", "context_id", "tls", "auth")
	if err != nil {
		return nil, binding, err
	}
	var kind string
	if json.Unmarshal(object["kind"], &kind) != nil || kind != "er1" {
		return nil, binding, ErrUnsupported
	}
	if json.Unmarshal(object["base_url"], &binding.BaseURL) != nil || !nativeText(binding.BaseURL, 8192) || json.Unmarshal(object["context_id"], &binding.ContextID) != nil || !nativeText(binding.ContextID, 8192) {
		return nil, binding, ErrInvalid
	}
	base, err := httpsafe.ParseAPIBase(binding.BaseURL, false)
	if err != nil {
		return nil, binding, ErrInvalid
	}
	binding.BaseURL = strings.TrimRight(base.URL, "/")
	var tlsMode struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(object["tls"], &tlsMode) != nil {
		return nil, binding, ErrInvalid
	}
	binding.TLSMode = tlsMode.Mode
	var ca []byte
	switch tlsMode.Mode {
	case "system":
		if _, err = nativeObject(object["tls"], "mode"); err != nil {
			return nil, binding, err
		}
	case "pinned-pem":
		tlsObject, e := nativeObject(object["tls"], "mode", "ca")
		if e != nil {
			return nil, binding, e
		}
		if _, e = nativeObject(tlsObject["ca"], "path", "sha256"); e != nil {
			return nil, binding, e
		}
		var ref fileRef
		if json.Unmarshal(tlsObject["ca"], &ref) != nil {
			return nil, binding, ErrInvalid
		}
		ca, err = readNativeRef(dir, ref, maxProfileBytes)
		if err != nil {
			return nil, binding, err
		}
		binding.CASHA256 = strings.ToLower(ref.SHA256)
	default:
		return nil, binding, ErrUnsupported
	}
	var auth struct {
		Mode   string `json:"mode"`
		Family string `json:"family"`
		Origin string `json:"origin"`
	}
	if json.Unmarshal(object["auth"], &auth) != nil {
		return nil, binding, ErrInvalid
	}
	switch auth.Mode {
	case "none":
		if _, err = nativeObject(object["auth"], "mode"); err != nil {
			return nil, binding, err
		}
	case "external-env":
		if _, err = nativeObject(object["auth"], "mode", "family", "origin"); err != nil {
			return nil, binding, err
		}
		if auth.Family != "api-key" && auth.Family != "bearer" {
			return nil, binding, ErrUnsupported
		}
		if !nativeText(auth.Origin, 8192) {
			return nil, binding, ErrInvalid
		}
	default:
		return nil, binding, ErrUnsupported
	}
	binding.AuthMode, binding.AuthFamily, binding.AuthOrigin = auth.Mode, auth.Family, auth.Origin
	source, err := registry.NewNativeLiveAgentSource(registry.NativeLiveAgentSourceOptions{BaseURL: binding.BaseURL, ContextID: binding.ContextID, AuthMode: binding.AuthMode, AuthFamily: binding.AuthFamily, AuthOrigin: binding.AuthOrigin, TLSMode: binding.TLSMode, CAPEM: ca})
	if err != nil {
		return nil, binding, ErrInvalid
	}
	return source, binding, nil
}

// BeginER1AgentInstall holds an existing fresh native journal before reading a
// selected external credential or requesting the exact agent archive. It never
// enrolls, adopts, or grants the generic native mutation intent.
func (p *NativePolicy) BeginER1AgentInstall(ctx context.Context, digest string) (*registry.NativeLiveAgentSession, error) {
	if p == nil || p.live == nil {
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
	return registry.NewNativeLiveAgentSession(ctx, journal, p.live, digest)
}
