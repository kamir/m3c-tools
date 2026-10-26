package projectpolicy

import (
	"context"
	"encoding/json"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type nativeSourceBinding struct {
	URL, Auth, TLSMode, CASHA string
}

func parseNativeEvidenceSource(dir string, raw json.RawMessage) (*registry.NativeEvidenceSource, nativeSourceBinding, error) {
	var binding nativeSourceBinding
	object, err := nativeObject(raw, "kind", "url", "auth", "tls")
	if err != nil {
		return nil, binding, err
	}
	var source struct {
		Kind string `json:"kind"`
		URL  string `json:"url"`
		Auth string `json:"auth"`
	}
	if json.Unmarshal(raw, &source) != nil || source.Kind != "https-native-evidence" || source.Auth != "none" || !nativeText(source.URL, 8192) {
		return nil, binding, ErrInvalid
	}
	// This is metadata validation only; the source constructor additionally
	// rejects ambiguous paths and captures the normalised exact endpoint.
	base, err := httpsafe.ParseAPIBase(source.URL, false)
	if err != nil {
		return nil, binding, ErrInvalid
	}
	var tlsObject map[string]json.RawMessage
	if json.Unmarshal(object["tls"], &tlsObject) != nil || tlsObject == nil {
		return nil, binding, ErrInvalid
	}
	var mode string
	if json.Unmarshal(tlsObject["mode"], &mode) != nil {
		return nil, binding, ErrInvalid
	}
	binding = nativeSourceBinding{URL: base.URL, Auth: source.Auth, TLSMode: mode}
	switch mode {
	case "system":
		if _, err = nativeObject(object["tls"], "mode"); err != nil {
			return nil, binding, err
		}
		reader, err := registry.NewNativeSystemEvidenceSource(base.URL)
		if err != nil {
			return nil, binding, ErrInvalid
		}
		return reader, binding, nil
	case "pinned-pem":
		tlsFields, err := nativeObject(object["tls"], "mode", "ca")
		if err != nil {
			return nil, binding, err
		}
		if _, err = nativeObject(tlsFields["ca"], "path", "sha256"); err != nil {
			return nil, binding, err
		}
		var ref fileRef
		if json.Unmarshal(tlsFields["ca"], &ref) != nil {
			return nil, binding, ErrInvalid
		}
		rawPEM, err := readNativeRef(dir, ref, 64<<10)
		if err != nil {
			return nil, binding, err
		}
		reader, err := registry.NewNativePinnedEvidenceSource(base.URL, rawPEM)
		if err != nil {
			return nil, binding, ErrInvalid
		}
		binding.CASHA = ref.SHA256
		return reader, binding, nil
	default:
		return nil, binding, ErrUnsupported
	}
}

// AdoptFromSource explicitly updates an existing authenticated native history.
// It neither enrolls missing state nor enables an installation or live carrier.
func (p *NativePolicy) AdoptFromSource(ctx context.Context) (registry.NativeJournalStatus, error) {
	var zero registry.NativeJournalStatus
	if p == nil {
		return zero, ErrInvalid
	}
	if p.source == nil {
		return zero, ErrUnsupported
	}
	if ctx == nil {
		return zero, registry.ErrNativeSessionUnavailable
	}
	selection, err := p.OfflineInstallSelection()
	if err != nil {
		return zero, err
	}
	journal, err := registry.OpenNativeJournal(selection)
	if err != nil {
		return zero, err
	}
	// Status authenticates stale history and checks lease release. The later
	// Adopt independently reloads the newest history under its own stable lock.
	if _, err = journal.Status(ctx); err != nil {
		return zero, err
	}
	raw, err := p.source.Fetch(ctx)
	if err != nil {
		return zero, err
	}
	return journal.Adopt(ctx, raw)
}
