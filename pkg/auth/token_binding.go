package auth

import (
	"fmt"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

const observedLoginSource = "client-observed-login"

// ErrCredentialBinding refuses missing, invalid or foreign saved-token metadata.
// A new explicit login is required; an old entry is never rebound by reading it.
var ErrCredentialBinding = fmt.Errorf("%w: saved device token requires re-login", httpsafe.ErrCredentialBinding)

// NewLoginBinding records the canonical HTTPS origin selected for a new login.
// It accepts no token and performs no I/O. The source describes client-observed
// login provenance, not authenticated issuer, audience or tenant authority.
func NewLoginBinding(rawBase string) (*httpsafe.CredentialBinding, error) {
	base, err := httpsafe.ParseAPIBase(rawBase, false)
	if err != nil {
		return nil, err
	}
	return &httpsafe.CredentialBinding{
		Version: httpsafe.CredentialBindingVersion,
		Kind:    httpsafe.CredentialDeviceBearer,
		Origin:  base.Origin.String(),
		Source:  observedLoginSource,
	}, nil
}

// BoundBearerReadOnly validates the independently selected HTTPS destination
// before one native Load, then validates the saved binding before returning a
// usable bearer. Native Get returns metadata and secret together; this does not
// claim a separate metadata-only native read. No migration or cleanup occurs.
func BoundBearerReadOnly(expectedBase, userIDHint string) (string, error) {
	return boundBearerReadOnly(expectedBase, newKeyringStore(), DeviceID(), userIDHint)
}

func boundBearerReadOnly(expectedBase string, store TokenStore, deviceID, userID string) (string, error) {
	base, err := httpsafe.ParseAPIBase(expectedBase, false)
	if err != nil {
		return "", err
	}
	token, err := store.Load(deviceID, userID)
	if err != nil {
		return "", err
	}
	if token == nil || token.Binding == nil {
		return "", ErrCredentialBinding
	}
	binding := token.Binding
	if binding.Version != httpsafe.CredentialBindingVersion ||
		binding.Kind != httpsafe.CredentialDeviceBearer ||
		binding.Source != observedLoginSource ||
		binding.Origin != base.Origin.String() {
		return "", ErrCredentialBinding
	}
	return deviceBearerValue(token)
}
