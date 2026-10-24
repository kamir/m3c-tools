package httpsafe

import "errors"

// CredentialBindingVersion is the supported local binding metadata version.
const CredentialBindingVersion = 1

// CredentialKind describes how a consumer can use a resolved secret.
type CredentialKind string

const (
	// CredentialAPIKey represents an API key, not a Bearer device token.
	CredentialAPIKey CredentialKind = "api_key"
	// CredentialDeviceBearer represents a device Bearer token.
	CredentialDeviceBearer CredentialKind = "device_bearer"
)

var (
	// ErrCredentialBinding identifies missing, invalid or mismatched metadata.
	ErrCredentialBinding = errors.New("credential binding missing, invalid or mismatched")
	// ErrSecretRead identifies a failed or missing deferred secret reader.
	ErrSecretRead = errors.New("credential secret read failed")
	// ErrEmptySecret identifies an empty secret returned by the selected source.
	ErrEmptySecret = errors.New("credential secret is empty")
)

// CredentialBinding records operator/client provenance, not authenticated issuer
// or tenant authority. Origin must be an origin URL without an API path prefix.
// Source labels the selected source; this helper does not authenticate metadata.
type CredentialBinding struct {
	Version int            `json:"version"`
	Kind    CredentialKind `json:"kind"`
	Origin  string         `json:"origin"`
	Source  string         `json:"source"`
}

// SecretReader reads only the already selected source. It must not silently try
// another source. ResolveCredential invokes it after validating binding metadata.
type SecretReader func() ([]byte, error)

// DeferredSecret separates nonsecret metadata from the operation reading a secret.
type DeferredSecret struct {
	Binding CredentialBinding
	Read    SecretReader
}

// ResolvedCredential contains a validated destination and the selected secret.
// Consumers still own request construction, redirects, secret lifetime and usage.
type ResolvedCredential struct {
	Base    APIBase
	Binding CredentialBinding
	Secret  []byte
}

// ResolveCredential validates target and local binding before invoking Read once.
// No source fallback or legacy unbound assignment occurs. Loopback HTTP requires
// explicit permission for both the destination and the binding. A same-origin
// match does not restrict API paths or prove who issued the credential.
func ResolveCredential(rawBase string, allowLoopbackHTTP bool, selected DeferredSecret) (ResolvedCredential, error) {
	base, err := ParseAPIBase(rawBase, allowLoopbackHTTP)
	if err != nil {
		return ResolvedCredential{}, err
	}
	binding := selected.Binding
	if binding.Version != CredentialBindingVersion || (binding.Kind != CredentialAPIKey && binding.Kind != CredentialDeviceBearer) || binding.Source == "" || unsafeURLText(binding.Source) {
		return ResolvedCredential{}, ErrCredentialBinding
	}
	bound, err := ParseAPIBase(binding.Origin, allowLoopbackHTTP)
	if err != nil || (bound.URL != bound.Origin.String() && bound.URL != bound.Origin.String()+"/") || bound.Origin != base.Origin {
		return ResolvedCredential{}, ErrCredentialBinding
	}
	if selected.Read == nil {
		return ResolvedCredential{}, ErrSecretRead
	}
	secret, err := selected.Read()
	if err != nil {
		return ResolvedCredential{}, &secretReadError{cause: err}
	}
	if len(secret) == 0 {
		return ResolvedCredential{}, ErrEmptySecret
	}
	binding.Origin = bound.Origin.String()
	return ResolvedCredential{Base: base, Binding: binding, Secret: secret}, nil
}

type secretReadError struct{ cause error }

func (e *secretReadError) Error() string        { return ErrSecretRead.Error() }
func (e *secretReadError) Unwrap() error        { return e.cause }
func (e *secretReadError) Is(target error) bool { return target == ErrSecretRead }
