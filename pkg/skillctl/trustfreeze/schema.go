// Package trustfreeze is the platform-neutral core of Trust Freeze
// (SPEC-0466): the common model, canonical JSON, bundle paths, the manifest
// and its content digest, bundle IO, completeness, the clock seam and the
// subject id.
//
// The core executes no probe and signs nothing. Probes live in the probe and
// platform packages, signing lives in seal. Raw evidence reaches disk only as
// a redact.Redacted value (SPEC-0467 R5).
package trustfreeze

import (
	"errors"
	"fmt"
)

// Schema ids. A reader rejects every id it does not know; there is no silent
// migration (SPEC-0466 R8).
const (
	SchemaCapture     = "trust-freeze/capture/v1"
	SchemaBaseline    = "trust-freeze/baseline/v1"
	SchemaDiff        = "trust-freeze/diff/v1"
	SchemaManifest    = "trust-freeze/manifest/v1"
	SchemaApproval    = "trust-freeze/approval/v1"
	SchemaSignature   = "trust-freeze/signature/v1"
	SchemaProfile     = "trust-freeze/profile/v1"
	SchemaPolicy      = "trust-freeze/policy/v1"
	SchemaTrustPolicy = "trust-freeze/trust-policy/v1"
)

// knownSchemas lists every schema id this build understands.
var knownSchemas = []string{
	SchemaCapture,
	SchemaBaseline,
	SchemaDiff,
	SchemaManifest,
	SchemaApproval,
	SchemaSignature,
	SchemaProfile,
	SchemaPolicy,
	SchemaTrustPolicy,
}

// Sentinel errors for schema and kind checks.
var (
	ErrUnknownSchema = errors.New("trustfreeze: unknown schema id")
	ErrUnknownKind   = errors.New("trustfreeze: unknown bundle kind")
)

// KnownSchema reports whether id is one of the schema ids of this build.
func KnownSchema(id string) bool {
	for _, s := range knownSchemas {
		if s == id {
			return true
		}
	}
	return false
}

// CheckSchema returns nil when got equals want and an error wrapping
// ErrUnknownSchema otherwise.
func CheckSchema(got, want string) error {
	if got != want {
		return fmt.Errorf("%w: got %q, want %q", ErrUnknownSchema, got, want)
	}
	return nil
}

// Kind is the bundle kind recorded in manifest.json. It is a closed enum
// (SPEC-0470 TF05-R1): a capture never reads as a baseline.
type Kind string

// Bundle kinds.
const (
	KindCapture  Kind = "capture"
	KindBaseline Kind = "baseline"
	KindDiff     Kind = "diff"
)

var kindValues = []Kind{KindCapture, KindBaseline, KindDiff}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return member(k, kindValues) }

// ParseKind parses a kind strictly.
func ParseKind(s string) (Kind, error) {
	k, err := parseEnum("kind", s, kindValues)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnknownKind, err)
	}
	return k, nil
}

// MarshalText rejects an unknown kind, so an invalid value is never written.
func (k Kind) MarshalText() ([]byte, error) { return marshalEnum("kind", k, kindValues) }

// UnmarshalText parses a kind strictly.
func (k *Kind) UnmarshalText(b []byte) error {
	v, err := ParseKind(string(b))
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known kind.
func (k *Kind) UnmarshalJSON(b []byte) error {
	s, err := jsonEnumString("kind", b)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnknownKind, err)
	}
	return k.UnmarshalText([]byte(s))
}

// Bundle file layout (SPEC-0466, SPEC-0470). All paths are canonical
// bundle paths (see CanonicalPath).
const (
	ManifestFile    = "manifest.json"
	CaptureFile     = "capture.json"
	ApprovalFile    = "approval.json"
	SignatureFile   = "signatures/manifest.ed25519.json"
	SignaturesDir   = "signatures"
	StateDeviceFile = "state/device.json"
	ProbesDir       = "probes"
	EvidenceDir     = "evidence"
)
