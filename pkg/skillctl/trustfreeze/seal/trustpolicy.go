package seal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// SelfApprovalMode says what a detected self-approval does (SPEC-0470
// TF05-R7).
type SelfApprovalMode string

// Self-approval modes. The zero value behaves as SelfApprovalWarn; an unknown
// value behaves as SelfApprovalBlock (fail closed).
const (
	SelfApprovalAllow SelfApprovalMode = "allow"
	SelfApprovalWarn  SelfApprovalMode = "warn"
	SelfApprovalBlock SelfApprovalMode = "block"
)

// ParseSelfApprovalMode parses a mode strictly.
func ParseSelfApprovalMode(s string) (SelfApprovalMode, error) {
	m := SelfApprovalMode(s)
	if !m.Valid() {
		return "", fmt.Errorf("%w: self_approval %q (want allow, warn or block)", ErrTrustPolicyInvalid, s)
	}
	return m, nil
}

// Valid reports whether m is one of the three modes.
func (m SelfApprovalMode) Valid() bool {
	return m == SelfApprovalAllow || m == SelfApprovalWarn || m == SelfApprovalBlock
}

// effective maps the zero value to warn and an unknown value to block.
func (m SelfApprovalMode) effective() SelfApprovalMode {
	switch {
	case m == "":
		return SelfApprovalWarn
	case m.Valid():
		return m
	default:
		return SelfApprovalBlock
	}
}

// TrustedKey is a public key a verifier accepts for baseline signatures.
// KeyID is optional; when set it must equal KeyIDFor(PublicKey).
type TrustedKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

// TrustPolicy is the verifier's trust configuration (SPEC-0470 section
// 4.6).
type TrustPolicy struct {
	// TrustedKeys lists the accepted signing keys. A baseline signed by any
	// other key fails with key_not_trusted, while the cryptographic result is
	// still reported separately.
	TrustedKeys []TrustedKey
	// SelfApproval: allow, warn (default) or block.
	SelfApproval SelfApprovalMode
	// RejectAdditions is part of the trust-policy schema. This version always
	// rejects files that the manifest does not list (VerifyDir reports each as
	// "extra", every manifest of this build says reject_additions:true), and a
	// policy file that asks for false is refused as not implemented. The Go
	// zero value therefore cannot relax anything.
	RejectAdditions bool
	// Now is the clock for expiry checks. nil means trustfreeze.SystemClock.
	Now trustfreeze.Clock
}

// ErrTrustPolicyInvalid is wrapped by trust policy loading and validation
// errors.
var ErrTrustPolicyInvalid = errors.New("seal: trust policy is invalid")

// DefaultTrustPolicy returns the default policy: no trusted keys, warn on
// self-approval, reject additions, system clock.
func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{SelfApproval: SelfApprovalWarn, RejectAdditions: true, Now: trustfreeze.SystemClock{}}
}

// NewTrustedKey returns the trusted key entry for pub.
func NewTrustedKey(pub ed25519.PublicKey) (TrustedKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return TrustedKey{}, fmt.Errorf("%w: public key has length %d, want %d", ErrTrustPolicyInvalid, len(pub), ed25519.PublicKeySize)
	}
	own := make(ed25519.PublicKey, len(pub))
	copy(own, pub)
	return TrustedKey{KeyID: KeyIDFor(own), PublicKey: own}, nil
}

// LoadTrustedKeyPEM reads a PEM/SPKI ed25519 public key file (the .pub file
// written by `skillctl keygen`) through signing.LoadPublicKey. It backs the
// repeatable --trusted-key flag.
func LoadTrustedKeyPEM(path string) (TrustedKey, error) {
	pub, err := signing.LoadPublicKey(path)
	if err != nil {
		return TrustedKey{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
	}
	return NewTrustedKey(pub)
}

// Validate checks the policy: a valid (or empty) self-approval mode and well
// formed, unique trusted keys whose key ids, when given, match their keys.
func (p TrustPolicy) Validate() error {
	if p.SelfApproval != "" && !p.SelfApproval.Valid() {
		return fmt.Errorf("%w: self_approval %q", ErrTrustPolicyInvalid, p.SelfApproval)
	}
	seen := map[string]bool{}
	for i, k := range p.TrustedKeys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: trusted_keys[%d]: public key has length %d, want %d", ErrTrustPolicyInvalid, i, len(k.PublicKey), ed25519.PublicKeySize)
		}
		id := KeyIDFor(k.PublicKey)
		if k.KeyID != "" && k.KeyID != id {
			return fmt.Errorf("%w: trusted_keys[%d]: key_id %q does not belong to the key (want %q)", ErrTrustPolicyInvalid, i, k.KeyID, id)
		}
		if seen[string(k.PublicKey)] {
			return fmt.Errorf("%w: trusted_keys[%d]: key %s is listed twice", ErrTrustPolicyInvalid, i, id)
		}
		seen[string(k.PublicKey)] = true
	}
	return nil
}

// Trusts reports whether pub is one of the trusted keys (full key
// comparison; the key id is never the deciding value).
func (p TrustPolicy) Trusts(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	for _, k := range p.TrustedKeys {
		if bytes.Equal(k.PublicKey, pub) {
			return true
		}
	}
	return false
}

func (p TrustPolicy) clock() trustfreeze.Clock {
	if p.Now == nil {
		return trustfreeze.SystemClock{}
	}
	return p.Now
}

// trustPolicyFile is the file form (schema trust-freeze/trust-policy/v1):
//
//	schema_version: trust-freeze/trust-policy/v1
//	self_approval: warn            # allow | warn | block, default warn
//	reject_additions: true         # optional; false is not implemented
//	trusted_keys:
//	  - key_id: ed25519:0123456789abcdef   # optional, checked when present
//	    public_key: <base64 of the raw 32-byte ed25519 public key>
type trustPolicyFile struct {
	SchemaVersion   string           `json:"schema_version" yaml:"schema_version"`
	SelfApproval    string           `json:"self_approval,omitempty" yaml:"self_approval,omitempty"`
	RejectAdditions *bool            `json:"reject_additions,omitempty" yaml:"reject_additions,omitempty"`
	TrustedKeys     []trustedKeyFile `json:"trusted_keys" yaml:"trusted_keys"`
}

type trustedKeyFile struct {
	KeyID     string `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// maxTrustPolicyBytes caps a trust policy file.
const maxTrustPolicyBytes = 1 << 20

// ParseTrustPolicy parses a trust policy file in JSON (first non-blank byte
// "{") or YAML. Unknown fields, a second YAML document, an unknown schema id
// and malformed keys are errors. Both forms parse alike: a duplicate key and
// a key that differs from a field name only by letter case are errors in
// JSON too (encoding/json alone would keep the last duplicate and match names
// case-insensitively, so one file could read as block and act as allow). Now
// is set to trustfreeze.SystemClock; tests and callers with an injected clock
// replace it.
func ParseTrustPolicy(b []byte) (TrustPolicy, error) {
	var f trustPolicyFile
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) == 0 {
		return TrustPolicy{}, fmt.Errorf("%w: empty document", ErrTrustPolicyInvalid)
	}
	if trimmed[0] == '{' {
		if err := checkJSONKeys(trimmed, trustPolicyKeys); err != nil {
			return TrustPolicy{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
		}
		if err := trustfreeze.UnmarshalStrict(trimmed, &f); err != nil {
			return TrustPolicy{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
		}
	} else {
		dec := yaml.NewDecoder(bytes.NewReader(trimmed))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return TrustPolicy{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return TrustPolicy{}, fmt.Errorf("%w: more than one YAML document", ErrTrustPolicyInvalid)
		}
	}
	if err := trustfreeze.CheckSchema(f.SchemaVersion, trustfreeze.SchemaTrustPolicy); err != nil {
		return TrustPolicy{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
	}
	p := DefaultTrustPolicy()
	if f.SelfApproval != "" {
		m, err := ParseSelfApprovalMode(f.SelfApproval)
		if err != nil {
			return TrustPolicy{}, err
		}
		p.SelfApproval = m
	}
	if f.RejectAdditions != nil && !*f.RejectAdditions {
		return TrustPolicy{}, fmt.Errorf("%w: reject_additions false is not implemented in this version", ErrTrustPolicyInvalid)
	}
	for i, k := range f.TrustedKeys {
		pub, err := decodeB64(k.PublicKey, ed25519.PublicKeySize)
		if err != nil {
			return TrustPolicy{}, fmt.Errorf("%w: trusted_keys[%d].public_key: %w", ErrTrustPolicyInvalid, i, err)
		}
		p.TrustedKeys = append(p.TrustedKeys, TrustedKey{KeyID: k.KeyID, PublicKey: ed25519.PublicKey(pub)})
	}
	if err := p.Validate(); err != nil {
		return TrustPolicy{}, err
	}
	return p, nil
}

// trustPolicyKeys are the field names of the trust policy file form, at any
// level. Placement is checked by the strict decoder; checkJSONKeys only makes
// sure that every key is spelled exactly and appears once per object.
var trustPolicyKeys = map[string]bool{
	"schema_version": true, "self_approval": true, "reject_additions": true,
	"trusted_keys": true, "key_id": true, "public_key": true,
}

// checkJSONKeys walks a JSON document token by token and rejects a key that
// appears twice in one object or that is not exactly one of known.
func checkJSONKeys(b []byte, known map[string]bool) error {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top != nil && top.object {
					top.expectKey = true // this value ends the current pair
				}
				stack = append(stack, &frame{object: d == '{', expectKey: d == '{', keys: map[string]bool{}})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if !top.expectKey {
			top.expectKey = true // a scalar value ends the current pair
			continue
		}
		key, _ := tok.(string)
		if !known[key] {
			return fmt.Errorf("unknown field %q (field names are exact and case-sensitive)", key)
		}
		if top.keys[key] {
			return fmt.Errorf("field %q appears more than once", key)
		}
		top.keys[key] = true
		top.expectKey = false
	}
}

// LoadTrustPolicy reads and parses a trust policy file (at most 1 MiB).
func LoadTrustPolicy(path string) (TrustPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return TrustPolicy{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxTrustPolicyBytes+1))
	if err != nil {
		return TrustPolicy{}, fmt.Errorf("%w: %w", ErrTrustPolicyInvalid, err)
	}
	if len(b) > maxTrustPolicyBytes {
		return TrustPolicy{}, fmt.Errorf("%w: file is larger than %d bytes", ErrTrustPolicyInvalid, maxTrustPolicyBytes)
	}
	return ParseTrustPolicy(b)
}

// MarshalTrustPolicy returns the JSON file form of p (MarshalFile), for
// writing a policy a verifier can load. Now is not part of the file.
func MarshalTrustPolicy(p TrustPolicy) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	f := trustPolicyFile{SchemaVersion: trustfreeze.SchemaTrustPolicy, SelfApproval: string(p.SelfApproval.effective()), TrustedKeys: []trustedKeyFile{}}
	t := true
	f.RejectAdditions = &t
	for _, k := range p.TrustedKeys {
		f.TrustedKeys = append(f.TrustedKeys, trustedKeyFile{KeyID: KeyIDFor(k.PublicKey), PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey)})
	}
	return trustfreeze.MarshalFile(f)
}
