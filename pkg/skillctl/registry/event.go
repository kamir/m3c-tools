package registry

// SPEC-0190 event types + envelope signing for the ER1 bundle transport
// (SPEC-0225). Three event shapes are SPEC-0190 verbatim (BundleAdmittedEvent
// §3.1, AttestationPublishedEvent §3.2, BundleRevokedEvent §3.3); a fourth —
// BundleInstalledEvent — is new in SPEC-0225 §6.3 (proposed into SPEC-0190 as
// §3.4 on adoption).
//
// Wire-format invariant: the item body IS the event JSON, verbatim. A future
// `skillctl publish --bus kafka` would emit the same bytes onto
// `m3c.<env>.skill_bundles.*`. We deliberately do not invent a new envelope.
//
// Canonical bytes. Events are represented as map[string]any so that JSON
// marshaling produces alphabetically-sorted keys at every level (Go's
// encoding/json marshals map keys alphabetically since Go 1.12; structs would
// marshal in declaration order — wrong). The canonical bytes are the
// JSON-marshal of the event *with envelope_signature removed*, HTML-escape off,
// no trailing newline. This is what the producer signs and what the consumer
// re-marshals before Verify.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Event kind tag values (the `skill-event:<kind>` ER1 tag).
const (
	EventKindAdmitted  = "admitted"
	EventKindAttested  = "attested"
	EventKindRevoked   = "revoked"
	EventKindInstalled = "installed"
)

// EventSchemaVersion is the SPEC-0190 event schema version. Bumping this is a
// breaking change for any consumer; the `skb-transport-version:<n>` tag on the
// ER1 item carries it in addition so consumers can filter by version.
const EventSchemaVersion = "1.0.0"

// SkbTransportVersion is the wire-format version of the ER1 bundle transport
// (SPEC-0225 §6 / INFRA/skill-registry/self/WIRE-FORMAT.md). v2 will be a clean
// tag filter, never an in-place format mutation.
const SkbTransportVersion = 1

// EnvelopeSignatureField is the JSON key under which the ed25519 signature
// over the canonical event bytes is stored. Removed before canonicalization.
const EnvelopeSignatureField = "envelope_signature"

// ─── Errors ────────────────────────────────────────────────────────────────

var (
	// ErrInvalidEvent is returned for events missing required fields or with
	// fields of the wrong shape (e.g. bundle_digest not starting with "sha256:").
	ErrInvalidEvent = errors.New("registry: invalid SPEC-0190 event")

	// ErrEnvelopeSignatureMissing is returned by VerifyEnvelopeSignature when
	// the event has no `envelope_signature` field. Distinct from ErrInvalidEvent
	// so callers can branch ("unsigned event") vs ("malformed event").
	ErrEnvelopeSignatureMissing = errors.New("registry: envelope_signature missing")

	// ErrEnvelopeSignatureInvalid is returned by VerifyEnvelopeSignature when
	// the signature does not verify against the supplied public key.
	ErrEnvelopeSignatureInvalid = errors.New("registry: envelope_signature does not verify")
)

// ─── Event constructors ────────────────────────────────────────────────────

// SignatureRef is one entry of an event's `signatures` array (admitted events
// only). Mirrors SPEC-0190 §3.1.
type SignatureRef struct {
	Role               string // "author" | "registry"
	IdentityID         string // e.g. "id:kamir@m3c"
	SignatureB64       string // base64 ed25519 detached signature over the bundle digest
	PubKeyFingerprint  string // "sha256:<hex>"
}

func (s SignatureRef) toMap() map[string]any {
	return map[string]any{
		"role":               s.Role,
		"identity_id":        s.IdentityID,
		"signature_b64":      s.SignatureB64,
		"pubkey_fingerprint": s.PubKeyFingerprint,
	}
}

// AdmittedEventInput is the typed input for BuildBundleAdmittedEvent.
type AdmittedEventInput struct {
	BundleDigest        string         // "sha256:<hex>"
	Name                string         // skill name
	Version             string         // skill version (semver-ish, no leading 'v')
	AuthorIntent        string         // "green" | "yellow" | "red"
	AdmittedByIdentity  string         // "id:kamir@m3c" for the self tenant
	AdmittedAt          time.Time      // event ts (UTC)
	BlobURI             string         // empty for transport:er1-inline
	Signatures          []SignatureRef // author + registry refs
	TenantScope         *string        // nil for self
}

// BuildBundleAdmittedEvent constructs the SPEC-0190 §3.1 event payload.
// Caller signs the result with SignEnvelopeSignature, which inserts the
// `envelope_signature` field in-place.
func BuildBundleAdmittedEvent(in AdmittedEventInput) (map[string]any, error) {
	if err := validateDigest(in.BundleDigest); err != nil {
		return nil, err
	}
	if in.Name == "" || in.Version == "" {
		return nil, fmt.Errorf("%w: name and version required", ErrInvalidEvent)
	}
	if !isGovernanceLevel(in.AuthorIntent) {
		return nil, fmt.Errorf("%w: author_intent %q not in {green,yellow,red}", ErrInvalidEvent, in.AuthorIntent)
	}
	if in.AdmittedByIdentity == "" {
		return nil, fmt.Errorf("%w: admitted_by_identity required", ErrInvalidEvent)
	}
	if len(in.Signatures) < 2 {
		// SPEC-0188: every admitted bundle carries both an author and a registry
		// signature. The personal tenant uses the same key for both roles; the
		// records list still distinguishes them.
		return nil, fmt.Errorf("%w: need at least 2 signature refs (author + registry)", ErrInvalidEvent)
	}
	sigs := make([]any, 0, len(in.Signatures))
	for _, s := range in.Signatures {
		sigs = append(sigs, s.toMap())
	}
	ev := map[string]any{
		"schema_version":       EventSchemaVersion,
		"event_id":             newEventID(),
		"occurred_at":          rfc3339(in.AdmittedAt),
		"bundle_digest":        in.BundleDigest,
		"name":                 in.Name,
		"version":              in.Version,
		"author_intent":        in.AuthorIntent,
		"admitted_by_identity": in.AdmittedByIdentity,
		"admitted_at":          rfc3339(in.AdmittedAt),
		"blob_uri":             nilIfEmpty(in.BlobURI),
		"signatures":           sigs,
		"tenant_scope":         derefOrNil(in.TenantScope),
	}
	return ev, nil
}

// AttestedEventInput is the typed input for BuildAttestationPublishedEvent.
type AttestedEventInput struct {
	BundleDigest    string
	AttestationID   string // optional — generated if empty
	ReviewerID      string // "id:kamir@m3c" for the self tenant
	GovernanceLevel string // "green" | "yellow" | "red"
	Rationale       string
	OccurredAt      time.Time
	TenantScope     *string
}

// BuildAttestationPublishedEvent constructs the SPEC-0190 §3.2 event payload.
func BuildAttestationPublishedEvent(in AttestedEventInput) (map[string]any, error) {
	if err := validateDigest(in.BundleDigest); err != nil {
		return nil, err
	}
	if !isGovernanceLevel(in.GovernanceLevel) {
		return nil, fmt.Errorf("%w: governance_level %q not in {green,yellow,red}", ErrInvalidEvent, in.GovernanceLevel)
	}
	if in.ReviewerID == "" {
		return nil, fmt.Errorf("%w: reviewer_id required", ErrInvalidEvent)
	}
	attID := in.AttestationID
	if attID == "" {
		attID = newEventID()
	}
	ev := map[string]any{
		"schema_version":   EventSchemaVersion,
		"event_id":         newEventID(),
		"occurred_at":      rfc3339(in.OccurredAt),
		"bundle_digest":    in.BundleDigest,
		"attestation_id":   attID,
		"reviewer_id":      in.ReviewerID,
		"governance_level": in.GovernanceLevel,
		"rationale":        in.Rationale,
		"tenant_scope":     derefOrNil(in.TenantScope),
	}
	return ev, nil
}

// RevokedEventInput is the typed input for BuildBundleRevokedEvent.
type RevokedEventInput struct {
	BundleDigest string
	ReasonCode   string // free-form short tag, e.g. "key-compromise" or "deprecated"
	Rationale    string
	RevokedBy    string // identity id
	OccurredAt   time.Time
	TenantScope  *string
}

// BuildBundleRevokedEvent constructs the SPEC-0190 §3.3 event payload.
func BuildBundleRevokedEvent(in RevokedEventInput) (map[string]any, error) {
	if err := validateDigest(in.BundleDigest); err != nil {
		return nil, err
	}
	if in.RevokedBy == "" {
		return nil, fmt.Errorf("%w: revoked_by required", ErrInvalidEvent)
	}
	ev := map[string]any{
		"schema_version": EventSchemaVersion,
		"event_id":       newEventID(),
		"occurred_at":    rfc3339(in.OccurredAt),
		"bundle_digest":  in.BundleDigest,
		"reason_code":    in.ReasonCode,
		"rationale":      in.Rationale,
		"revoked_by":     in.RevokedBy,
		"revoked_at":     rfc3339(in.OccurredAt),
		"tenant_scope":   derefOrNil(in.TenantScope),
	}
	return ev, nil
}

// InstalledEventInput is the typed input for BuildBundleInstalledEvent
// (SPEC-0225 §6.3 — the one event shape new in this SPEC; proposed into
// SPEC-0190 as §3.4 on adoption).
type InstalledEventInput struct {
	BundleDigest          string
	Name                  string
	Version               string
	InstalledOnHost       string // short hostname
	InstalledAt           time.Time
	TrustRootsFingerprint string // "sha256:<hex>"
	Registry              string // e.g. "self"
	TenantScope           *string
}

// BuildBundleInstalledEvent constructs the new event payload.
func BuildBundleInstalledEvent(in InstalledEventInput) (map[string]any, error) {
	if err := validateDigest(in.BundleDigest); err != nil {
		return nil, err
	}
	if in.Name == "" || in.Version == "" {
		return nil, fmt.Errorf("%w: name and version required", ErrInvalidEvent)
	}
	if in.InstalledOnHost == "" {
		return nil, fmt.Errorf("%w: installed_on_host required", ErrInvalidEvent)
	}
	if in.Registry == "" {
		return nil, fmt.Errorf("%w: registry required (e.g. \"self\")", ErrInvalidEvent)
	}
	ev := map[string]any{
		"schema_version":          EventSchemaVersion,
		"event_id":                newEventID(),
		"occurred_at":             rfc3339(in.InstalledAt),
		"bundle_digest":           in.BundleDigest,
		"name":                    in.Name,
		"version":                 in.Version,
		"installed_on_host":       in.InstalledOnHost,
		"installed_at":            rfc3339(in.InstalledAt),
		"trust_roots_fingerprint": in.TrustRootsFingerprint,
		"registry":                in.Registry,
		"tenant_scope":            derefOrNil(in.TenantScope),
	}
	return ev, nil
}

// ─── Canonical bytes + envelope sign/verify ────────────────────────────────

// CanonicalEventBytes returns the JSON bytes that the envelope signature is
// computed over: the event marshaled WITHOUT the envelope_signature field,
// with HTML escape disabled (so '<', '>', '&' pass through literal), and
// without a trailing newline. Map keys are sorted alphabetically at every
// level by encoding/json (Go ≥ 1.12).
func CanonicalEventBytes(ev map[string]any) ([]byte, error) {
	if ev == nil {
		return nil, fmt.Errorf("%w: event is nil", ErrInvalidEvent)
	}
	// Make a shallow copy that omits envelope_signature. We don't deep-copy
	// because we never mutate nested structures here.
	cp := make(map[string]any, len(ev))
	for k, v := range ev {
		if k == EnvelopeSignatureField {
			continue
		}
		cp[k] = v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cp); err != nil {
		return nil, fmt.Errorf("canonicalize event: %w", err)
	}
	// Encode appends a newline; strip it so the canonical form is
	// JSON-only, no terminator. (Matches Python json.dumps(...).encode().)
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// SignEnvelopeSignature computes the ed25519 signature of the canonical event
// bytes and inserts it under envelope_signature (base64-encoded). Returns the
// raw signature bytes (the in-place mutation of ev is the convenient surface;
// the returned value is what consumers re-derive).
func SignEnvelopeSignature(priv ed25519.PrivateKey, ev map[string]any) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid ed25519 private key size %d", ErrInvalidEvent, len(priv))
	}
	canon, err := CanonicalEventBytes(ev)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	ev[EnvelopeSignatureField] = base64.StdEncoding.EncodeToString(sig)
	return sig, nil
}

// VerifyEnvelopeSignature checks the event's envelope_signature against the
// supplied public key. Returns ErrEnvelopeSignatureMissing if no signature is
// present, ErrEnvelopeSignatureInvalid on mismatch.
func VerifyEnvelopeSignature(pub ed25519.PublicKey, ev map[string]any) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid ed25519 public key size %d", ErrInvalidEvent, len(pub))
	}
	raw, ok := ev[EnvelopeSignatureField]
	if !ok {
		return ErrEnvelopeSignatureMissing
	}
	sigB64, ok := raw.(string)
	if !ok || sigB64 == "" {
		return fmt.Errorf("%w: envelope_signature is not a non-empty string", ErrInvalidEvent)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: envelope_signature not valid base64: %v", ErrInvalidEvent, err)
	}
	canon, err := CanonicalEventBytes(ev)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, sig) {
		return ErrEnvelopeSignatureInvalid
	}
	return nil
}

// ─── helpers ───────────────────────────────────────────────────────────────

func validateDigest(d string) error {
	const prefix = "sha256:"
	if len(d) != len(prefix)+64 || d[:len(prefix)] != prefix {
		return fmt.Errorf("%w: bundle_digest %q not in form sha256:<64-hex>", ErrInvalidEvent, d)
	}
	for i := len(prefix); i < len(d); i++ {
		c := d[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return fmt.Errorf("%w: bundle_digest %q has non-lowercase-hex char at %d", ErrInvalidEvent, d, i)
		}
	}
	return nil
}

func isGovernanceLevel(s string) bool {
	return s == "green" || s == "yellow" || s == "red"
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func newEventID() string {
	// Best-effort; if uuid generation ever fails (it doesn't on supported
	// platforms with /dev/urandom), fall back to a short random hex.
	if id, err := uuid.NewRandomFromReader(rand.Reader); err == nil {
		return id.String()
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func derefOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
