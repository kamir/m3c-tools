package registry

// ER1 bundle transport — SPEC-0225 (Personal Skill Registry & Cross-Machine
// Trust-Mode Distribution via ER1).
//
// This file is the P0 *stub* (PLAN-SPEC-0225 P0.2): it establishes the
// recognizer and the carrier seam so `skillctl publish` / `pull` / `registry`
// (P1/P2) can be built against a stable shape, without yet implementing the
// transport. No behaviour here — every method returns ErrNotImplemented.
//
// Background. The existing registry.Client in this package is the HTTP client
// for the aims-core admission API (SPEC-0188 §5) — it talks to a `--registry
// <url>` endpoint. The ER1 transport is a *different carrier*: it does not call
// that HTTP API. A published bundle event is one ER1 memory item (created via
// POST /upload_2, SPEC-0187) whose body is a SPEC-0190 event verbatim and whose
// payload is either the .skb bytes (base64, inline) or a claim-check pointer
// into MinIO. So `skillctl --registry self` (or `--registry er1://...`) routes
// here, not to registry.Client. The full carrier interface is designed in P1
// against pkg/er1; this stub deliberately keeps the surface tiny.
//
// Wire format (frozen): INFRA/skill-registry/self/WIRE-FORMAT.md in
// m3c-tools-maintenance. Tenant profile: INFRA/skill-registry/env/self.env.

import (
	"errors"
	"strings"
)

// ErrNotImplemented is returned by every ER1Transport method until the P1/P2
// implementation lands. Sentinel-comparable so callers (and tests) can branch.
var ErrNotImplemented = errors.New("registry: ER1 bundle transport not implemented yet (SPEC-0225 P1/P2)")

// ER1RegistrySelf is the well-known registry spec that means "the author's
// personal ER1-mediated registry" — the `self` tenant of SPEC-0225 /
// INFRA/skill-registry/env/self.env. Used as `skillctl ... --registry self`.
const ER1RegistrySelf = "self"

// ER1RegistryScheme is the URL scheme that also selects the ER1 transport, for
// the (rare) case a caller wants to point at a non-default ER1 context
// explicitly, e.g. `er1://prod/skills`. Parsing of the authority/path is P1.
const ER1RegistryScheme = "er1://"

// IsER1Registry reports whether a `--registry` spec selects the ER1 bundle
// transport (this file) rather than the HTTP admission client (registry.Client).
// True for the literal "self" and for any "er1://…" spec; false otherwise
// (including the empty string and http(s) URLs).
func IsER1Registry(spec string) bool {
	return spec == ER1RegistrySelf || strings.HasPrefix(spec, ER1RegistryScheme)
}

// ER1Transport is the (stubbed) carrier for the `self` tenant. Construct via
// NewER1Transport. In P0 it carries only the resolved registry spec; P1 adds
// the pkg/er1 client, the signing key, the inline-size cap, and the MinIO
// overflow handle (all sourced from self.env / trust-roots).
type ER1Transport struct {
	// Spec is the `--registry` value this transport was resolved from
	// ("self" or "er1://…").
	Spec string
}

// NewER1Transport builds the stub transport for the given registry spec. It
// does not validate the spec beyond IsER1Registry (the caller is expected to
// have routed here on that basis); a non-ER1 spec is accepted but every method
// will still return ErrNotImplemented in this build.
func NewER1Transport(spec string) *ER1Transport {
	return &ER1Transport{Spec: spec}
}

// String renders the transport for diagnostics, e.g. `er1-transport(self)`.
func (t *ER1Transport) String() string {
	if t == nil {
		return "er1-transport(<nil>)"
	}
	return "er1-transport(" + t.Spec + ")"
}

// Publish will (P1) pack/sign/attest-check a bundle, build a SPEC-0190
// BundleAdmittedEvent, sign the envelope, place the bytes (inline or MinIO
// claim-check), and POST the ER1 item. Stub: ErrNotImplemented.
func (t *ER1Transport) Publish() error { return ErrNotImplemented }

// Pull will (P2) query ER1 for bundle items, run the five-gate verification
// gauntlet (envelope sig → digest → author+registry sigs → governance floor →
// not-revoked), and stage verified bundles. Stub: ErrNotImplemented.
func (t *ER1Transport) Pull() error { return ErrNotImplemented }

// List will (P2) return the registry view — bundle items grouped by skill,
// deduped by digest, with the event timeline. Stub: ErrNotImplemented.
func (t *ER1Transport) List() error { return ErrNotImplemented }

// Get will (P2) return full detail for one bundle digest — envelope,
// signatures, attestations, install events, revocation status. Stub:
// ErrNotImplemented.
func (t *ER1Transport) Get() error { return ErrNotImplemented }

// Revoke will (P2) emit a SPEC-0190 BundleRevokedEvent item. Stub:
// ErrNotImplemented.
func (t *ER1Transport) Revoke() error { return ErrNotImplemented }
