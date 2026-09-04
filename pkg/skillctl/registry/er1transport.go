package registry

// ER1 registry recognizer: SPEC-0225 (Personal Skill Registry & Cross-Machine
// Trust-Mode Distribution via ER1).
//
// This file recognizes which `--registry` specs select the ER1 carrier. The
// carrier itself ships as ER1Backend (er1_backend.go), which implements
// artifact.Backend (+ GovernanceLog) and is resolved through artifact.Open;
// the ER1 free functions (er1_publish.go / er1_pull.go) do the publish/pull work.
//
// Background. The existing registry.Client in this package is the HTTP client
// for the aims-core admission API (SPEC-0188 §5): it talks to a `--registry
// <url>` endpoint. The ER1 carrier is a *different carrier*: it does not call
// that HTTP API. A published bundle event is one ER1 memory item (created via
// POST /upload_2, SPEC-0187) whose body is a SPEC-0190 event verbatim and whose
// payload is either the .skb bytes (base64, inline) or a claim-check pointer
// into MinIO. So `skillctl --registry self` (or `--registry er1://...`) routes
// to ER1Backend, not to registry.Client.
//
// Wire format (frozen): INFRA/skill-registry/self/WIRE-FORMAT.md in
// m3c-tools-maintenance. Tenant profile: INFRA/skill-registry/env/self.env.

import "strings"

// ER1RegistrySelf is the well-known registry spec that means "the author's
// personal ER1-mediated registry": the `self` tenant of SPEC-0225 /
// INFRA/skill-registry/env/self.env. Used as `skillctl ... --registry self`.
const ER1RegistrySelf = "self"

// ER1RegistryScheme is the URL scheme that also selects the ER1 carrier, for
// the (rare) case a caller wants to point at a non-default ER1 context
// explicitly, e.g. `er1://prod/skills`.
const ER1RegistryScheme = "er1://"

// IsER1Registry reports whether a `--registry` spec selects the ER1 bundle
// carrier (ER1Backend) rather than the HTTP admission client (registry.Client).
// True for the literal "self" and for any "er1://…" spec; false otherwise
// (including the empty string and http(s) URLs).
func IsER1Registry(spec string) bool {
	return spec == ER1RegistrySelf || strings.HasPrefix(spec, ER1RegistryScheme)
}
