// Package artifact defines the pluggable artifact-repository abstraction for
// skillctl (SPEC-0356). ER1, the HTTP admission API, GitHub/GitLab repos, and
// OCI registries are peers behind Backend: "repositories that support an
// artifact lifecycle." The invariant across every backend is the content
// digest (sha256:<hex>); everything else is a backend-native projection of the
// SAME SPEC-0190 event envelope.
//
// This package is a LEAF by design: it imports nothing from
// pkg/skillctl/registry or any backend package, so those packages can implement
// the interface without an import cycle — the database/sql driver pattern.
// Backends Register themselves from init(); callers reach them only via Open.
//
// The trust core is deliberately NOT part of this interface. A Backend's only
// trust job is to carry the same signed event bytes and the same .skb bytes,
// and to make them available for the (unchanged) SPEC-0188 §7 verifier. Trust
// lives in the detached Ed25519 signature chain + the pinned trust-roots, never
// in the backend — verify.Verify recomputes the digest and re-checks every
// signature against pinned keys, so "backends are untrusted-but-available."
package artifact

import (
	"context"
	"io"
)

// Backend is the pluggable artifact-repository abstraction. Every method maps
// to behaviour the ER1 carrier already implements today (er1_publish.go /
// er1_pull.go); the git/OCI backends implement the same shape natively.
type Backend interface {
	// Describe returns the backend's identity + declared capability set.
	// Callers read this to know which flags are legal and how to degrade —
	// never by probing methods and catching errors.
	Describe() Descriptor

	// Publish emits ONE lifecycle event. For KindAdmit the .skb Blob is
	// required (it is the artifact); other kinds carry only the signed
	// envelope. KindAdmit MUST be idempotent on Meta.Digest — re-admitting the
	// same digest is a safe no-op that sets PublishResult.AlreadyExists. The
	// governance events (KindAttest/KindRevoke/KindInstall) are APPEND-ONLY by
	// design (the event history is the record): a repeat appends another signed
	// event and idempotency is NOT promised for them.
	Publish(ctx context.Context, req PublishRequest) (*PublishResult, error)

	// List returns one PAGE of the per-skill index, filtered and cursor-
	// paginated. A caller loops until Listing.NextCursor == "". This designs
	// out the single-shot searchByTagsRaw fragility (the "multi-skill pull
	// returns one skill" bug).
	List(ctx context.Context, filter ListFilter, page Page) (*Listing, error)

	// Resolve maps a human handle (name, name@version) or a digest pin
	// (sha256:<hex>) to a concrete, digest-pinned ArtifactRef. "Latest"
	// resolution follows Describe().Capabilities.LatestPolicy — never a
	// hard-coded guess.
	Resolve(ctx context.Context, q RefQuery) (*ArtifactRef, error)

	// Fetch returns the raw .skb bytes for a digest-pinned ref. The caller
	// recomputes sha256 and refuses on mismatch — that recomputation, not the
	// backend, is the integrity check.
	Fetch(ctx context.Context, ref ArtifactRef) ([]byte, error)

	// Closer releases transport resources (HTTP keep-alives, OCI clients).
	io.Closer
}

// GovernanceLog is implemented by backends that keep a server-side, append-only
// event timeline (admit → attest → revoke → install): ER1. A plain git tag
// store does not implement it (its "log" is the committed events/ tree, exposed
// via the git backend's own path); the HTTP admission client does not either
// (it exposes a server-COMPUTED verdict, not raw events).
type GovernanceLog interface {
	Events(ctx context.Context, filter ListFilter, page Page) (*EventPage, error)
}

// Roomer is implemented by backends with SPEC-0096 co-learning rooms: ER1.
// GitHub/GitLab/OCI/HTTP do not; callers degrade with a clear message.
type Roomer interface {
	Share(ctx context.Context, room string, sel RoomSelector) (*RoomResult, error)
	Unshare(ctx context.Context, room string, sel RoomSelector) (*RoomResult, error)
	MatchRoom(ctx context.Context, sel RoomSelector, inRooms ...string) (*RoomMatch, error)
}

// IdentityDirectory is implemented by backends that expose a pubkey directory
// keyed by identity id: the HTTP admission API. ER1 does not — its trust anchor
// is the single pinned trust-roots key, not a server lookup.
type IdentityDirectory interface {
	Identity(ctx context.Context, id string) (*Identity, error)
}

// Descriptor is a backend's self-description: its scheme key, a human label,
// and its declared capabilities.
type Descriptor struct {
	// Scheme is the factory key: "er1" | "https" | "github" | "gitlab" | "oci".
	Scheme string
	// Display is a human-readable label, e.g. "ER1 self tenant (ctx=…___skills)".
	Display string
	// Capabilities declares what this backend can and cannot do.
	Capabilities Capabilities
}
