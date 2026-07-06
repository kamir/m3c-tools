package registry

// SPEC-0279 R4 (signed freshness checkpoint) / FR-0045 D1 — the G5 kill-switch
// feed HEAD.
//
// A RevocationHead is a signed, monotonic pointer at the current revoked-digest
// set: {epoch, issued_at, revoked_set_root, emergency}. It is NOT a new envelope
// — it reuses the SPEC-0190 canonical bytes + ed25519 signing from event.go
// verbatim (CanonicalEventBytes / SignEnvelopeSignature / VerifyEnvelopeSignature),
// so the HEAD is just another event shape on the same wire. The registry key
// signs it; verifiers pin that key via trust-roots (ActiveKeys).
//
// Why a HEAD at all: a verifier that only fetches the revoked *set* cannot tell
// a fresh snapshot from a stale one, so it silently fails open. The HEAD carries
// a monotonic `epoch` (rollback protection) and an `issued_at` (freshness), and
// binds itself to the full set via `revoked_set_root` so a truncated or forged
// set is detectable. Per the 2026-07-06 BDR, the signed HEAD — not the transport
// (HTTP/ER1/Kafka) — is the source of truth; the transport only carries it.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RevocationHeadSchema is the value of the head's `schema_version` field. Bumping
// it is a breaking change for any consumer.
const RevocationHeadSchema = "m3c-revocation-head/v1"

var (
	// ErrInvalidHead is returned for a head missing required fields or with
	// fields of the wrong shape.
	ErrInvalidHead = errors.New("registry: invalid revocation head")

	// ErrHeadRollback is returned when a head's epoch is lower than the highest
	// epoch a verifier has already accepted (SPEC-0279 R1 rollback protection).
	ErrHeadRollback = errors.New("registry: revocation head epoch went backwards")

	// ErrHeadSetRootMismatch is returned when a revoked set hashes to a root that
	// does not match the head's revoked_set_root (truncated / forged set).
	ErrHeadSetRootMismatch = errors.New("registry: revoked set does not match head revoked_set_root")
)

// RevocationHeadInput is the typed input for BuildRevocationHead.
type RevocationHeadInput struct {
	Epoch       int       // monotonic; verifier persists the highest seen and refuses lower
	IssuedAt    time.Time // event ts (UTC); freshness anchor
	Digests     []string  // the full revoked set; revoked_set_root is computed from it
	Emergency   []string  // subset of Digests that short-circuits the cadence (R5)
	TenantScope *string   // nil for the self tenant
}

// BuildRevocationHead constructs the signed head payload (unsigned map; caller
// signs with SignEnvelopeSignature, exactly as for the SPEC-0190 events). Digests
// and Emergency are validated; Emergency must be a subset of Digests (an
// emergency-denied digest is by definition revoked).
func BuildRevocationHead(in RevocationHeadInput) (map[string]any, error) {
	if in.Epoch < 0 {
		return nil, fmt.Errorf("%w: epoch must be >= 0, got %d", ErrInvalidHead, in.Epoch)
	}
	inSet := make(map[string]struct{}, len(in.Digests))
	for _, d := range in.Digests {
		if err := validateDigest(d); err != nil {
			return nil, fmt.Errorf("%w: revoked digest: %v", ErrInvalidHead, err)
		}
		inSet[d] = struct{}{}
	}
	for _, e := range in.Emergency {
		if err := validateDigest(e); err != nil {
			return nil, fmt.Errorf("%w: emergency digest: %v", ErrInvalidHead, err)
		}
		if _, ok := inSet[e]; !ok {
			return nil, fmt.Errorf("%w: emergency digest %s not in revoked set", ErrInvalidHead, e)
		}
	}
	emergency := dedupeSortedAny(in.Emergency)
	head := map[string]any{
		"schema_version":   RevocationHeadSchema,
		"event_id":         newEventID(),
		"occurred_at":      rfc3339(in.IssuedAt),
		"epoch":            in.Epoch,
		"issued_at":        rfc3339(in.IssuedAt),
		"revoked_set_root": ComputeRevokedSetRoot(in.Digests),
		"revoked_count":    len(inSet),
		"emergency":        emergency,
		"tenant_scope":     derefOrNil(in.TenantScope),
	}
	return head, nil
}

// ComputeRevokedSetRoot returns "sha256:<hex>" over the deduped, sorted revoked
// digest set joined by '\n' (no trailing newline). Deterministic and independent
// of input order/duplication, so producer and verifier agree. The empty set
// hashes the empty string.
func ComputeRevokedSetRoot(digests []string) string {
	sorted := dedupeSorted(digests)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

// VerifyRevocationHeadSet recomputes the root over the supplied revoked set and
// compares it to the head's revoked_set_root. Call this AFTER the envelope
// signature verifies, to bind the (separately transported) set to the signed head.
func VerifyRevocationHeadSet(head map[string]any, digests []string) error {
	want, err := headString(head, "revoked_set_root")
	if err != nil {
		return err
	}
	got := ComputeRevokedSetRoot(digests)
	if got != want {
		return fmt.Errorf("%w: got %s want %s", ErrHeadSetRootMismatch, got, want)
	}
	return nil
}

// HeadEpoch extracts the epoch as an int, tolerating both an in-process map (int)
// and a JSON-decoded map (float64 / json.Number).
func HeadEpoch(head map[string]any) (int, error) {
	raw, ok := head["epoch"]
	if !ok {
		return 0, fmt.Errorf("%w: epoch missing", ErrInvalidHead)
	}
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("%w: epoch %q not an integer", ErrInvalidHead, v.String())
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("%w: epoch has unexpected type %T", ErrInvalidHead, raw)
	}
}

// HeadIssuedAt extracts and parses the head's issued_at (RFC3339 UTC).
func HeadIssuedAt(head map[string]any) (time.Time, error) {
	s, err := headString(head, "issued_at")
	if err != nil {
		return time.Time{}, err
	}
	t, perr := time.Parse(time.RFC3339, s)
	if perr != nil {
		return time.Time{}, fmt.Errorf("%w: issued_at %q not RFC3339: %v", ErrInvalidHead, s, perr)
	}
	return t.UTC(), nil
}

// HeadEmergency returns the head's emergency deny-list as a string slice.
func HeadEmergency(head map[string]any) ([]string, error) {
	raw, ok := head["emergency"]
	if !ok {
		return nil, nil // absent == empty
	}
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%w: emergency entry not a string (%T)", ErrInvalidHead, e)
			}
			out = append(out, s)
		}
		return out, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: emergency has unexpected type %T", ErrInvalidHead, raw)
	}
}

// CheckEpochMonotonic returns ErrHeadRollback if the head's epoch is below the
// highest epoch the verifier has already accepted (SPEC-0279 R1). persistedMax is
// the verifier's stored floor (0 if none seen yet).
func CheckEpochMonotonic(head map[string]any, persistedMax int) error {
	epoch, err := HeadEpoch(head)
	if err != nil {
		return err
	}
	if epoch < persistedMax {
		return fmt.Errorf("%w: head epoch %d < accepted floor %d", ErrHeadRollback, epoch, persistedMax)
	}
	return nil
}

// AdoptRevocationHead is the client's gate for accepting a fetched HEAD before
// it advances its freshness/epoch. It composes, in fail-closed order:
//  1. the envelope signature against the pinned registry key (event.go),
//  2. epoch monotonicity against the client's persisted floor (R1 rollback),
//  3. that the separately-transported set binds to the head's revoked_set_root.
// On success it returns the epoch + issued_at to persist. On ANY failure the
// client MUST NOT advance its epoch or treat the snapshot as fresh — the gate
// (SPEC-0247 / FR-0045 D4) then applies the fail-closed staleness policy.
func AdoptRevocationHead(pub ed25519.PublicKey, head map[string]any, set []string, persistedEpoch int) (epoch int, issuedAt time.Time, err error) {
	if err = VerifyEnvelopeSignature(pub, head); err != nil {
		return 0, time.Time{}, err
	}
	if err = CheckEpochMonotonic(head, persistedEpoch); err != nil {
		return 0, time.Time{}, err
	}
	if err = VerifyRevocationHeadSet(head, set); err != nil {
		return 0, time.Time{}, err
	}
	if epoch, err = HeadEpoch(head); err != nil {
		return 0, time.Time{}, err
	}
	if issuedAt, err = HeadIssuedAt(head); err != nil {
		return 0, time.Time{}, err
	}
	return epoch, issuedAt, nil
}

// ─── helpers ───────────────────────────────────────────────────────────────

func headString(head map[string]any, key string) (string, error) {
	raw, ok := head[key]
	if !ok {
		return "", fmt.Errorf("%w: %s missing", ErrInvalidHead, key)
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%w: %s not a non-empty string", ErrInvalidHead, key)
	}
	return s, nil
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func dedupeSortedAny(in []string) []any {
	sorted := dedupeSorted(in)
	out := make([]any, len(sorted))
	for i, s := range sorted {
		out[i] = s
	}
	return out
}
