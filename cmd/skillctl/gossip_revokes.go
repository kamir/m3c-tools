package main

// SPEC-0359 D5(b) — git-native revoke-feed gossip.
//
// Peers are git/gitlab/local registries; they do NOT serve the HTTP signed
// revocation-HEAD. Their revocations live as SIGNED SPEC-0190 BundleRevokedEvents
// in events/<digesthex>/. Gossip reads each CONTRIBUTING peer's revoke events,
// verifies them against that peer's PINNED key, and unions the revoked digests
// into a durable GROW-ONLY local cache — so a peer that later omits a revoke can
// never un-revoke it (the anti-rollback for append-only event gossip). The union
// is consulted by the revocation sweep (fetchRevokedWithGossip), so a digest
// revoked by ANY trusted peer is denied even without pulling from that peer.
//
// Availability FAIL-OPEN (unreachable peer → skip, keep last-known-good); integrity
// FAIL-CLOSED (bad signature → drop). Contribution is gated on the peer being a
// governance contributor (peer add --contributes-revokes) to bound revoke-DoS.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func gossipedRevokedPath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "gossiped-revoked.json")
}

type gossipedRevokedFile struct {
	Digests   []string `json:"digests"`
	UpdatedAt string   `json:"updated_at"`
}

// loadGossipedRevoked returns the durable grow-only gossip revoked set.
func loadGossipedRevoked(home string) map[string]struct{} {
	out := map[string]struct{}{}
	b, err := os.ReadFile(gossipedRevokedPath(home))
	if err != nil {
		return out
	}
	var f gossipedRevokedFile
	if json.Unmarshal(b, &f) != nil {
		return out
	}
	for _, d := range f.Digests {
		out[d] = struct{}{}
	}
	return out
}

// mergeGossipedRevoked unions newSet into the persisted GROW-ONLY gossip cache
// (a peer omitting a revoke later can never shrink it) and returns the new total.
func mergeGossipedRevoked(home string, newSet map[string]struct{}, now time.Time) (int, error) {
	union := loadGossipedRevoked(home)
	for d := range newSet {
		union[d] = struct{}{}
	}
	digs := make([]string, 0, len(union))
	for d := range union {
		digs = append(digs, d)
	}
	sort.Strings(digs)
	data, _ := json.MarshalIndent(gossipedRevokedFile{Digests: digs, UpdatedAt: now.UTC().Format(time.RFC3339)}, "", "  ")
	p := gossipedRevokedPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return 0, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, p); err != nil {
		return 0, err
	}
	return len(union), nil
}

type peerGossipReport struct {
	Name, Locator, Status string
	Contributed           int
}

// gossipRevokedDigests reads each CONTRIBUTING peer's signed revoke events and
// unions the verified revoked digests. Non-contributor peers are advisory
// (reported, not unioned). See the file header for the fail-open/fail-closed rules.
func gossipRevokedDigests(peers *registry.Peers) (map[string]struct{}, []peerGossipReport) {
	union := map[string]struct{}{}
	var reports []peerGossipReport
	ctx := context.Background()
	for _, pe := range peers.Peers {
		rep := peerGossipReport{Name: pe.Name, Locator: pe.Locator}
		if !pe.ContributesRevokes {
			rep.Status = "advisory (not a governance contributor)"
			reports = append(reports, rep)
			continue
		}
		tr, err := pe.AsTrustRoots()
		if err != nil {
			rep.Status = "bad pin — skipped: " + err.Error()
			reports = append(reports, rep)
			continue
		}
		be, err := artifact.Open(pe.Locator, artifact.OpenOptions{Creds: artifactauth.New()})
		if err != nil {
			rep.Status = "unreachable (fail-open): " + err.Error()
			reports = append(reports, rep)
			continue
		}
		gl, ok := be.(artifact.GovernanceLog)
		if !ok {
			be.Close()
			rep.Status = "no signed event log"
			reports = append(reports, rep)
			continue
		}
		page, err := gl.Events(ctx, artifact.ListFilter{}, artifact.Page{})
		be.Close()
		if err != nil {
			rep.Status = "read error (fail-open): " + err.Error()
			reports = append(reports, rep)
			continue
		}
		rep.Contributed = unionVerifiedRevokes(page.Events, tr.PubKey(), union)
		rep.Status = "ok"
		reports = append(reports, rep)
	}
	return union, reports
}

// unionVerifiedRevokes adds every SIGNED revoke digest in events (verified against
// pub) into `into` and returns how many it added. Integrity fail-closed.
//
// CRITICAL: the revoke IDENTITY comes from the SIGNED envelope, never the unsigned
// git path. For a git peer both EventRecord.Kind (filename) and .Digest (dir name)
// are attacker-controllable path components; VerifyEnvelopeSignature authenticates
// only the envelope content. So after the signature verifies we (a) confirm it is
// genuinely a REVOKE via the signed `revoked_by` (a field only revokes carry — a
// replayed admit/attest has none, closing the kind-confusion), and (b) union the
// SIGNED `bundle_digest`, rejecting a mismatch with the path digest (a rebind that
// would revoke an attacker-chosen digest). This mirrors the online loadAttestRevoke
// binding (registry/er1_pull.go) that the git-path Kind/Digest projection dropped.
func unionVerifiedRevokes(events []artifact.EventRecord, pub ed25519.PublicKey, into map[string]struct{}) int {
	n := 0
	for _, ev := range events {
		if ev.Kind != artifact.KindRevoke || ev.Envelope == nil {
			continue // cheap pre-filter; the authoritative check is the envelope below
		}
		if registry.VerifyEnvelopeSignature(pub, ev.Envelope) != nil {
			continue // an unsigned/forged event does not count
		}
		if rb, _ := ev.Envelope["revoked_by"].(string); rb == "" {
			continue // signed discriminator: not a revoke envelope (e.g. a replayed admit)
		}
		signedDigest, _ := ev.Envelope["bundle_digest"].(string)
		if signedDigest == "" || signedDigest != ev.Digest {
			continue // digest not signed, or path-rebound to an attacker-chosen digest → drop
		}
		into[signedDigest] = struct{}{} // the SIGNED digest, never the path
		n++
	}
	return n
}

// printGossipReports renders the per-peer gossip outcome.
func printGossipReports(w io.Writer, reports []peerGossipReport) {
	for _, r := range reports {
		suffix := r.Status
		if r.Contributed > 0 {
			suffix = fmt.Sprintf("contributed %d revoke(s)", r.Contributed)
		}
		fmt.Fprintf(w, "  %-16s %-40s %s\n", r.Name, r.Locator, suffix)
	}
}
