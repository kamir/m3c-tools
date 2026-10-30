package main

// Git registries serve no revocation HEAD, so their signed revoke events reach the
// load-time gate through the durable grow-only set in gossip_revokes.go: every pull
// and every sweep verifies them against the pinned key and unions them in.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifactauth"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// gitRevocationReadTimeout bounds one registry read, because the sweep also runs at
// session start and must not hang on a slow remote.
const gitRevocationReadTimeout = 30 * time.Second

func isGitRegistryLocator(spec string) bool {
	if spec == "" {
		return false
	}
	scheme := artifact.SchemeOf(spec)
	return scheme != "er1" && scheme != "https"
}

// pinnedRootsForLocator finds the pin for a registry the same way pull does: a
// pinned peer wins, then the handwritten trust-roots file when it names the locator.
func pinnedRootsForLocator(locator string) (*registry.SelfTrustRoots, bool) {
	if peers, err := registry.LoadPeers(peersConfigPath); err == nil {
		if pe, ok := peers.FindPeerByLocator(locator); ok {
			if tr, aerr := pe.AsTrustRoots(); aerr == nil {
				return tr, true
			}
		}
	}
	if tr, err := registry.LoadSelfTrustRoots(""); err == nil && tr != nil && tr.Registry == locator {
		return tr, true
	}
	return nil, false
}

// peerRootsForInstalled returns the peer pin for an installed skill, or nil when
// the handwritten trust-roots file is the carrier.
func peerRootsForInstalled(home, name string) *registry.SelfTrustRoots {
	side, ok := loadInstalledSidecar(home, name)
	if !ok || side.Registry == "" {
		return nil
	}
	peers, err := registry.LoadPeers(peersConfigPath)
	if err != nil {
		return nil
	}
	pe, ok := peers.FindPeerByLocator(side.Registry)
	if !ok {
		return nil
	}
	tr, err := pe.AsTrustRoots()
	if err != nil {
		return nil
	}
	return tr
}

func installedDigestRevoked(home, name string) bool {
	dig := installedSkillDigest(home, name)
	if dig == "" {
		return false
	}
	_, revoked := loadGossipedRevoked(home)[dig]
	return revoked
}

func recordVerifiedRevocations(home string, digests []string, now time.Time) error {
	set := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		set[d] = struct{}{}
	}
	_, err := mergeGossipedRevoked(home, set, now)
	return err
}

// refreshGitRegistryRevocations reads the signed revoke events of every git registry
// an installed skill came from. It returns the locators read successfully and one
// message per locator that could not be read. An unreachable registry says nothing
// about revocation, so the caller reports it instead of treating the skill as clean.
func refreshGitRegistryRevocations(home, skillsDir string, now time.Time) (map[string]bool, []string) {
	locators := map[string]bool{}
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil, nil
	}
	for _, e := range entries {
		if side, ok := loadInstalledSidecar(home, e.Name()); ok && isGitRegistryLocator(side.Registry) {
			locators[side.Registry] = true
		}
	}
	refreshed := map[string]bool{}
	var failures []string
	union := map[string]struct{}{}
	for locator := range locators {
		if err := readGitRegistryRevokes(locator, union); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", locator, err))
			continue
		}
		refreshed[locator] = true
	}
	sort.Strings(failures)
	if _, err := mergeGossipedRevoked(home, union, now); err != nil {
		return nil, append(failures, "revoked set not written: "+err.Error())
	}
	return refreshed, failures
}

func readGitRegistryRevokes(locator string, into map[string]struct{}) error {
	tr, ok := pinnedRootsForLocator(locator)
	if !ok {
		return fmt.Errorf("no pinned key for this registry")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitRevocationReadTimeout)
	defer cancel()
	be, err := artifact.Open(locator, artifact.OpenOptions{Creds: artifactauth.New()})
	if err != nil {
		return err
	}
	defer be.Close() //nolint:errcheck // read-only backend
	gl, ok := be.(artifact.GovernanceLog)
	if !ok {
		return fmt.Errorf("registry exposes no signed event log")
	}
	page, err := gl.Events(ctx, artifact.ListFilter{}, artifact.Page{})
	if err != nil {
		return err
	}
	unionVerifiedRevokes(page.Events, tr.PubKey(), into)
	return nil
}
