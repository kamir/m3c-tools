package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/netguard"
)

// Bounds against a hostile/oversized registry (the carrier is untrusted). Manifests
// and event JSON are tiny; the .skb is capped generously (SPEC-0252 extraction is
// 100 MiB). Enumeration is capped so a registry cannot OOM/hang the pulling host.
const (
	maxManifestBytes = 4 << 20   // 4 MiB, skill/event/referrer manifests + event JSON
	maxBlobBytes     = 128 << 20 // 128 MiB, the .skb layer
	maxTags          = 100_000   // tags scanned per List/Resolve/Fetch/Events
	maxReferrers     = 10_000    // event referrers scanned per skill manifest
)

// openOCI maps oci://<registry>/<repo> to a remote.Repository. All skill versions
// live in that ONE repo as <name>_<version> tags (events are their referrers).
// M3C_OCI_HTTP=1 flips to plain HTTP for a LAN/test registry (registry:2 / Zot).
// Credentials come from opts.Creds (SPEC-0356 D5); cosign is out-of-band.
func openOCI(spec string, opts artifact.OpenOptions) (artifact.Backend, error) {
	ref := strings.TrimPrefix(spec, "oci://")
	if ref == "" {
		return nil, fmt.Errorf("oci: empty spec %q", spec)
	}
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("oci: %w", err)
	}
	if os.Getenv("M3C_OCI_HTTP") == "1" {
		repo.PlainHTTP = true
	}
	b := newOCIBackend(repo, spec)
	// CD-13: bake the READ-only credential into the shared oras client by default.
	// The oras auth.Client is constructed once, and its per-request Credential
	// callback carries no read/write mode, so we cannot distinguish op mode inside
	// oras. Instead the common path (Fetch/List/Resolve/Events, a verifying pull)
	// uses the read tier here, and Publish, the ONLY write op: swaps to the write
	// tier via applyOCIAuth(ModeWrite) at its start. For a single-token operator
	// ModeRead falls back to the write token in the resolver, so behavior is
	// unchanged; only an operator who provisioned a distinct read-only token gets
	// least privilege on pulls.
	b.creds = opts.Creds
	b.credHost = repo.Reference.Registry
	if err := applyOCIAuth(repo, opts.Creds, b.credHost, artifact.ModeRead); err != nil {
		return nil, err
	}
	return b, nil
}

// applyOCIAuth resolves the (host, mode) credential via creds and installs it on
// repo.Client, or leaves the repo anonymous when there is no resolver/token. It
// enforces the CD-03/WIN-12 egress guard: a bearer/basic credential must never
// ride cleartext HTTP to a host that is not provably loopback/private. An on-path
// attacker would capture a write-scoped registry token (same class as
// ER1_VERIFY_SSL=false). Called at Open with ModeRead and by Publish with ModeWrite.
func applyOCIAuth(repo *remote.Repository, creds artifact.CredentialSource, host string, mode artifact.AccessMode) error {
	if creds == nil {
		return nil
	}
	c, cerr := creds.Credential(context.Background(), "oci", host, mode)
	if cerr != nil || (c.Token == "" && c.User == "") {
		return nil // anonymous for this mode
	}
	if repo.PlainHTTP && !isLoopbackOrPrivate(host) {
		return fmt.Errorf("oci: refusing to send credential over plain HTTP to non-loopback host %q; use https or unset M3C_OCI_HTTP", host)
	}
	repo.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: auth.StaticCredential(host, auth.Credential{Username: c.User, Password: c.Token}),
	}
	return nil
}

// --- input validation (SEC-M9): name/version/digest become tags + annotations. ---

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func validateName(s string) error {
	if s == "" || s == "." || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || !nameRe.MatchString(s) {
		return fmt.Errorf("oci: invalid skill name %q", s)
	}
	return nil
}
func validateVersion(s string) error {
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || !versionRe.MatchString(s) {
		return fmt.Errorf("oci: invalid version %q", s)
	}
	return nil
}
func validateDigest(s string) error {
	if !digestRe.MatchString(s) {
		return fmt.Errorf("oci: invalid digest %q (want sha256:<64 lowercase hex>)", s)
	}
	return nil
}

// --- misc string helpers ---

func strOr(s, fb string) string {
	if s == "" {
		return fb
	}
	return s
}
func strFromMap(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}
func parseRFC3339(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

// kindFromSignedEnvelope / the signed-envelope classifier now lives in the shared
// pkg/skillctl/trustcore (FR-0090 IS-T0) so the OCI, git, and ER1 backends plus the
// gossip + gauntlet paths derive event identity from ONE audited definition. Events()
// calls trustcore.KindFromSignedEnvelope + trustcore.SignedDigest directly.

// isLoopbackOrPrivate reports whether host (possibly host:port) resolves to a
// loopback or RFC1918/ULA address: the only place a bearer token may ride plain
// HTTP. A bare hostname (not an IP literal) is treated as NON-local (fail-closed).
//
// This is now a thin alias over netguard.IsLoopbackOrPrivate so the OCI, git, and
// ER1 egress guards share ONE audited definition (FR-0090-style) and cannot drift.
func isLoopbackOrPrivate(host string) bool { return netguard.IsLoopbackOrPrivate(host) }

// tagHash is an injective disambiguator so that no two distinct (name,version)
// pairs can collide onto one tag (sanitizeTag is lossy and '_' is legal in both
// fields). List/Resolve read the authoritative name/version from annotations, so
// the tag only needs to be unique + deterministic.
func tagHash(name, version string) string {
	sum := sha256.Sum256([]byte(name + "\x00" + version))
	return hex.EncodeToString(sum[:])[:12]
}


func versionStrings(rows []artifact.VersionRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Version)
	}
	return out
}

func rowFor(rows []artifact.VersionRow, version string) (artifact.VersionRow, bool) {
	for _, r := range rows {
		if r.Version == version {
			return r, true
		}
	}
	return artifact.VersionRow{}, false
}
