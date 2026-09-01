package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// Bounds against a hostile/oversized registry (the carrier is untrusted). Manifests
// and event JSON are tiny; the .skb is capped generously (SPEC-0252 extraction is
// 100 MiB). Enumeration is capped so a registry cannot OOM/hang the pulling host.
const (
	maxManifestBytes = 4 << 20   // 4 MiB — skill/event/referrer manifests + event JSON
	maxBlobBytes     = 128 << 20 // 128 MiB — the .skb layer
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
	if opts.Creds != nil {
		host := repo.Reference.Registry
		if c, cerr := opts.Creds.Credential(context.Background(), "oci", host); cerr == nil && (c.Token != "" || c.User != "") {
			// Never send a bearer/basic credential over cleartext to a host that is
			// not provably loopback/private — an on-path attacker would capture a
			// write-scoped registry token (same class as ER1_VERIFY_SSL=false).
			if repo.PlainHTTP && !isLoopbackOrPrivate(host) {
				return nil, fmt.Errorf("oci: refusing to send credential over plain HTTP to non-loopback host %q; use https or unset M3C_OCI_HTTP", host)
			}
			repo.Client = &auth.Client{
				Client:     retry.DefaultClient,
				Cache:      auth.NewCache(),
				Credential: auth.StaticCredential(host, auth.Credential{Username: c.User, Password: c.Token}),
			}
		}
	}
	return newOCIBackend(repo, spec), nil
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

// kindFromSignedEnvelope classifies a lifecycle event from fields that are inside
// the SIGNED SPEC-0190 envelope — never from the registry-controlled OCI annotation.
// A malicious registry can relabel/strip a referrer's annKind, but it cannot alter
// `revoked_by`/`reviewer_id`/… without breaking the ed25519 signature the gauntlet
// re-verifies. The builders are mutually exclusive (event.go), so field presence is
// an unambiguous discriminator. Returns "" for an unclassifiable envelope (dropped).
func kindFromSignedEnvelope(env map[string]any) artifact.EventKind {
	switch {
	case envHas(env, "revoked_by"):
		return artifact.KindRevoke
	case envHas(env, "reviewer_id"):
		return artifact.KindAttest
	case envHas(env, "installed_on_host"):
		return artifact.KindInstall
	case envHas(env, "admitted_by_identity"):
		return artifact.KindAdmit
	}
	return ""
}

func envHas(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k]
	if !ok || v == nil {
		return false
	}
	s, isStr := v.(string)
	return !isStr || s != ""
}

// isLoopbackOrPrivate reports whether host (possibly host:port) resolves to a
// loopback or RFC1918/ULA address — the only place a bearer token may ride plain
// HTTP. A bare hostname (not an IP literal) is treated as NON-local (fail-closed).
func isLoopbackOrPrivate(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a DNS name could resolve anywhere → not provably local
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// tagHash is an injective disambiguator so that no two distinct (name,version)
// pairs can collide onto one tag (sanitizeTag is lossy and '_' is legal in both
// fields). List/Resolve read the authoritative name/version from annotations, so
// the tag only needs to be unique + deterministic.
func tagHash(name, version string) string {
	sum := sha256.Sum256([]byte(name + "\x00" + version))
	return hex.EncodeToString(sum[:])[:12]
}

// --- semver (semver-max, non-revoked) — mirrors the git backend. ---

func semverLess(a, b string) bool { return compareSemver(a, b) < 0 }

func compareSemver(a, b string) int {
	if a == b {
		return 0
	}
	ap := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bp := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(ap) {
			ai, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			bi, _ = strconv.Atoi(bp[i])
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

func maxSemver(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	cp := append([]string(nil), vs...)
	sort.Slice(cp, func(i, j int) bool { return semverLess(cp[i], cp[j]) })
	return cp[len(cp)-1]
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
