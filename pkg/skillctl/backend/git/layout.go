// Package git implements a SPEC-0356 artifact.Backend over a git repository —
// the provider-neutral core shared by the GitHub and GitLab schemes. It carries
// the SAME .skb bytes and the SAME signed SPEC-0190 event JSON as every other
// backend, laid out per the SPEC-0356 §6 git wire-format:
//
//	skills/<name>/<version>/bundle.skb    (authoritative blob; sha256 == digest)
//	skills/<name>/<version>/bundle.json   (unpacked manifest, review handle)
//	events/<digesthex>/<seq>-<kind>.json  (append-only signed SPEC-0190 events)
//
// v1 uses the `git` CLI (os/exec) and is validated against a local bare repo;
// it works against any git remote, GitLab included. The distroless REST path
// and Git-LFS for large blobs are follow-ups (SPEC-0356 §6/D6).
package git

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// bundleJSON is the per-version review handle committed next to the blob. The
// digest here is advisory for humans/CI; the trust identity is always the
// recomputed sha256 of bundle.skb (verify.Verify never trusts this field).
type bundleJSON struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
	Governance string `json:"governance,omitempty"`
}

func digestHex(digest string) string { return strings.TrimPrefix(digest, "sha256:") }

func skillVersionDir(name, version string) string {
	return path.Join("skills", name, version)
}
func bundleSkbPath(name, version string) string {
	return path.Join(skillVersionDir(name, version), "bundle.skb")
}
func bundleJSONPath(name, version string) string {
	return path.Join(skillVersionDir(name, version), "bundle.json")
}
func eventDir(digest string) string { return path.Join("events", digestHex(digest)) }

// eventFileName renders "<seq>-<kind>.json", zero-padded so lexical order is
// chronological (0001-admitted.json, 0002-attested.json, …).
func eventFileName(seq int, kind string) string {
	return fmt.Sprintf("%04d-%s.json", seq, kind)
}

// tagName is the publish unit: "<name>/v<version>" (SPEC-0356 §6).
func tagName(name, version string) string { return name + "/v" + version }

func marshalEvent(event map[string]any) ([]byte, error) {
	// Sorted keys keep the committed file stable/diff-reviewable. The bytes are
	// the SPEC-0190 envelope verbatim; verification recomputes over them.
	return json.MarshalIndent(event, "", "  ")
}

func marshalBundleJSON(b bundleJSON) ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// --- minimal semver (semver-max, non-revoked). TODO(SPEC-0356): move to a
// shared pkg/skillctl/semver and retire the duplicated compareSemver copies. ---

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

// maxSemver returns the highest version in vs (empty string if none).
func maxSemver(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	cp := append([]string(nil), vs...)
	sort.Slice(cp, func(i, j int) bool { return semverLess(cp[i], cp[j]) })
	return cp[len(cp)-1]
}
