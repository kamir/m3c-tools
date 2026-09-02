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
	"regexp"
	"strings"
)

// --- input validation (SEC-M9): skill name/version/digest become filesystem
// paths (filepath.Join) AND git operands. Reject anything that could escape the
// repo root ('..', '/', absolute) or be parsed as a git flag (leading '-'), and
// pin the digest to its canonical shape. This mirrors the sanitization the rest
// of the codebase enforces; the challenge gate flagged its absence here. ---

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// NOTE (WIN-T9, NTFS case-insensitivity): the name/version validated here become
// filesystem path components under skills/<name>/<version>/ in a CLONE. NTFS (and
// APFS by default) are case-INSENSITIVE but case-PRESERVING, so two names that
// differ only in case — "Foo" vs "foo" — are distinct tags/annotations but collide
// onto the SAME directory when the repo is checked out on Windows/macOS. Whatever
// was written last wins; the other silently reads back the wrong bytes. The regexp
// below intentionally does NOT fold case (git storage is case-sensitive and the
// authoritative identity is the recomputed .skb digest, which a collision does not
// forge). If a future storage layer relies on the on-disk name being unique, it
// must dedup names case-INSENSITIVELY, not rely on this validator.
func validateName(s string) error {
	if s == "" || s == "." || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || !nameRe.MatchString(s) {
		return fmt.Errorf("git: invalid skill name %q (allowed [A-Za-z0-9._-], no '..', no leading '-')", s)
	}
	return nil
}

func validateVersion(s string) error {
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || !versionRe.MatchString(s) {
		return fmt.Errorf("git: invalid version %q", s)
	}
	return nil
}

func validateDigest(s string) error {
	if !digestRe.MatchString(s) {
		return fmt.Errorf("git: invalid digest %q (want sha256:<64 lowercase hex>)", s)
	}
	return nil
}

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

