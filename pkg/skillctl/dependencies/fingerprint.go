package dependencies

import (
	"context"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const treeFingerprintAlgorithm = "m3c.python-site-tree/v1"

// TreeObservationLimits describes the enforced bounds of a tree observation.
type TreeObservationLimits struct {
	Entries    int   `json:"entries"`
	PathBytes  int   `json:"path_bytes"`
	PathLength int   `json:"path_length"`
	Depth      int   `json:"depth"`
	Bytes      int64 `json:"bytes"`
}

// TreeObservation reports observed bytes, not operator approval or authenticity.
// Path identifies the canonical selected directory. Interior links and special
// file types are rejected by the shared tree reader; selected root aliases are
// resolved. Transparent Windows DEDUP files classified as regular bind their bytes.
type TreeObservation struct {
	Algorithm string                `json:"algorithm"`
	Path      string                `json:"path"`
	Digest    string                `json:"digest"`
	Complete  bool                  `json:"complete"`
	Approved  bool                  `json:"approved"`
	Limits    TreeObservationLimits `json:"limits"`
}

// FingerprintTree observes an explicitly selected absolute directory without
// writing profiles, approving a baseline or selecting an interpreter.
func FingerprintTree(ctx context.Context, path string) (*TreeObservation, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limits := defaultTreeLimits()
	if len(path) > limits.PathLength || !utf8.ValidString(path) || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrInvalid
	}
	actual, digest, err := siteFingerprint(ctx, path)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &TreeObservation{Algorithm: treeFingerprintAlgorithm, Path: actual, Digest: digest, Complete: true, Approved: false, Limits: limits}, nil
}
