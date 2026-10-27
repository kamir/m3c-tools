package registry

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// ErrNativeGitSourceIO identifies acquisition failures without exposing URLs,
// response bodies or credential values in diagnostics.
var ErrNativeGitSourceIO = errors.New("native Git source unavailable")

type nativeGitSourceError struct{ cause error }

func (e *nativeGitSourceError) Error() string   { return ErrNativeGitSourceIO.Error() }
func (e *nativeGitSourceError) Unwrap() []error { return []error{ErrNativeGitSourceIO, e.cause} }
func nativeGitIO(err error) error               { return &nativeGitSourceError{cause: err} }

// NativeGitSourceOptions selects public carrier metadata, never authority.
type NativeGitSourceOptions struct {
	Provider, APIBase, Repository, CommitOID, RootTreeOID, ObjectFormat string
	AuthMode, AuthFamily, AuthOrigin, TLSMode                           string
	CAPEM                                                               []byte
}

// NativeGitSource owns immutable metadata. The private fault observations are
// package-test seams, never public transport or authorization capabilities.
type NativeGitSource struct {
	provider, base, repository, commit, tree, authMode, family, configID string
	roots                                                                *x509.CertPool
	readEnv                                                              func(string) (string, bool)
	dialContext                                                          func(context.Context, string, string) (net.Conn, error)
	closeBody                                                            func(io.ReadCloser) error
}

type nativeGitCandidate struct {
	Archive   []byte
	Bundle    *StagedBundle
	workBytes int64
	bindingID string
}

var nativeGitSegment = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func nativeGitOID(text string) bool {
	if len(text) != 40 {
		return false
	}
	for _, c := range []byte(text) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NewNativeGitSource performs bounded metadata and TLS validation only. It does
// not read credentials, open native stores, acquire a journal or make requests.
func NewNativeGitSource(o NativeGitSourceOptions) (*NativeGitSource, error) {
	for _, v := range []string{o.Provider, o.ObjectFormat, o.AuthMode, o.AuthFamily, o.TLSMode} {
		if !utf8.ValidString(v) || len(v) > 64 {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	for _, v := range []string{o.APIBase, o.AuthOrigin} {
		if !agentText(v, 8192) && v != "" {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	if len(o.Repository) > 1024 || len(o.CAPEM) > nativeEvidenceCAMax || !nativeGitOID(o.CommitOID) || !nativeGitOID(o.RootTreeOID) || o.ObjectFormat != "sha1" {
		return nil, ErrNativeEvidenceInvalid
	}
	parts := strings.Split(o.Repository, "/")
	if (o.Provider != "github" && o.Provider != "gitlab") || len(parts) < 2 || len(parts) > 8 || (o.Provider == "github" && len(parts) != 2) {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 255 || p == "." || p == ".." || strings.HasPrefix(p, "-") || strings.HasSuffix(strings.ToLower(p), ".git") || !nativeGitSegment.MatchString(p) {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	base, err := httpsafe.ParseAPIBase(o.APIBase, false)
	if err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	if _, err = httpsafe.NewGETBoundary(base.URL, false, 1); err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	switch o.AuthMode {
	case "none":
		if o.AuthFamily != "" || o.AuthOrigin != "" {
			return nil, ErrNativeEvidenceInvalid
		}
	case "external-env":
		origin, e := httpsafe.ParseAPIBase(o.AuthOrigin, false)
		if e != nil || o.AuthOrigin != origin.Origin.String() || origin.Origin != base.Origin || o.AuthFamily != o.Provider+"-read-token" {
			return nil, ErrNativeEvidenceInvalid
		}
	default:
		return nil, ErrNativeEvidenceInvalid
	}
	var roots *x509.CertPool
	switch o.TLSMode {
	case "system":
		if len(o.CAPEM) != 0 {
			return nil, ErrNativeEvidenceInvalid
		}
	case "pinned-pem":
		selected, e := NewNativePinnedEvidenceSource(strings.TrimRight(base.URL, "/")+"/", o.CAPEM)
		if e != nil {
			return nil, ErrNativeEvidenceInvalid
		}
		roots = selected.roots
	default:
		return nil, ErrNativeEvidenceInvalid
	}
	ca := sha256.Sum256(o.CAPEM)
	public := struct{ Domain, Provider, Base, Repository, Commit, Tree, Format, AuthMode, Family, Origin, TLSMode, CA string }{"m3c.native-git-config/v1", o.Provider, strings.TrimRight(base.URL, "/"), o.Repository, o.CommitOID, o.RootTreeOID, o.ObjectFormat, o.AuthMode, o.AuthFamily, o.AuthOrigin, o.TLSMode, hex.EncodeToString(ca[:])}
	raw, err := json.Marshal(public)
	if err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	id := sha256.Sum256(raw)
	return &NativeGitSource{provider: o.Provider, base: public.Base, repository: o.Repository, commit: o.CommitOID, tree: o.RootTreeOID, authMode: o.AuthMode, family: o.AuthFamily, roots: roots, configID: hex.EncodeToString(id[:])}, nil
}

// fetchCandidate is called once under the actual kind-specific session mutex.
// Its caller consumes acquisition before entry and terminally closes on error.
func (s *NativeGitSource) fetchCandidate(ctx context.Context, journal *NativeJournal, lease *nativeJournalLease, digest, kind string) (candidate *nativeGitCandidate, resultErr error) {
	if s == nil || s.configID == "" || ctx == nil || journal == nil || lease == nil || lease.journal != journal {
		return nil, ErrNativeSessionUnavailable
	}
	if !nativeSubject(digest) || (kind != skillbundle.KindAgent && kind != skillbundle.KindSkill) {
		return nil, ErrNativeEvidenceInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := lease.recheck(ctx, digest); err != nil {
		return nil, nativeSessionDiagnostic(err)
	}
	secret := ""
	if s.authMode == "external-env" {
		read := s.readEnv
		if read == nil {
			read = os.LookupEnv
		}
		name := "M3C_GITHUB_RO_TOKEN"
		if s.provider == "gitlab" {
			name = "M3C_GITLAB_RO_TOKEN"
		}
		var ok bool
		secret, ok = read(name)
		if !ok || len(secret) == 0 || len(secret) > 8192 || !utf8.ValidString(secret) || strings.TrimSpace(secret) != secret || strings.ContainsFunc(secret, unicode.IsControl) {
			return nil, nativeGitIO(ErrNativeGitSourceIO)
		}
	}
	f := newNativeGitFetch(ctx, s, journal, secret)
	defer f.transport.CloseIdleConnections()
	if err := f.checkCommit(); err != nil {
		return nil, err
	}
	if _, err := f.treeAt("", s.tree); err != nil {
		return nil, err
	}
	if err := f.checkMetadata(); err != nil {
		return nil, err
	}
	if err := f.readEvents(); err != nil {
		return nil, err
	}
	bundle, err := f.selectBundle(digest, kind)
	if err != nil {
		return nil, err
	}
	archive, err := f.bundleBlob(bundle.Name, bundle.Version)
	if err != nil {
		return nil, err
	}
	if agentDigest(archive) != digest {
		return nil, ErrNativeEvidenceInvalid
	}
	if err = ctx.Err(); err != nil {
		return nil, nativeGitIO(err)
	}
	proof, err := f.proofDigest()
	if err != nil {
		return nil, err
	}
	binding, err := json.Marshal(struct {
		Domain, Config, Kind, Registry string
		Tenant                         *string
		Proof                          string
	}{"m3c.native-git-source/v1", s.configID, kind, journal.selection.authority.registry, journal.selection.authority.tenant, proof})
	if err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	sum := sha256.Sum256(binding)
	return &nativeGitCandidate{Archive: archive, Bundle: bundle, workBytes: f.work.bytes, bindingID: hex.EncodeToString(sum[:])}, nil
}
