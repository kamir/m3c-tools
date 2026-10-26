package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

// ErrNativeEvidenceSourceIO is a transport failure, not an invalid trust proof
// or a statement that journal persistence has started.
var ErrNativeEvidenceSourceIO = errors.New("native revocation evidence source unavailable")

const nativeEvidenceResponseMax = 1 << 20
const nativeEvidenceCAMax = 64 << 10

type nativeEvidenceSourceError struct{ cause error }

func (e *nativeEvidenceSourceError) Error() string { return ErrNativeEvidenceSourceIO.Error() }
func (e *nativeEvidenceSourceError) Unwrap() []error {
	return []error{ErrNativeEvidenceSourceIO, e.cause}
}

// NativeEvidenceSource retains an explicit public HTTPS endpoint and its TLS
// trust snapshot. Fetch returns untrusted bytes, never installation permission.
type NativeEvidenceSource struct {
	endpoint    string
	system      bool
	caPEM       []byte
	roots       *x509.CertPool
	closeBody   func(io.ReadCloser) error // private per-instance fault seams
	dialContext func(context.Context, string, string) (net.Conn, error)
}

// NewNativeSystemEvidenceSource uses ordinary system TLS trust without opening
// a connection or selecting any credentials.
func NewNativeSystemEvidenceSource(endpoint string) (*NativeEvidenceSource, error) {
	u, err := nativeEvidenceEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return &NativeEvidenceSource{endpoint: u, system: true}, nil
}

// NewNativePinnedEvidenceSource retains only the explicitly supplied CA roots.
// It does not append ambient roots or modify the system trust store.
func NewNativePinnedEvidenceSource(endpoint string, caPEM []byte) (*NativeEvidenceSource, error) {
	u, err := nativeEvidenceEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if len(caPEM) == 0 || len(caPEM) > nativeEvidenceCAMax {
		return nil, ErrNativeEvidenceInvalid
	}
	pool := x509.NewCertPool()
	seen := make(map[[32]byte]bool)
	remaining := caPEM
	for len(bytes.TrimSpace(remaining)) != 0 {
		remaining = bytes.TrimSpace(remaining)
		const begin = "-----BEGIN CERTIFICATE-----"
		const end = "-----END CERTIFICATE-----"
		if len(seen) >= 32 || !bytes.HasPrefix(remaining, []byte(begin)) {
			return nil, ErrNativeEvidenceInvalid
		}
		i := bytes.Index(remaining, []byte(end))
		if i < 0 {
			return nil, ErrNativeEvidenceInvalid
		}
		segment := remaining[:i+len(end)]
		if bytes.Count(segment, []byte("-----BEGIN")) != 1 {
			return nil, ErrNativeEvidenceInvalid
		}
		block, rest := pem.Decode(segment)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrNativeEvidenceInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrNativeEvidenceInvalid
		}
		digest := sha256.Sum256(cert.Raw)
		if seen[digest] {
			return nil, ErrNativeEvidenceInvalid
		}
		seen[digest] = true
		pool.AddCert(cert)
		remaining = remaining[len(segment):]
	}
	if len(seen) == 0 {
		return nil, ErrNativeEvidenceInvalid
	}
	return &NativeEvidenceSource{endpoint: u, roots: pool, caPEM: append([]byte(nil), caPEM...)}, nil
}

func nativeEvidenceEndpoint(endpoint string) (string, error) {
	if len(endpoint) == 0 || len(endpoint) > 8192 || !utf8.ValidString(endpoint) {
		return "", ErrNativeEvidenceInvalid
	}
	base, err := httpsafe.ParseAPIBase(endpoint, false)
	if err != nil {
		return "", ErrNativeEvidenceInvalid
	}
	u, err := url.Parse(base.URL)
	if err != nil || u.Path == "" {
		return "", ErrNativeEvidenceInvalid
	}
	if _, err = httpsafe.NewGETBoundary(base.URL, false, 1); err != nil {
		return "", ErrNativeEvidenceInvalid
	}
	return base.URL, nil
}

// Fetch uses one fresh HTTP/1.1 transport and one application request, without
// redirects, proxies, cookies, compression or credentials. The complete native
// envelope must still pass the selected journal's locked Adopt authentication.
func (s *NativeEvidenceSource) Fetch(ctx context.Context) (raw []byte, resultErr error) {
	if s == nil || s.endpoint == "" || (!s.system && s.roots == nil) {
		return nil, ErrNativeEvidenceInvalid
	}
	defer func() {
		if resultErr != nil {
			raw = nil
			resultErr = &nativeEvidenceSourceError{cause: resultErr}
		}
	}()
	if ctx == nil {
		return nil, errors.New("native evidence source requires a context")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if s.roots != nil {
		tlsConfig.RootCAs = s.roots.Clone()
	}
	dialContext := s.dialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	transport := &http.Transport{
		DialContext:     dialContext,
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, Protocols: protocols,
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	// RoundTrip leaves every status body with us, including malformed redirect
	// locations; Client.Do may otherwise close those bodies internally.
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeBody := s.closeBody
		if closeBody == nil {
			closeBody = func(body io.ReadCloser) error { return body.Close() }
		}
		resultErr = errors.Join(resultErr, closeBody(resp.Body), ctx.Err())
	}()
	if len(resp.Header.Values("Content-Type")) != 1 || len(resp.Header.Values("Content-Encoding")) > 1 {
		return nil, ErrNativeEvidenceSourceIO
	}
	media, parameters, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || err != nil || media != "application/json" || len(parameters) > 1 || (len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8")) {
		return nil, ErrNativeEvidenceSourceIO
	}
	encoding := resp.Header.Get("Content-Encoding")
	if (encoding != "" && !strings.EqualFold(encoding, "identity")) || resp.ContentLength > nativeEvidenceResponseMax {
		return nil, ErrNativeEvidenceSourceIO
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, nativeEvidenceResponseMax+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > nativeEvidenceResponseMax {
		return nil, ErrNativeEvidenceSourceIO
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}
