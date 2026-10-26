package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func nativeSourceTestCA(t *testing.T, serial int64) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Synthetic evidence CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed, key
}

func nativeSourceTestServer(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, handler http.Handler, connections *atomic.Int32) *httptest.Server {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(900), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"evidence.synthetic.invalid"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	if connections != nil {
		s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		}
	}
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: leafKey}}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func nativeSourceProxyContract(t *testing.T) {
	t.Helper()
	var proxyCalls, sourceCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	// This helper runs in a fresh process, before ProxyFromEnvironment can cache
	// any values. A non-loopback DNS name prevents its localhost exemption.
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	for _, name := range []string{"ER1_API_KEY", "ER1_DEVICE_TOKEN", "M3C_REGISTRY_TOKEN", "M3C_REGISTRY_RO_TOKEN", "M3C_GITLAB_TOKEN", "M3C_GITLAB_RO_TOKEN", "M3C_GITHUB_TOKEN", "M3C_GITHUB_RO_TOKEN"} {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name, hex.EncodeToString(value))
	}
	caRaw, ca, key := nativeSourceTestCA(t, 91)
	_, signer, _ := nativeFixtureRoots(t)
	proof := nativeEvidenceBytes(t, signer, time.Now().UTC().Add(-time.Minute), 1, []string{}, nil)
	server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceCalls.Add(1)
		if !strings.HasPrefix(r.Host, "evidence.synthetic.invalid:") || r.Method != http.MethodGet || r.URL.RequestURI() != "/selected/full.json" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("source used unexpected endpoint or ambient credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(proof)
	}), nil)
	actual, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	selected := net.JoinHostPort("evidence.synthetic.invalid", actual.Port())
	reader, err := NewNativePinnedEvidenceSource("https://"+selected+"/selected/full.json", caRaw)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: time.Second}
	reader.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == selected {
			address = actual.Host
		}
		return dialer.DialContext(ctx, network, address)
	}
	raw, err := reader.Fetch(context.Background())
	if err != nil || !bytes.Equal(raw, proof) || sourceCalls.Load() != 1 || proxyCalls.Load() != 0 {
		t.Fatalf("public source used ambient proxy/credentials or lost TLS proof: err=%v source=%d proxy=%d", err, sourceCalls.Load(), proxyCalls.Load())
	}
}

func TestNativeEvidenceHTTPSReaderContract(t *testing.T) {
	if os.Getenv("M3C_NATIVE_EVIDENCE_PROXY_CHILD") == "1" {
		nativeSourceProxyContract(t)
		return
	}
	t.Run("no-ambient-proxy-or-credentials", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, exe, "-test.run=^TestNativeEvidenceHTTPSReaderContract$")
		child.WaitDelay = time.Second
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "M3C_NATIVE_EVIDENCE_PROXY_CHILD=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "M3C_NATIVE_EVIDENCE_PROXY_CHILD=1")
		output, err := child.CombinedOutput()
		if err != nil || ctx.Err() != nil {
			t.Fatalf("fresh-process proxy contract failed: %v %s", err, output)
		}
	})
	caRaw, ca, key := nativeSourceTestCA(t, 1)
	roots, signingKey, _ := nativeFixtureRoots(t)
	proof := nativeEvidenceBytes(t, signingKey, time.Now().UTC().Add(-time.Minute), 1, []string{}, nil)
	for _, chunked := range []bool{false, true} {
		t.Run("exact-body-chunked-"+strconv.FormatBool(chunked), func(t *testing.T) {
			var calls, connections atomic.Int32
			body := append(append([]byte(nil), proof...), bytes.Repeat([]byte(" "), nativeEvidenceResponseMax-len(proof))...)
			server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.URL.RequestURI() != "/full.json" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("unexpected protocol, endpoint or ambient credentials")
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write(body)
			}), &connections)
			reader, err := NewNativePinnedEvidenceSource(server.URL+"/full.json", caRaw)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				actual, err := reader.Fetch(context.Background())
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatalf("exact bounded body lost: %v", err)
				}
				authority, err := NewNativeRevocationAuthority("self", nil, roots)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = InspectNativeRevocationEvidence(actual, authority); err != nil {
					t.Fatalf("fixture must be genuinely signed: %v", err)
				}
			}
			if calls.Load() != 2 || connections.Load() != 2 {
				t.Fatal("Fetch reused a connection or transmitted extra requests", calls.Load(), connections.Load())
			}
		})
	}
	t.Run("no-retry-after-first-request", func(t *testing.T) {
		var calls, connections atomic.Int32
		server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if err = conn.Close(); err != nil {
				t.Error(err)
			}
		}), &connections)
		reader, err := NewNativePinnedEvidenceSource(server.URL+"/full.json", caRaw)
		if err != nil {
			t.Fatal(err)
		}
		if raw, err := reader.Fetch(context.Background()); raw != nil || !errors.Is(err, ErrNativeEvidenceSourceIO) {
			t.Fatal("dropped response supplied proof", err)
		}
		if calls.Load() != 1 || connections.Load() != 1 {
			t.Fatal("wire request retried", calls.Load(), connections.Load())
		}
	})
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run("redirect-"+strconv.Itoa(status), func(t *testing.T) {
			var targetCalls atomic.Int32
			target := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { targetCalls.Add(1) }), nil)
			server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.URL+"/full.json")
				w.WriteHeader(status)
			}), nil)
			reader, err := NewNativePinnedEvidenceSource(server.URL+"/full.json", caRaw)
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			reader.closeBody = func(body io.ReadCloser) error { closed = true; return body.Close() }
			raw, err := reader.Fetch(context.Background())
			if raw != nil || !errors.Is(err, ErrNativeEvidenceSourceIO) || !closed || targetCalls.Load() != 0 {
				t.Fatal("redirect escaped or body close unchecked", err)
			}
		})
	}
	for _, failure := range []string{"cap", "length", "status", "media", "encoding", "truncated", "headers", "malformed-location", "duplicate-media-same", "duplicate-media-different", "duplicate-encoding-same", "duplicate-encoding-different"} {
		t.Run("response-"+failure, func(t *testing.T) {
			server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch failure {
				case "length":
					w.Header().Set("Content-Length", strconv.Itoa(nativeEvidenceResponseMax+1))
				case "status":
					w.WriteHeader(503)
				case "media":
					w.Header().Set("Content-Type", "text/plain")
				case "duplicate-media-same":
					w.Header().Add("Content-Type", "application/json")
				case "duplicate-media-different":
					w.Header().Add("Content-Type", "text/plain")
				case "duplicate-encoding-same":
					w.Header()["Content-Encoding"] = []string{"identity", "identity"}
				case "duplicate-encoding-different":
					w.Header()["Content-Encoding"] = []string{"identity", "gzip"}
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "truncated":
					w.Header().Set("Content-Length", strconv.Itoa(len(proof)+1))
				case "headers":
					w.Header().Set("X-Oversize", strings.Repeat("h", 17<<10))
				case "malformed-location":
					w.Header().Set("Location", "://%")
					w.WriteHeader(302)
				case "cap":
					w.(http.Flusher).Flush()
					_, _ = w.Write(bytes.Repeat([]byte(" "), nativeEvidenceResponseMax+1))
					return
				}
				_, _ = w.Write(proof)
			}), nil)
			reader, err := NewNativePinnedEvidenceSource(server.URL+"/full.json", caRaw)
			if err != nil {
				t.Fatal(err)
			}
			if raw, err := reader.Fetch(context.Background()); raw != nil || !errors.Is(err, ErrNativeEvidenceSourceIO) || err.Error() != ErrNativeEvidenceSourceIO.Error() {
				t.Fatal("unsafe response supplied bytes or raw diagnostic", err)
			}
		})
	}
	t.Run("checked-close-and-late-cancel", func(t *testing.T) {
		server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(proof)
		}), nil)
		reader, err := NewNativePinnedEvidenceSource(server.URL+"/full.json", caRaw)
		if err != nil {
			t.Fatal(err)
		}
		fault := errors.New("synthetic private Close detail")
		reader.closeBody = func(body io.ReadCloser) error { return errors.Join(body.Close(), fault) }
		if raw, err := reader.Fetch(context.Background()); raw != nil || !errors.Is(err, fault) || err.Error() != ErrNativeEvidenceSourceIO.Error() {
			t.Fatal("Close error hidden or leaked", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		reader.closeBody = func(body io.ReadCloser) error { err := body.Close(); cancel(); return err }
		if raw, err := reader.Fetch(ctx); raw != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("late cancellation supplied proof", err)
		}
	})
	t.Run("tls-and-pre-cancel", func(t *testing.T) {
		var calls atomic.Int32
		server := nativeSourceTestServer(t, ca, key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) }), nil)
		other, _, _ := nativeSourceTestCA(t, 2)
		reader, err := NewNativePinnedEvidenceSource(server.URL+"/full.json", other)
		if err != nil {
			t.Fatal(err)
		}
		if raw, err := reader.Fetch(context.Background()); raw != nil || !errors.Is(err, ErrNativeEvidenceSourceIO) {
			t.Fatal("foreign TLS CA accepted", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = reader.Fetch(ctx); !errors.Is(err, context.Canceled) || calls.Load() != 0 {
			t.Fatal("canceled call made a request", err)
		}
	})
	t.Run("constructor-and-ca-bounds", func(t *testing.T) {
		for _, endpoint := range []string{"", "http://127.0.0.1/full", "https://source.invalid", "https://u@source.invalid/full", "https://source.invalid/a/../full", "https://source.invalid/%2f", "https://source.invalid/full?x=y"} {
			if _, err := NewNativeSystemEvidenceSource(endpoint); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("invalid endpoint accepted", endpoint, err)
			}
		}
		for _, raw := range [][]byte{nil, []byte("garbage"), append(append([]byte(nil), caRaw...), caRaw...), append(append([]byte(nil), caRaw...), 'x'), bytes.Repeat([]byte(" "), nativeEvidenceCAMax+1)} {
			if _, err := NewNativePinnedEvidenceSource("https://source.invalid/full", raw); !errors.Is(err, ErrNativeEvidenceInvalid) {
				t.Fatal("invalid CA inventory accepted", err)
			}
		}
		exactPEM := append(append([]byte(nil), caRaw...), bytes.Repeat([]byte(" "), nativeEvidenceCAMax-len(caRaw))...)
		if _, err := NewNativePinnedEvidenceSource("https://source.invalid/full", exactPEM); err != nil {
			t.Fatal("exact PEM byte cap refused", err)
		}
		var many []byte
		for i := int64(1); i <= 33; i++ {
			cert, _, _ := nativeSourceTestCA(t, i)
			many = append(many, cert...)
			if i == 32 {
				if _, err := NewNativePinnedEvidenceSource("https://source.invalid/full", many); err != nil {
					t.Fatal("32 CA boundary refused", err)
				}
			}
		}
		if _, err := NewNativePinnedEvidenceSource("https://source.invalid/full", many); !errors.Is(err, ErrNativeEvidenceInvalid) {
			t.Fatal("33 CAs accepted", err)
		}
	})
}
