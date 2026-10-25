package install

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const managedTransportToken = "synthetic-managed-transport-key"

func managedTransportFixture(t *testing.T, pinned bool) *registryIdentityFixture {
	t.Helper()
	f := newRegistryIdentityFixture(t)
	if pinned {
		f.home = snapshotTestHome(t)
		root := projectManagedRoot(t, f.root)
		root.RegistryURL = f.server.URL + "/api/skills"
		f.policy = installProjectProfile(t, f.home, root)
		enrollProject(t, f.home, f.policy.TrustRoot(), f.root)
		installedDependencyTree(t, f.home, f.leaf, "required", "1.0.0")
	}
	f.client.Token = managedTransportToken
	return f
}
func managedTransportRoute(r *http.Request) string {
	if strings.Contains(r.URL.Path, "/by-name/") {
		return "name"
	}
	if strings.Contains(r.URL.Path, "/bundles/") {
		if r.URL.Query().Get("meta") == "1" {
			return "meta"
		}
		return "blob"
	}
	return ""
}
func TestManagedRegistryTransportRedirectBoundary(t *testing.T) {
	for _, pinned := range []bool{true, false} {
		author := "registry"
		if pinned {
			author = "pinned"
		}
		for _, route := range []string{"name", "blob", "meta"} {
			for _, mode := range []string{"relative", "absolute", "other-port", "foreign-prefix", "lookalike", "intermediate", "encoded-slash", "encoded-dot", "double-encoded", "userinfo", "dot-relative", "relative-escape", "cycle"} {
				t.Run(author+"/"+route+"/"+mode, func(t *testing.T) {
					f := managedTransportFixture(t, pinned)
					old := installedDependencyOldTarget(t, f.home)
					base := f.server.Config.Handler
					var forbidden, redirected, allowed, wrongHeader atomic.Int32
					decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forbidden.Add(1); w.WriteHeader(500) }))
					defer decoy.Close()
					f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Header.Get("Authorization") != "Bearer "+managedTransportToken {
							wrongHeader.Add(1)
						}
						if !strings.HasPrefix(r.URL.Path, "/api/skills/") {
							forbidden.Add(1)
							w.WriteHeader(500)
							return
						}
						if strings.HasPrefix(r.URL.Path, "/api/skills/allowed/") || r.URL.Path == "/api/skills/by-name/retained-redirected" || r.URL.Path == "/api/skills/bundles/retained-redirected" {
							allowed.Add(1)
							clone := r.Clone(r.Context())
							switch route {
							case "name":
								clone.URL.Path = "/api/skills/by-name/fetch-contract"
								clone.URL.RawQuery = ""
							case "blob", "meta":
								clone.URL.Path = "/api/skills/bundles/" + f.root.digestStr
								clone.URL.RawQuery = ""
								if route == "meta" {
									clone.URL.RawQuery = "meta=1"
								}
							}
							base.ServeHTTP(w, clone)
							return
						}
						if managedTransportRoute(r) == "" && !strings.Contains(r.URL.Path, "/identities/") {
							forbidden.Add(1)
							w.WriteHeader(500)
							return
						}
						if managedTransportRoute(r) == route {
							redirected.Add(1)
							location := "/api/skills/allowed/" + route
							switch mode {
							case "relative":
								location = "retained-redirected"
							case "absolute":
								location = f.server.URL + location
							case "other-port":
								location = decoy.URL + location
							case "foreign-prefix", "intermediate":
								location = "/other/escape"
							case "lookalike":
								location = "/api/skills-foreign/escape"
							case "encoded-slash":
								location = "/api/skills/%2f..%2fother"
							case "encoded-dot":
								location = "/api/skills/%2e%2e/other"
							case "double-encoded":
								location = "/api/skills/%252e%252e/other"
							case "userinfo":
								location = strings.Replace(f.server.URL, "://", "://user:synthetic@", 1) + location
							case "dot-relative":
								location = "../allowed/" + route
							case "relative-escape":
								location = "../../outside"
							case "cycle":
								location = r.URL.RequestURI()
							}
							w.Header().Set("Location", location)
							w.WriteHeader(302)
							return
						}
						base.ServeHTTP(w, r)
					})
					result, err := f.install(nil)
					positive := mode == "relative" || mode == "absolute" || mode == "dot-relative"
					if positive {
						if err != nil || result == nil || allowed.Load() != 1 {
							t.Fatalf("allowed signed redirect: %v hops=%d", err, allowed.Load())
						}
						retainedRootStash(t, result.InstalledPath, f.root.blob)
					} else {
						if err == nil || result != nil {
							t.Fatal("forbidden redirect installed target")
						}
						assertInstalledDependencyOldTarget(t, old)
					}
					if redirected.Load() == 0 {
						t.Fatal("redirect route not exercised")
					}
					if forbidden.Load() != 0 {
						t.Fatalf("forbidden target received request: %d", forbidden.Load())
					}
					if wrongHeader.Load() != 0 {
						t.Fatal("selected registry credential changed")
					}
					if mode == "cycle" && redirected.Load() > 6 {
						t.Fatalf("unbounded redirect cycle: %d", redirected.Load())
					}
				})
			}
		}
	}
}
func TestManagedRegistryTransportSnapshotAndErrors(t *testing.T) {
	for _, pinned := range []bool{true, false} {
		author := "registry"
		if pinned {
			author = "pinned"
		}
		t.Run(author+"/cancelled", func(t *testing.T) {
			f := managedTransportFixture(t, pinned)
			var calls atomic.Int32
			base := f.server.Config.Handler
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); base.ServeHTTP(w, r) })
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			result, err := Install(Opts{Name: "fetch-contract", Client: f.client, TrustRoot: f.policy.TrustRoot(), ProjectPolicy: f.policy, HomeDir: f.home, Ctx: ctx})
			if !errors.Is(err, context.Canceled) || result != nil || calls.Load() != 0 {
				t.Fatalf("context cause or request precondition lost: %v calls=%d", err, calls.Load())
			}
		})
		t.Run(author+"/loopback-proxy", func(t *testing.T) {
			f := managedTransportFixture(t, pinned)
			var calls, proxyChoice atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(502) }))
			defer proxy.Close()
			target, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			tr := http.DefaultTransport.(*http.Transport).Clone()
			t.Cleanup(tr.CloseIdleConnections)
			tr.Proxy = func(*http.Request) (*url.URL, error) { proxyChoice.Add(1); return target, nil }
			f.client.HTTPClient.Transport = tr
			t.Setenv("HTTP_PROXY", proxy.URL)
			t.Setenv("http_proxy", proxy.URL)
			t.Setenv("NO_PROXY", "")
			t.Setenv("no_proxy", "")
			result, err := f.install(nil)
			if err != nil || result == nil || calls.Load() != 0 || proxyChoice.Load() != 0 {
				t.Fatalf("explicit loopback used caller proxy: %v requests=%d selection=%d", err, calls.Load(), proxyChoice.Load())
			}
		})
		t.Run(author+"/snapshot", func(t *testing.T) {
			f := managedTransportFixture(t, pinned)
			base := f.server.Config.Handler
			var bad atomic.Int32
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+managedTransportToken {
					bad.Add(1)
				}
				base.ServeHTTP(w, r)
			})
			logger := &retainedRootLogger{event: "resolved", mutate: func() error {
				f.client.BaseURL = "https://foreign.invalid/api/skills"
				f.client.Token = "changed-selected-token"
				f.client.HTTPClient.Transport = registryIdentityForbiddenTransport{t: t}
				return nil
			}}
			t.Setenv("M3C_REGISTRY_TOKEN", "ambient-changed")
			result, err := f.install(logger)
			if err != nil || result == nil || !logger.fired || logger.err != nil || bad.Load() != 0 {
				t.Fatalf("managed snapshot drift: %v fired=%v headers=%d", err, logger.fired, bad.Load())
			}
		})
		for _, mode := range []string{"malformed-location", "metadata-reflection"} {
			t.Run(author+"/"+mode, func(t *testing.T) {
				f := managedTransportFixture(t, pinned)
				old := installedDependencyOldTarget(t, f.home)
				base := f.server.Config.Handler
				var hit atomic.Int32
				f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "malformed-location" && managedTransportRoute(r) == "name" {
						hit.Add(1)
						w.Header().Set("Location", f.server.URL+"/api/skills/"+managedTransportToken+"%zz")
						w.WriteHeader(302)
						return
					}
					if mode == "metadata-reflection" && managedTransportRoute(r) == "meta" {
						hit.Add(1)
						m := *f.meta
						m.Bundle = map[string]any{"bundle_digest": managedTransportToken, "status": "admitted"}
						_ = json.NewEncoder(w).Encode(m)
						return
					}
					base.ServeHTTP(w, r)
				})
				result, err := f.install(nil)
				if err == nil || result != nil || hit.Load() != 1 {
					t.Fatalf("managed error case not reached: %v hits=%d", err, hit.Load())
				}
				if strings.Contains(err.Error(), managedTransportToken) {
					t.Fatal("selected credential reflected in managed error")
				}
				if mode == "metadata-reflection" && !errors.Is(err, verify.ErrDigestMismatch) {
					t.Fatalf("managed redaction changed trust classification: %v", err)
				}
				assertInstalledDependencyOldTarget(t, old)
			})
		}
		t.Run(author+"/override-no-audit", func(t *testing.T) {
			f := managedTransportFixture(t, pinned)
			calls := 0
			_, err := Install(Opts{Name: "fetch-contract", Client: f.client, TrustRoot: f.policy.TrustRoot(), ProjectPolicy: f.policy, HomeDir: f.home, IgnoreDeps: true, AuditPoster: func(context.Context, AuditEntry) error { calls++; return nil }})
			if !errors.Is(err, verify.ErrRegistryNotTrusted) || calls != 0 {
				t.Fatalf("managed override reached audit: %v calls=%d", err, calls)
			}
		})
	}
	t.Run("local-pinned-no-http", func(t *testing.T) {
		f := managedTransportFixture(t, true)
		var calls atomic.Int32
		base := f.server.Config.Handler
		f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); base.ServeHTTP(w, r) })
		result, err := InstallBundle(BundleOpts{ProjectPolicy: f.policy, TrustRoot: f.policy.TrustRoot(), HomeDir: f.home, BundlePath: writeBundle(t, f.root), Meta: f.meta})
		if err != nil || result == nil || calls.Load() != 0 {
			t.Fatalf("local route used HTTP: %v calls=%d", err, calls.Load())
		}
	})
}
