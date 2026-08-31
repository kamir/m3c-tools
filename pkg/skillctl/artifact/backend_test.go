package artifact

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSchemeOf(t *testing.T) {
	cases := map[string]string{
		"self":                                "er1",
		"er1://prod/skills":                   "er1",
		"https://onboarding.guide/api/skills": "https",
		"http://localhost:8080/api/skills":    "https",
		"github://kamir/skills":               "github",
		"gitlab://gitlab.example.com/g/p":     "gitlab",
		"oci://ghcr.io/kamir/skills":          "oci",
		"":                                    "",
		"weird-no-scheme":                     "",
		"foo://bar":                           "foo",
	}
	for in, want := range cases {
		if got := SchemeOf(in); got != want {
			t.Errorf("SchemeOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenUnknownScheme(t *testing.T) {
	_, err := Open("nope://x", OpenOptions{})
	if err == nil {
		t.Fatal("expected error for unregistered scheme")
	}
	if !strings.Contains(err.Error(), "no backend registered") {
		t.Errorf("unexpected error: %v", err)
	}
}

// fakeBackend is a compile-time proof the interface is implementable and a
// reusable offline test double (a precursor to the SPEC-0356 conformance
// harness).
type fakeBackend struct{ blobs map[string][]byte }

func (f *fakeBackend) Describe() Descriptor {
	return Descriptor{
		Scheme:  "faketest",
		Display: "in-memory fake",
		Capabilities: Capabilities{
			CanAdmit: true, CanRevoke: true, Paginated: true,
			Governance: GovNone, LatestPolicy: LatestSemverMax,
		},
	}
}
func (f *fakeBackend) Publish(ctx context.Context, req PublishRequest) (*PublishResult, error) {
	if req.Kind == KindAdmit {
		if f.blobs == nil {
			f.blobs = map[string][]byte{}
		}
		f.blobs[req.Meta.Digest] = req.Blob
	}
	return &PublishResult{Ref: ArtifactRef{Digest: req.Meta.Digest, Scheme: "faketest"}, Transport: "fake"}, nil
}
func (f *fakeBackend) List(ctx context.Context, filter ListFilter, page Page) (*Listing, error) {
	return &Listing{}, nil
}
func (f *fakeBackend) Resolve(ctx context.Context, q RefQuery) (*ArtifactRef, error) {
	return &ArtifactRef{Digest: q.Digest, Scheme: "faketest"}, nil
}
func (f *fakeBackend) Fetch(ctx context.Context, ref ArtifactRef) ([]byte, error) {
	b, ok := f.blobs[ref.Digest]
	if !ok {
		return nil, errors.New("artifact: not found")
	}
	return b, nil
}
func (f *fakeBackend) Close() error { return nil }

// Compile-time assertion that fakeBackend satisfies the core interface.
var _ Backend = (*fakeBackend)(nil)

func TestRegisterAndRoundTrip(t *testing.T) {
	Register("faketest", func(spec string, opts OpenOptions) (Backend, error) {
		return &fakeBackend{}, nil
	})
	if !Registered("faketest://x") {
		t.Fatal("Registered should be true after Register")
	}
	b, err := Open("faketest://x", OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	if b.Describe().Scheme != "faketest" {
		t.Errorf("Describe().Scheme = %q, want faketest", b.Describe().Scheme)
	}

	dig := "sha256:" + strings.Repeat("a", 64)
	if _, err := b.Publish(context.Background(), PublishRequest{
		Kind: KindAdmit, Meta: ArtifactMeta{Name: "x", Version: "1.0.0", Digest: dig}, Blob: []byte("skb-bytes"),
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := b.Fetch(context.Background(), ArtifactRef{Digest: dig})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != "skb-bytes" {
		t.Errorf("Fetch = %q, want skb-bytes", got)
	}
}

func TestDuplicateRegisterPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate Register")
		}
	}()
	Register("dup-scheme", func(string, OpenOptions) (Backend, error) { return nil, nil })
	Register("dup-scheme", func(string, OpenOptions) (Backend, error) { return nil, nil })
}
