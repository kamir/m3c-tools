package git

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// TestGitEventsSinceHostInstall covers the three ER1↔GitLab parity additions on
// the git side in one lifecycle: (1) an installed event published OVER git
// (Publish(KindInstall) appended under events/<digesthex>/ and surfaced by
// Events); (2) EventRecord.Host populated from packed_on_host / installed_on_host;
// (3) ListFilter.Since honored on occurred_at.
func TestGitEventsSinceHostInstall(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	b := newGitBackend(bareRepo(t), "gitlab")
	defer b.Close()
	d := fdig('a')

	// admit @ 2026-01-01 on host boxA
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind: artifact.KindAdmit,
		Event: map[string]any{
			"kind": "admitted", "name": "ev", "version": "1.0.0", "bundle_digest": d,
			"occurred_at": "2026-01-01T00:00:00Z", "packed_on_host": "boxA",
		},
		Meta: artifact.ArtifactMeta{Name: "ev", Version: "1.0.0", Digest: d},
		Blob: []byte("SKB:ev@1.0.0"),
	}); err != nil {
		t.Fatalf("admit: %v", err)
	}

	// installed event OVER GIT @ 2026-06-01 on host boxB
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind: artifact.KindInstall,
		Event: map[string]any{
			"kind": "installed", "bundle_digest": d,
			"occurred_at": "2026-06-01T00:00:00Z", "installed_on_host": "boxB",
		},
		Meta: artifact.ArtifactMeta{Name: "ev", Version: "1.0.0", Digest: d},
	}); err != nil {
		t.Fatalf("install-over-git: %v", err)
	}

	// No --since: both events, with Host + OccurredAt populated.
	page, err := b.Events(ctx, artifact.ListFilter{Name: "ev"}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("got %d events, want 2 (admit + install): %+v", len(page.Events), page.Events)
	}
	var sawAdmitHost, sawInstall bool
	for _, e := range page.Events {
		switch e.Kind {
		case artifact.KindAdmit:
			if e.Host != "boxA" {
				t.Errorf("admit Host = %q, want boxA", e.Host)
			}
			if e.OccurredAt.IsZero() {
				t.Error("admit OccurredAt not parsed")
			}
			sawAdmitHost = true
		case artifact.KindInstall:
			if e.Host != "boxB" {
				t.Errorf("install Host = %q, want boxB (installed_on_host)", e.Host)
			}
			sawInstall = true
		}
	}
	if !sawAdmitHost || !sawInstall {
		t.Errorf("missing admit-host (%v) or installed-over-git event (%v)", sawAdmitHost, sawInstall)
	}

	// --since 2026-03-01 excludes the Jan admit, keeps the Jun install.
	page2, err := b.Events(ctx, artifact.ListFilter{Name: "ev", Since: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}, artifact.Page{})
	if err != nil {
		t.Fatalf("Events --since: %v", err)
	}
	if len(page2.Events) != 1 || page2.Events[0].Kind != artifact.KindInstall {
		t.Errorf("--since 2026-03 => want [installed], got %+v", page2.Events)
	}
}
