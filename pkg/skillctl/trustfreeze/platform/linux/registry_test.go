package linux

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// toolUser is the structural interface the capture package uses for the
// doctor tool check; it is repeated here so this package imports nothing of
// capture (SPEC-0471 section 11.2).
type toolUser interface{ RequiredTools() []string }

// SPEC-0471 TF06-R3: every probe of this package registers, on any platform,
// with a valid descriptor that names linux as its only platform.
func TestRegisterAllProbes(t *testing.T) {
	reg := probe.NewRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		ContainersProbeID, FirewallProbeID, MountsProbeID, ListenersProbeID,
		PackagesProbeID, SSHProbeID, SudoProbeID, SystemdProbeID, UsersProbeID,
	}
	slices.Sort(want)
	if got := reg.IDs(); !slices.Equal(got, want) {
		t.Fatalf("registered %q, want %q", got, want)
	}
	if err := Register(reg); err == nil {
		t.Fatal("registering twice was accepted")
	}
	for _, p := range Probes() {
		d := p.Descriptor()
		if err := d.Validate(); err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		if len(d.Platforms) != 1 || d.Platforms[0] != probe.PlatformLinux {
			t.Fatalf("%s: platforms %v, want linux only", d.ID, d.Platforms)
		}
		if d.RequiredPrivilege != probe.PrivilegeUser && d.RequiredPrivilege != probe.PrivilegeElevated {
			t.Fatalf("%s: privilege %q", d.ID, d.RequiredPrivilege)
		}
		// Every probe of this package runs at least one executable and names
		// it, so doctor can resolve it before a capture.
		u, ok := p.(toolUser)
		if !ok || len(u.RequiredTools()) == 0 {
			t.Fatalf("%s names no executable", d.ID)
		}
		for _, tool := range u.RequiredTools() {
			if strings.TrimSpace(tool) == "" || strings.ContainsAny(tool, "/\\ ") {
				t.Fatalf("%s: tool %q is not a bare executable name", d.ID, tool)
			}
		}
		// On another platform the probe is unsupported, never available.
		host := probe.HostContext{GOOS: "darwin"}
		if s := p.Support(context.Background(), host); s.Available {
			t.Fatalf("%s reports available on darwin", d.ID)
		}
	}
}

// The file roots of this package are only for linux, sorted and free of
// duplicates; the engine hands them to the restricted file reader.
func TestAllowedRoots(t *testing.T) {
	for _, goos := range []string{"darwin", "windows", ""} {
		if r := AllowedRoots(goos); r != nil {
			t.Fatalf("AllowedRoots(%q) = %v", goos, r)
		}
	}
	roots := AllowedRoots("linux")
	if !slices.IsSorted(roots) || len(roots) != len(slices.Compact(slices.Clone(roots))) {
		t.Fatalf("roots %v are not sorted or hold a duplicate", roots)
	}
	for _, want := range append(SudoAllowedRoots(), SSHAllowedRoots()...) {
		if !slices.Contains(roots, want) {
			t.Fatalf("root %q of a probe is missing from %v", want, roots)
		}
	}
	for _, r := range roots {
		if !strings.HasPrefix(r, "/") {
			t.Fatalf("root %q is not absolute", r)
		}
	}
}
