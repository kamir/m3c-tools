package capture

import (
	"context"
	"slices"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// toolFake is a fakeProbe that also names the executables it uses
// (ToolUser). The interface is structural, so this is the whole cost of
// implementing it.
type toolFake struct {
	*fakeProbe
	tools []string
}

func (f toolFake) RequiredTools() []string { return f.tools }

func newToolFake(id string, tools ...string) toolFake {
	return toolFake{fakeProbe: newFake(id, captured), tools: tools}
}

// TestPlanResolvesDeclaredTools: Plan resolves every executable a probe names
// through the runner's LookPath and runs none of them (SPEC-0471 section
// 11.2). A probe that names none reports ToolsDeclared false, which is not
// the same as a probe with no tools.
func TestPlanResolvesDeclaredTools(t *testing.T) {
	p := profile(t, []string{"common.identity"}, []string{"test.tools", "test.missing", "test.silent"})
	runner := identityRunner().AddTool("ss", "/usr/sbin/ss").DenyTool("nft", "/usr/sbin/nft")
	reg := registry(t,
		newToolFake("test.tools", "ss", "uname", "ss"),
		newToolFake("test.missing", "absent-tool", "nft"),
		newFake("test.silent", captured),
	)
	rows := Plan(context.Background(), p, reg, fixtureHost(runner))
	byID := map[string]PlannedProbe{}
	for _, r := range rows {
		byID[r.ProbeID] = r
	}

	// Declared, resolvable, sorted and deduplicated.
	got := byID["test.tools"]
	if !got.ToolsDeclared || len(got.Tools) != 2 {
		t.Fatalf("test.tools: declared %v, tools %+v", got.ToolsDeclared, got.Tools)
	}
	if got.Tools[0].Name != "ss" || got.Tools[1].Name != "uname" {
		t.Fatalf("tools not sorted and deduplicated: %+v", got.Tools)
	}
	for _, tc := range got.Tools {
		if !tc.OK() || tc.Path == "" {
			t.Fatalf("%s did not resolve: %+v", tc.Name, tc)
		}
	}

	// A missing tool and one that is not executable keep their class.
	got = byID["test.missing"]
	if !got.ToolsDeclared || len(got.Tools) != 2 {
		t.Fatalf("test.missing: %+v", got)
	}
	want := map[string]string{"absent-tool": probe.ClassToolMissing, "nft": probe.ClassPermissionDenied}
	for _, tc := range got.Tools {
		if tc.OK() || tc.Class != want[tc.Name] {
			t.Fatalf("%s: class %q, want %q (%+v)", tc.Name, tc.Class, want[tc.Name], tc)
		}
	}

	// A probe that names nothing is reported as such, not as "no tools".
	if got = byID["test.silent"]; got.ToolsDeclared || len(got.Tools) != 0 {
		t.Fatalf("test.silent: %+v", got)
	}

	// Nothing was executed.
	if calls := runner.Calls(); len(calls) != 0 {
		t.Fatalf("Plan ran %d command(s): %+v", len(calls), calls)
	}
}

// TestPlanToolsNeedAPlatformAndARegistration: an unregistered probe and one
// this build does not implement for the host platform have no tools to
// resolve, so they report ToolsDeclared false.
func TestPlanToolsNeedAPlatformAndARegistration(t *testing.T) {
	p := profile(t, []string{"common.identity"}, []string{"test.other-platform", "test.unregistered"})
	other := newToolFake("test.other-platform", "ss")
	other.fakeProbe.d.Platforms = []probe.Platform{probe.PlatformWindows}
	rows := Plan(context.Background(), p, registry(t, other), fixtureHost(identityRunner()))
	for _, r := range rows {
		switch r.ProbeID {
		case "test.other-platform":
			if r.ToolsDeclared || len(r.Tools) != 0 {
				t.Fatalf("a probe for another platform declared tools: %+v", r)
			}
		case "test.unregistered":
			if r.Registered || r.ToolsDeclared || r.Support.Reason != trustfreeze.ReasonNotImplemented {
				t.Fatalf("unregistered probe: %+v", r)
			}
		}
	}
}

// TestFileRootsOfACaptureAreTwoLists: a capture has two file seams, and the two
// accessors say which is which (review of T-03b, finding 3).
//
// The engine's restricted reader refuses every path outside DefaultAllowedRoots.
// linux.executables hashes program files through its own reader, whose roots are
// NOT in that list, because a hash streams a file while the restricted reader
// returns whole files under a 1 MiB limit. A caller that reports only the first
// list understates what a capture may open.
func TestFileRootsOfACaptureAreTwoLists(t *testing.T) {
	reader := DefaultAllowedRoots("linux")
	own := ProbeOwnedRoots("linux")
	if len(reader) == 0 {
		t.Fatal("no restricted reader root on linux")
	}
	if len(own) == 0 {
		t.Fatal("no probe-owned root on linux, although linux.executables hashes under its own roots")
	}
	if !slices.IsSorted(own) {
		t.Errorf("the probe-owned roots are not sorted: %v", own)
	}
	if !slices.Equal(own, slices.Compact(append([]string(nil), own...))) {
		t.Errorf("the probe-owned roots carry a duplicate: %v", own)
	}
	// The two lists are disjoint in this build, which is the whole reason the
	// second one has to be reported: a reader of the first learns nothing about
	// it.
	for _, r := range own {
		if slices.Contains(reader, r) {
			t.Errorf("%s is in both lists; then one of the two accessors is wrong about which reader opens it", r)
		}
	}
	// Another platform has neither.
	for _, goos := range []string{"darwin", "windows"} {
		if got := ProbeOwnedRoots(goos); len(got) != 0 {
			t.Errorf("ProbeOwnedRoots(%q) = %v, want none: no probe of this build hashes a file there", goos, got)
		}
	}
}
