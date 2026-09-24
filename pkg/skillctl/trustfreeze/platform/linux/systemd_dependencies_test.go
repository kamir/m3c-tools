package linux

// Tests of the systemd dependency edges (SPEC-0471 TF06-R3, T-03b section 1D).
//
// The measured input is testdata/systemd/systemctl-show-dependencies.txt from
// the Ubuntu 22.04 bastion and testdata/systemd/systemctl-show-required-by.txt
// from the Ubuntu 24.04.1 trial host; testdata/executables/README.md names the
// argv, the stream and the exit code of both. The one constructed input is the
// over-long list of the cut test, because the longest dependency line measured
// over all 372 units of the trial host was 346 bytes and no host of this
// laboratory carries one above the cap.

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// The property list of the call and the map that records the answers are the
// two places a dependency kind is named, and they must name the same five. A
// property that is recorded without being asked for would produce an attribute
// that is always empty; one that is asked for without being recorded would cost
// output for nothing.
func TestSystemdDependencyPropertiesAreAsked(t *testing.T) {
	asked := map[string]bool{}
	for _, p := range strings.Split(systemdShowProperties, ",") {
		asked[p] = true
	}
	want := []string{ShowPropRequires, ShowPropWants, ShowPropAfter, ShowPropBindsTo, ShowPropRequiredBy}
	if len(systemdDependencyProperties) != len(want) {
		t.Fatalf("%d dependency properties are recorded, want %d", len(systemdDependencyProperties), len(want))
	}
	seen := map[string]bool{}
	for _, p := range want {
		if !asked[p] {
			t.Errorf("%s is recorded but not in systemdShowProperties", p)
		}
		attr, ok := systemdDependencyProperties[p]
		if !ok {
			t.Fatalf("%s has no attribute name", p)
		}
		if seen[attr] {
			t.Errorf("two properties record into the attribute %q", attr)
		}
		seen[attr] = true
	}
}

// The parser reads a space separated unit list, sorts it and drops the
// duplicates, so two captures of an unchanged host produce the same bytes
// (playbook L8).
func TestParseUnitList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   []string
	}{
		{
			// The measured Requires of the ngrok unit: three names, the root
			// mount unit among them, and the manager's own order. The sort is
			// by BYTE, so "sysinit.target" comes before "system.slice"; that is
			// what makes two captures comparable, not what a reader would call
			// alphabetical.
			name:   "the measured requires of a real unit",
			values: []string{"system.slice -.mount sysinit.target"},
			want:   []string{"-.mount", "sysinit.target", "system.slice"},
		},
		{
			name:   "an empty property is no edge",
			values: []string{""},
			want:   nil,
		},
		{
			name:   "no property at all",
			values: nil,
			want:   nil,
		},
		{
			name:   "duplicates collapse",
			values: []string{"a.service b.service a.service"},
			want:   []string{"a.service", "b.service"},
		},
		{
			// systemd prints a property once per unit, but the block keeps
			// every value it saw, and all of them are read.
			name:   "several values of one property",
			values: []string{"b.service", "a.service b.service"},
			want:   []string{"a.service", "b.service"},
		},
		{
			name:   "runs of white space",
			values: []string{"  a.service \t b.service  "},
			want:   []string{"a.service", "b.service"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUnitList(tc.values...)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseUnitList(%q) = %v, want %v", tc.values, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseUnitList(%q) = %v, want %v", tc.values, got, tc.want)
				}
			}
		})
	}
}

// The measured show answer of the bastion: the edges land on the OBSERVED
// artifact of the unit, an empty property records nothing, and the declared
// artifact carries none of them.
func TestSystemdDependencyEdgesFromMeasuredAnswer(t *testing.T) {
	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: netFixture(t, "executables/systemctl-list-unit-files-subset-2204.txt")})
	runner.Script(systemctlExe, append([]string{"show", "--no-pager", "-p", systemdShowProperties},
		"ngrok-host-a.service", "ssh.socket"),
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-show-dependencies.txt")})
	cc, _ := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, reason %q, warnings %+v", res.Status, res.Reason, res.Warnings)
	}

	a := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"ngrok-host-a.service")
	if a.State != trustfreeze.StateObserved {
		t.Fatalf("state %q, want observed", a.State)
	}
	for attr, want := range map[string]string{
		systemdAttrRequires: "-.mount,sysinit.target,system.slice",
		systemdAttrWants:    "network-online.target,tmp.mount",
		systemdAttrAfter: "-.mount,basic.target,network-online.target,ssh.service,sysinit.target," +
			"system.slice,systemd-journald.socket,systemd-tmpfiles-setup.service,tmp.mount",
	} {
		if got := a.Attributes[attr]; got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
	// The manager printed "BindsTo=" and "RequiredBy=": no edge, and therefore
	// no attribute. An attribute with an empty value would make an absent edge
	// look like a recorded one.
	for _, attr := range []string{systemdAttrBindsTo, systemdAttrRequiredBy} {
		if got, ok := a.Attributes[attr]; ok {
			t.Errorf("%s = %q, want no attribute at all", attr, got)
		}
	}
	// No count attribute, because nothing was cut.
	for attr := range systemdDependencyProperties {
		if _, ok := a.Attributes[systemdDependencyProperties[attr]+systemdAttrCountSuffix]; ok {
			t.Errorf("a count attribute was recorded although the list fits")
		}
	}
	// The measured Requires names units no unit file can name (the manager adds
	// them), which is why the declared artifact carries no edges (playbook L3).
	declared := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"ngrok-host-a.service")
	if declared.State != trustfreeze.StateDeclared {
		t.Fatalf("the unit artifact has state %q", declared.State)
	}
	for _, attr := range []string{systemdAttrRequires, systemdAttrWants, systemdAttrAfter, systemdAttrBindsTo, systemdAttrRequiredBy} {
		if got, ok := declared.Attributes[attr]; ok {
			t.Errorf("the declared artifact carries %s = %q", attr, got)
		}
	}
	// The socket unit of the same answer: two edges, and its own artifact.
	socket := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"ssh.socket")
	if got := socket.Attributes[systemdAttrRequires]; got != "sysinit.target,system.slice" {
		t.Errorf("ssh.socket requires %q", got)
	}
	if got, ok := socket.Attributes[systemdAttrWants]; ok {
		t.Errorf("ssh.socket wants %q, want no attribute", got)
	}
}

// The reverse edge the manager computes: 17 unit names in the longest
// dependency line measured on the trial host.
func TestSystemdDependencyEdgesRequiredBy(t *testing.T) {
	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: execUnitFileList(map[string]string{
			"dbus.socket": "static", "docker.socket": "enabled",
		})})
	runner.Script(systemctlExe, append([]string{"show", "--no-pager", "-p", systemdShowProperties},
		"dbus.socket", "docker.socket"),
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-show-required-by.txt")})
	cc, _ := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)

	a := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"dbus.socket")
	got := a.Attributes[systemdAttrRequiredBy]
	names := strings.Split(got, ",")
	if len(names) != 17 {
		t.Fatalf("required_by holds %d names, want the 17 of the measured line: %q", len(names), got)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("required_by is not sorted: %q", got)
		}
	}
	if names[0] != "ModemManager.service" || names[len(names)-1] != "wpa_supplicant.service" {
		t.Fatalf("required_by = %q", got)
	}
	// The measured line is 343 bytes and therefore fits: no cut, no count.
	if _, ok := a.Attributes[systemdAttrRequiredBy+systemdAttrCountSuffix]; ok {
		t.Error("the longest measured dependency line was reported as cut")
	}
	b := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"docker.socket")
	if got := b.Attributes[systemdAttrRequiredBy]; got != "docker.service" {
		t.Errorf("docker.socket required_by = %q", got)
	}
}

// A dependency list above the cap is recorded up to the last name that fitted,
// the count says how many there were, and the run is partial: a cut list is an
// incomplete list (playbook L1). The input is constructed, because the longest
// line measured on either host is a third of the cap.
func TestSystemdDependencyListCut(t *testing.T) {
	var deps []string
	total := 0
	for i := 0; total <= systemdMaxDependencyBytes; i++ {
		name := "dep-" + string(rune('a'+i%26)) + "-" + strings.Repeat("x", 20) + "-" + strconv.Itoa(i) + ".service"
		deps = append(deps, name)
		total += len(name) + 1
	}
	answer := "Id=cut.service\nLoadState=loaded\nActiveState=active\nAfter=" + strings.Join(deps, " ") + "\n"
	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"cut.service": "enabled"})})
	runner.Script(systemctlExe, append([]string{"show", "--no-pager", "-p", systemdShowProperties}, "cut.service"),
		probe.FakeResponse{Stdout: []byte(answer)})
	cc, _ := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial", res.Status)
	}
	a := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"cut.service")
	got := a.Attributes[systemdAttrAfter]
	if len(got) > systemdMaxDependencyBytes {
		t.Fatalf("the recorded list is %d bytes, above the cap of %d", len(got), systemdMaxDependencyBytes)
	}
	if strings.HasSuffix(got, ",") || strings.Contains(got, ",,") {
		t.Fatalf("the cut did not land on a name boundary: %q", got)
	}
	if want := strconv.Itoa(len(deps)); a.Attributes[systemdAttrAfter+systemdAttrCountSuffix] != want {
		t.Fatalf("after_count = %q, want %q", a.Attributes[systemdAttrAfter+systemdAttrCountSuffix], want)
	}
	var found bool
	for _, w := range res.Warnings {
		if w.Code == DiagSystemdDependencyTruncated && strings.Contains(w.Message, "cut.service") &&
			strings.Contains(w.Message, ShowPropAfter) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s diagnostic names the unit and the property: %+v", DiagSystemdDependencyTruncated, res.Warnings)
	}
}
