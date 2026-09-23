package linux

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// The fixtures under testdata are transcribed from a real Ubuntu 24.04.1
// host and sanitized; testdata/README.md and testdata/commands.json name the
// exact argv, stream and exit code of every one of them. The tests below run
// on any operating system, because every tool call goes through the fake
// runner (SPEC-0467 R9).

var netTestTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

const netTestHostname = "host-a.example"

// netFixture reads one fixture file by its path relative to testdata.
func netFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("fixture %s: %v", rel, err)
	}
	return b
}

// netTestHost builds a Linux host context with the given runner.
func netTestHost(runner probe.CommandRunner) probe.HostContext {
	return probe.HostContext{
		GOOS: "linux", GOARCH: "amd64",
		Hostname:  func() (string, error) { return netTestHostname, nil },
		Files:     probe.FakeFiles{},
		Runner:    runner,
		Clock:     trustfreeze.FixedClock{T: netTestTime},
		Privilege: probe.PrivilegeUser,
	}
}

// netTestCollect builds a collect context with an evidence buffer.
func netTestCollect(probeID string, runner probe.CommandRunner) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(probeID, probe.Limits{})
	return probe.CollectContext{
		HostContext: netTestHost(runner),
		ProbeID:     probeID,
		Redactor:    redact.Default(),
		Evidence:    ev,
		Support:     probe.Supported(),
	}, ev
}

// netArtifact returns the artifact with id or fails.
func netArtifact(t *testing.T, res trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no artifact %q; got %v", id, netArtifactIDs(res))
	return trustfreeze.Artifact{}
}

func netArtifactIDs(res trustfreeze.ProbeResult) []string {
	out := make([]string, 0, len(res.NormalizedState))
	for _, a := range res.NormalizedState {
		out = append(out, a.ID)
	}
	return out
}

// netEvidenceNames returns the names of the buffered evidence files.
func netEvidenceNames(ev *probe.EvidenceBuffer) []string {
	items := ev.Close()
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Name)
	}
	sort.Strings(out)
	return out
}

func netHasWarning(res trustfreeze.ProbeResult, code, field string) bool {
	for _, w := range res.Warnings {
		if w.Code == code && (field == "" || w.Field == field) {
			return true
		}
	}
	return false
}

// netListenersRunner scripts the two calls of the listener probe with the
// fixtures of the trial host.
func netListenersRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().AddTool(ListenersTool, "/usr/bin/ss").
		Script(ListenersTool, []string{"-V"}, probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-version.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")})
}

// TF06-R3: the fixture holds all 51 listeners of the trial host. The parser
// reads every row, classifies the exposure of each address and keeps the
// zone of a scoped address apart from the address itself.
func TestParseSSListenersReadsEveryRowOfTheFixture(t *testing.T) {
	listeners, diags := ParseSSListeners(netFixture(t, "network.listeners/ss-H-lntup.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if len(listeners) != 51 {
		t.Fatalf("got %d listeners, want 51", len(listeners))
	}
	counts := map[string]int{}
	owners := 0
	for _, l := range listeners {
		counts[l.Exposure]++
		if l.OwnerKnown() {
			owners++
		}
	}
	if counts[ExposureAnyAddress] != 42 || counts[ExposureLoopback] != 9 {
		t.Errorf("exposure counts %v, want 42 any_address and 9 loopback", counts)
	}
	if owners != 1 {
		t.Errorf("%d listeners with a known owner, want 1 (unprivileged ss fills the users column only for its own processes)", owners)
	}
}

// The rows that carry the traps of the fixture: a scoped loopback address, a
// bracketed IPv6 wildcard, the bare "*" and the one row with an owner.
func TestParseSSListenersSpotChecks(t *testing.T) {
	listeners, _ := ParseSSListeners(netFixture(t, "network.listeners/ss-H-lntup.txt"))
	byID := map[string]Listener{}
	for _, l := range listeners {
		byID[l.ArtifactID()] = l
	}
	cases := []struct {
		id       string
		address  string
		zone     string
		exposure string
		family   string
		socket   string
	}{
		{"network/listener/tcp/127.0.0.53%lo/53", "127.0.0.53", "lo", ExposureLoopback, familyIPv4, "LISTEN"},
		{"network/listener/udp/0.0.0.0/5353", "0.0.0.0", "", ExposureAnyAddress, familyIPv4, "UNCONN"},
		{"network/listener/tcp/[::]/22", "::", "", ExposureAnyAddress, familyIPv6, "LISTEN"},
		{"network/listener/tcp/[::1]/631", "::1", "", ExposureLoopback, familyIPv6, "LISTEN"},
		{"network/listener/tcp/*/18088", "*", "", ExposureAnyAddress, familyUnspecified, "LISTEN"},
	}
	for _, c := range cases {
		l, ok := byID[c.id]
		if !ok {
			t.Errorf("no listener %s", c.id)
			continue
		}
		if l.Address != c.address || l.Zone != c.zone || l.Exposure != c.exposure || l.Family != c.family || l.SocketState != c.socket {
			t.Errorf("%s: got address %q zone %q exposure %q family %q state %q", c.id, l.Address, l.Zone, l.Exposure, l.Family, l.SocketState)
		}
	}
	owner := byID["network/listener/tcp/*/18088"]
	if len(owner.Processes) != 1 || owner.Processes[0].Name != "svc-app-exporte" || owner.Processes[0].PID != "2698" {
		t.Errorf("owner column of the one observable listener: %+v", owner.Processes)
	}
}

func TestClassifyExposure(t *testing.T) {
	cases := []struct{ address, want string }{
		{"0.0.0.0", ExposureAnyAddress},
		{"::", ExposureAnyAddress},
		{"[::]", ExposureAnyAddress},
		{"*", ExposureAnyAddress},
		{"127.0.0.1", ExposureLoopback},
		{"127.0.0.53%lo", ExposureLoopback},
		{"::1", ExposureLoopback},
		{"[::1]", ExposureLoopback},
		{"169.254.10.1", ExposureLinkLocal},
		{"[fe80::1%eth0]", ExposureLinkLocal},
		{"203.0.113.10", ExposureSpecificAddress},
		{"2001:db8::1", ExposureSpecificAddress},
		{"", ExposureUnknown},
		{"not-an-address", ExposureUnknown},
	}
	for _, c := range cases {
		if got := ClassifyExposure(c.address); got != c.want {
			t.Errorf("ClassifyExposure(%q) = %q, want %q", c.address, got, c.want)
		}
	}
}

// A row with too few columns and a local endpoint without a port are lost
// records, not silent omissions: each one yields a diagnostic.
func TestParseSSListenersReportsUnreadableRecords(t *testing.T) {
	in := "tcp LISTEN 0 4096\n" +
		"tcp LISTEN 0 4096 0.0.0.0 0.0.0.0:*\n" +
		"tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
	listeners, diags := ParseSSListeners([]byte(in))
	if len(listeners) != 1 || listeners[0].Port != "22" {
		t.Fatalf("got %d listeners, want the one readable row: %+v", len(listeners), listeners)
	}
	if len(diags) != 2 {
		t.Fatalf("got %d diagnostics, want one per unreadable row: %v", len(diags), diags)
	}
	for _, d := range diags {
		if d.Code != netDiagRecordUnparsed {
			t.Errorf("diagnostic code %q, want %q", d.Code, netDiagRecordUnparsed)
		}
	}
}

// TF06-R2: an unprivileged run cannot see the owning process of a socket of
// another user. The result is partial with a named gap, never captured.
func TestListenersProbeIsPartialWhenOwnersAreNotObservable(t *testing.T) {
	cc, ev := netTestCollect(ListenersProbeID, netListenersRunner(t))
	res := NewListenersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "50 of 51") {
		t.Errorf("reason %q does not name the 50 of 51 listeners without an owner", res.Reason)
	}
	if !netHasWarning(res, probe.DiagFieldPermissionDenied, "listener_process") {
		t.Errorf("no permission diagnostic for the owner column: %v", res.Warnings)
	}
	if len(res.NormalizedState) != 52 {
		t.Fatalf("got %d artifacts, want 51 listeners plus the set artifact", len(res.NormalizedState))
	}
	set := netArtifact(t, res, ArtifactListeners)
	for k, want := range map[string]string{
		"listener_count":         "51",
		"any_address_count":      "42",
		"loopback_count":         "9",
		"link_local_count":       "0",
		"specific_address_count": "0",
		"owner_unknown_count":    "50",
	} {
		if set.Attributes[k] != want {
			t.Errorf("%s = %q, want %q", k, set.Attributes[k], want)
		}
	}
	if set.Provenance.ToolVersion != "ss utility, iproute2-6.1.0" {
		t.Errorf("tool version %q, want the line of the ss -V fixture", set.Provenance.ToolVersion)
	}
	exposed := netArtifact(t, res, "network/listener/tcp/0.0.0.0/22")
	if exposed.Attributes["exposure"] != ExposureAnyAddress || exposed.Attributes["owner_known"] != "false" {
		t.Errorf("the ssh listener is the interesting finding: %v", exposed.Attributes)
	}
	if exposed.State != trustfreeze.StateObserved || exposed.Digest == "" {
		t.Errorf("listener artifact state %q digest %q", exposed.State, exposed.Digest)
	}
	owned := netArtifact(t, res, "network/listener/tcp/*/18088")
	if owned.Attributes["process_name"] != "svc-app-exporte" || owned.Attributes["pid"] != "2698" {
		t.Errorf("owner attributes: %v", owned.Attributes)
	}
	if got := netEvidenceNames(ev); len(got) != 2 || got[0] != "ss-lntup.stdout" || got[1] != "ss-version.stdout" {
		t.Errorf("evidence files %v", got)
	}
}

// Every id the probe produces is a valid artifact id, whatever shape the
// address had (SPEC-0466 R4).
func TestListenerArtifactIDsAreValid(t *testing.T) {
	cc, _ := netTestCollect(ListenersProbeID, netListenersRunner(t))
	res := NewListenersProbe().Collect(context.Background(), cc)
	for _, a := range res.NormalizedState {
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			t.Errorf("artifact id %q: %v", a.ID, err)
		}
	}
	// Sorted by id, so two captures of an unchanged host produce the same
	// bytes.
	for i := 1; i < len(res.NormalizedState); i++ {
		if res.NormalizedState[i-1].ID >= res.NormalizedState[i].ID {
			t.Fatalf("artifacts are not sorted: %q before %q", res.NormalizedState[i-1].ID, res.NormalizedState[i].ID)
		}
	}
}

// The pid of a listening process is volatile: the probe records it under the
// attribute key the normalization rule set drops, so a restarted but
// otherwise unchanged service is not drift (SPEC-0469 R4).
func TestListenerPIDIsDroppedByTheNormalizationRuleSet(t *testing.T) {
	cc, _ := netTestCollect(ListenersProbeID, netListenersRunner(t))
	res := NewListenersProbe().Collect(context.Background(), cc)
	owned := netArtifact(t, res, "network/listener/tcp/*/18088")

	rs, err := compare.LoadRuleSet("")
	if err != nil {
		t.Fatalf("load rule set: %v", err)
	}
	normalized := rs.NormalizeAttributes(owned.Attributes)
	if _, ok := normalized["pid"]; ok {
		t.Errorf("the pid attribute survived normalization: %v", normalized)
	}
	if normalized["process_name"] != "svc-app-exporte" {
		t.Errorf("the program name must survive normalization: %v", normalized)
	}
}

// An empty result that is genuinely empty is captured with an empty list,
// and the set artifact says so (SPEC-0471 TF06-R2).
func TestListenersProbeEmptyResultIsCaptured(t *testing.T) {
	runner := probe.NewFakeRunner().AddTool(ListenersTool, "/usr/bin/ss").
		Script(ListenersTool, []string{"-V"}, probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-version.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{
			Stdout: netFixture(t, "honest-status/empty-result-ss-no-match.txt"),
		})
	cc, _ := netTestCollect(ListenersProbeID, runner)
	res := NewListenersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q)", res.Status, res.Reason)
	}
	if len(res.NormalizedState) != 1 {
		t.Fatalf("got %d artifacts, want only the set artifact", len(res.NormalizedState))
	}
	if got := netArtifact(t, res, ArtifactListeners).Attributes["listener_count"]; got != "0" {
		t.Errorf("listener_count = %q, want 0", got)
	}
}

// A missing tool is unavailable, in Support and in Collect, and no artifact
// claims an empty listener list.
func TestListenersProbeWithoutSS(t *testing.T) {
	runner := probe.NewFakeRunner()
	p := NewListenersProbe()
	sup := p.Support(context.Background(), netTestHost(runner))
	if sup.Available || sup.Status != trustfreeze.StatusUnavailable {
		t.Fatalf("support %+v, want unavailable", sup)
	}
	cc, _ := netTestCollect(ListenersProbeID, runner)
	res := p.Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusUnavailable {
		t.Fatalf("status %q, want unavailable", res.Status)
	}
	if len(res.NormalizedState) != 0 {
		t.Errorf("a probe without its tool must not produce artifacts: %v", netArtifactIDs(res))
	}
	if res.Error == nil || res.Error.Class != probe.ClassToolMissing {
		t.Errorf("error %+v, want the tool_missing class", res.Error)
	}
}

// ss is a Linux tool: on another platform the probe is unsupported, not
// unavailable (SPEC-0471 TF06-R2).
func TestListenersProbeSupportOnOtherPlatform(t *testing.T) {
	host := netTestHost(netListenersRunner(t))
	host.GOOS = "darwin"
	sup := NewListenersProbe().Support(context.Background(), host)
	if sup.Available || sup.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("support %+v, want unsupported", sup)
	}
}

// The descriptor is valid and the probe names the executables doctor
// resolves without running them.
func TestListenersProbeDescriptor(t *testing.T) {
	p := NewListenersProbe()
	if err := p.Descriptor().Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if got := p.RequiredTools(); len(got) != 1 || got[0] != "ss" {
		t.Errorf("required tools %v", got)
	}
	if levels := p.EvidenceClaims()[probe.PlatformLinux]; len(levels) != 2 {
		t.Errorf("evidence claims %v", levels)
	}
}
