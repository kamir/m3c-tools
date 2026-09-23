package linux

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// The container fixtures come from the trial host (20 running containers,
// one docker info line, the empty listing and the unreachable daemon). Two
// shapes are constructed and say so here: the inspect answer, because the
// fixture set has no inspect call, and the refused socket, because the
// capturing account is in the docker group and could not produce that
// refusal read-only (testdata/README.md, "What this host could not show").

// netDockerPSIDs returns the container ids of the ps fixture, sorted, which
// is the order the probe passes them to the inspect call.
func netDockerPSIDs(t *testing.T) []string {
	t.Helper()
	containers, diags := ParseDockerPS(netFixture(t, "containers/docker-ps.txt"))
	if len(diags) != 0 {
		t.Fatalf("the ps fixture must parse cleanly: %v", diags)
	}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	return ids
}

// netDockerInspectOutput builds a constructed inspect answer for the ids of
// the ps fixture: the two kind nodes run privileged, everything else does
// not, and every container declares the same restart policy.
func netDockerInspectOutput(t *testing.T) []byte {
	t.Helper()
	containers, _ := ParseDockerPS(netFixture(t, "containers/docker-ps.txt"))
	privileged := map[string]bool{}
	for _, c := range containers {
		if strings.HasSuffix(c.Name(), "control-plane") {
			privileged[c.ID] = true
		}
	}
	var b strings.Builder
	for _, id := range netDockerPSIDs(t) {
		b.WriteString(id)
		b.WriteString("\tunless-stopped\t")
		if privileged[id] {
			b.WriteString("true\n")
		} else {
			b.WriteString("false\n")
		}
	}
	return []byte(b.String())
}

// netDockerRunner scripts the four docker calls; podman is absent, as it is
// on the trial host.
func netDockerRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	specs := containerRuntimeSpecs()[0]
	inspect := append(append([]string{}, specs.inspectArgs...), netDockerPSIDs(t)...)
	return probe.NewFakeRunner().AddTool(ContainerRuntimeDocker, "/usr/bin/docker").
		Script(ContainerRuntimeDocker, specs.versionArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-version.txt")}).
		Script(ContainerRuntimeDocker, specs.infoArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-info.txt")}).
		Script(ContainerRuntimeDocker, specs.psArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-ps.txt")}).
		Script(ContainerRuntimeDocker, inspect, probe.FakeResponse{Stdout: netDockerInspectOutput(t)})
}

// TF06-R3: the listing fixture holds 20 containers with six tab separated
// fields, an empty ports column, exposed ranges, both spellings of the IPv6
// wildcard and an image pinned by digest.
func TestParseDockerPSReadsEveryContainer(t *testing.T) {
	containers, diags := ParseDockerPS(netFixture(t, "containers/docker-ps.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if len(containers) != 20 {
		t.Fatalf("got %d containers, want 20", len(containers))
	}
	byName := map[string]Container{}
	for _, c := range containers {
		byName[c.Name()] = c
	}

	edge := byName["app-edge-supervisor"]
	if len(edge.Ports) != 2 {
		t.Fatalf("app-edge-supervisor ports %+v", edge.Ports)
	}
	if got := edge.Ports[0].String(); got != "0.0.0.0:9113->9113/tcp" {
		t.Errorf("port[0] = %q", got)
	}
	// The runtime prints the IPv6 wildcard as ":::9113" here and as
	// "[::]:19092" elsewhere; both are the same address.
	if got := edge.Ports[1].String(); got != "[::]:9113->9113/tcp" {
		t.Errorf("port[1] = %q", got)
	}
	if edge.Exposure() != ExposureAnyAddress {
		t.Errorf("exposure %q", edge.Exposure())
	}

	if w := byName["app-sim-writer"]; len(w.Ports) != 0 || w.Exposure() != ExposureNone {
		t.Errorf("a container without published ports: %+v", w.Ports)
	}
	broker := byName["app-stream-broker"]
	if len(broker.Ports) != 2 || broker.Ports[0].HostAddress != "" || broker.Exposure() != ExposureNone {
		t.Errorf("exposed ranges are not published ports: %+v", broker.Ports)
	}
	kind := byName["example-control-plane"]
	if kind.ImageDigest != "sha256:d16e5700d16e5700d16e5700d16e5700d16e5700d16e5700d16e5700d16e5700" {
		t.Errorf("image digest %q", kind.ImageDigest)
	}
	if len(kind.Ports) != 9 {
		t.Errorf("the kind node publishes 9 ports, got %d", len(kind.Ports))
	}
	loopback := byName["svc-app-control-plane"]
	if loopback.Ports[0].Exposure != ExposureLoopback && loopback.Ports[1].Exposure != ExposureLoopback {
		t.Errorf("a loopback publishing is not exposure: %+v", loopback.Ports)
	}
	if !strings.HasPrefix(byName["app-grafana"].Status, "Up ") {
		t.Errorf("the status column is parsed even though it is not persisted: %q", byName["app-grafana"].Status)
	}
}

func TestParsePublishedPorts(t *testing.T) {
	cases := []struct {
		in       string
		want     []string
		exposure []string
	}{
		{"", nil, nil},
		{"0.0.0.0:9113->9113/tcp, :::9113->9113/tcp",
			[]string{"0.0.0.0:9113->9113/tcp", "[::]:9113->9113/tcp"},
			[]string{ExposureAnyAddress, ExposureAnyAddress}},
		{"8080/tcp, 0.0.0.0:50000->50000/tcp",
			[]string{"0.0.0.0:50000->50000/tcp", "8080/tcp"},
			[]string{ExposureAnyAddress, ExposureNone}},
		{"127.0.0.1:39153->6443/tcp",
			[]string{"127.0.0.1:39153->6443/tcp"},
			[]string{ExposureLoopback}},
		{"[::]:19092->9092/tcp",
			[]string{"[::]:19092->9092/tcp"},
			[]string{ExposureAnyAddress}},
		{"9092-9094/tcp",
			[]string{"9092-9094/tcp"},
			[]string{ExposureNone}},
	}
	for _, c := range cases {
		ports, diags := ParsePublishedPorts(c.in)
		if len(diags) != 0 {
			t.Errorf("ParsePublishedPorts(%q) diagnostics %v", c.in, diags)
		}
		got := make([]string, 0, len(ports))
		for i, p := range ports {
			got = append(got, p.String())
			if p.Exposure != c.exposure[i] {
				t.Errorf("ParsePublishedPorts(%q)[%d] exposure %q, want %q", c.in, i, p.Exposure, c.exposure[i])
			}
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("ParsePublishedPorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, diags := ParsePublishedPorts("9113, ->9113/tcp"); len(diags) != 2 {
		t.Errorf("unreadable port entries must yield one diagnostic each: %v", diags)
	}
}

// The published ports of the containers and the listening sockets of the
// host are two views of the same exposure: every published host port of the
// listing fixture carries the artifact id of a listener the ss fixture
// reported, so a reader can follow one to the other.
func TestPublishedPortsCrossReferenceTheListeners(t *testing.T) {
	listeners, _ := ParseSSListeners(netFixture(t, "network.listeners/ss-H-lntup.txt"))
	ids := map[string]bool{}
	for _, l := range listeners {
		ids[l.ArtifactID()] = true
	}
	containers, _ := ParseDockerPS(netFixture(t, "containers/docker-ps.txt"))
	total := 0
	for i := range containers {
		containers[i].Runtime = ContainerRuntimeDocker
		got, skipped := containers[i].ListenerIDs()
		if len(skipped) != 0 {
			t.Errorf("%s: skipped port ranges %v", containers[i].Name(), skipped)
		}
		for _, id := range got {
			total++
			if !ids[id] {
				t.Errorf("%s publishes %s, which is not among the listeners of the same host", containers[i].Name(), id)
			}
		}
	}
	if total != 35 {
		t.Errorf("got %d published listener ids, want 35", total)
	}
}

func TestParseDockerInfo(t *testing.T) {
	info, err := ParseDockerInfo(netFixture(t, "containers/docker-info.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.ServerVersion != "27.5.1" || info.StorageDriver != "overlay2" ||
		info.OperatingSystem != "Ubuntu 24.04.1 LTS" || info.KernelVersion != "6.17.0-35-generic" ||
		info.Architecture != "x86_64" || info.RootDir != "/var/lib/docker" {
		t.Errorf("info %+v", info)
	}
	if info.Containers != "32" || info.ContainersRunning != "20" || info.Images != "66" {
		t.Errorf("counters %+v", info)
	}
	for _, bad := range [][]byte{nil, []byte("one\ttwo\n")} {
		if _, err := ParseDockerInfo(bad); !errors.Is(err, ErrRuntimeInfo) {
			t.Errorf("ParseDockerInfo(%q) error = %v", string(bad), err)
		}
	}
}

func TestParseDockerInspect(t *testing.T) {
	configs, diags := ParseDockerInspect([]byte("abc\tunless-stopped\tfalse\ndef\talways\ttrue\nbroken\n"))
	if len(diags) != 1 || diags[0].Code != netDiagRecordUnparsed {
		t.Errorf("diagnostics %v", diags)
	}
	if c := configs["abc"]; c.RestartPolicy != "unless-stopped" || c.Privileged {
		t.Errorf("abc %+v", c)
	}
	if c := configs["def"]; c.RestartPolicy != "always" || !c.Privileged {
		t.Errorf("def %+v", c)
	}
}

// The full path against the fixtures: runtime and containers recorded,
// published ports carried as listener ids, the declared restart policy and
// the privileged flag from the inspect call, and no volatile uptime text in
// any artifact.
func TestContainersProbeCollectsTheFixtures(t *testing.T) {
	cc, ev := netTestCollect(ContainersProbeID, netDockerRunner(t))
	res := NewContainersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q, warnings %v)", res.Status, res.Reason, res.Warnings)
	}
	if len(res.NormalizedState) != 21 {
		t.Fatalf("got %d artifacts, want 20 containers plus the runtime", len(res.NormalizedState))
	}
	rt := netArtifact(t, res, "container/runtime/docker")
	for k, want := range map[string]string{
		"runtime":         ContainerRuntimeDocker,
		"server_version":  "27.5.1",
		"storage_driver":  "overlay2",
		"architecture":    "x86_64",
		"root_dir":        "/var/lib/docker",
		"container_count": "20",
		"client_version":  "Docker version 27.5.1, build 9f9e405",
	} {
		if rt.Attributes[k] != want {
			t.Errorf("runtime %s = %q, want %q", k, rt.Attributes[k], want)
		}
	}
	// The host name of the info line is not repeated here: it lives in the
	// identity artifacts, with the sensitivity that belongs to it.
	for _, k := range []string{"node_name", "name", "containers", "images"} {
		if _, ok := rt.Attributes[k]; ok {
			t.Errorf("runtime artifact carries %q: %v", k, rt.Attributes)
		}
	}

	edge := netArtifact(t, res, "container/docker/app-edge-supervisor")
	if edge.Attributes["published_ports"] != "0.0.0.0:9113->9113/tcp,[::]:9113->9113/tcp" {
		t.Errorf("published ports %q", edge.Attributes["published_ports"])
	}
	if edge.Attributes["published_listener_ids"] != "network/listener/tcp/0.0.0.0/9113,network/listener/tcp/[::]/9113" {
		t.Errorf("published listener ids %q", edge.Attributes["published_listener_ids"])
	}
	if edge.Attributes["exposure"] != ExposureAnyAddress || edge.Attributes["container_state"] != "running" {
		t.Errorf("edge attributes %v", edge.Attributes)
	}
	if edge.Attributes["declared_restart_policy"] != "unless-stopped" || edge.Attributes["declared_privileged"] != "false" {
		t.Errorf("declared configuration %v", edge.Attributes)
	}
	kind := netArtifact(t, res, "container/docker/example-control-plane")
	if kind.Attributes["declared_privileged"] != "true" {
		t.Errorf("the privileged container is not marked: %v", kind.Attributes)
	}
	if !strings.HasPrefix(kind.Attributes["image_digest"], "sha256:") {
		t.Errorf("image digest %q", kind.Attributes["image_digest"])
	}
	writer := netArtifact(t, res, "container/docker/app-sim-writer")
	if writer.Attributes["exposure"] != ExposureNone || writer.Attributes["published_ports"] != "" {
		t.Errorf("a container without published ports: %v", writer.Attributes)
	}
	for _, a := range res.NormalizedState {
		for k, v := range a.Attributes {
			if strings.Contains(v, "Up 2 weeks") || strings.Contains(v, "Up 3 weeks") {
				t.Errorf("%s carries the volatile status column in %s: %q", a.ID, k, v)
			}
		}
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			t.Errorf("artifact id %q: %v", a.ID, err)
		}
	}
	if names := netEvidenceNames(ev); len(names) != 4 {
		t.Errorf("evidence files %v, want version, info, ps and inspect", names)
	}
}

// Runtime present, nothing running: captured with an empty list, and the
// runtime artifact says the count is zero.
func TestContainersProbeEmptyListingIsCaptured(t *testing.T) {
	spec := containerRuntimeSpecs()[0]
	runner := probe.NewFakeRunner().AddTool(ContainerRuntimeDocker, "/usr/bin/docker").
		Script(ContainerRuntimeDocker, spec.versionArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-version.txt")}).
		Script(ContainerRuntimeDocker, spec.infoArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-info.txt")}).
		Script(ContainerRuntimeDocker, spec.psArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-ps-empty.txt")})
	cc, _ := netTestCollect(ContainersProbeID, runner)
	res := NewContainersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q)", res.Status, res.Reason)
	}
	if len(res.NormalizedState) != 1 {
		t.Fatalf("artifacts %v", netArtifactIDs(res))
	}
	if got := netArtifact(t, res, "container/runtime/docker").Attributes["container_count"]; got != "0" {
		t.Errorf("container_count %q, want 0", got)
	}
}

// Client present, daemon not reachable: that is a failure, and it must not
// be reported as a refusal or as an empty host.
func TestContainersProbeDaemonUnreachableIsFailed(t *testing.T) {
	spec := containerRuntimeSpecs()[0]
	stderr := netFixture(t, "containers/docker-daemon-unreachable.stderr.txt")
	runner := probe.NewFakeRunner().AddTool(ContainerRuntimeDocker, "/usr/bin/docker").
		Script(ContainerRuntimeDocker, spec.versionArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-version.txt")}).
		Script(ContainerRuntimeDocker, spec.infoArgs, probe.FakeResponse{Stderr: stderr, ExitCode: 1}).
		Script(ContainerRuntimeDocker, spec.psArgs, probe.FakeResponse{Stderr: stderr, ExitCode: 1})
	cc, _ := netTestCollect(ContainersProbeID, runner)
	res := NewContainersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusFailed {
		t.Fatalf("status %q, want failed (reason %q)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "Cannot connect to the Docker daemon") {
		t.Errorf("reason %q does not carry what the client printed", res.Reason)
	}
	rt := netArtifact(t, res, "container/runtime/docker")
	if rt.State != trustfreeze.StateUnknown || rt.Attributes["container_count"] != "" {
		t.Errorf("a runtime that did not answer must not claim a container count: %v", rt.Attributes)
	}
}

// Constructed shape, stated as such: a socket the caller may not open. The
// trial host could not produce it, because the capturing account is in the
// docker group. The classification is by the refusal wording, not by an
// exact message.
func TestContainersProbeRefusedSocketIsPermissionDenied(t *testing.T) {
	spec := containerRuntimeSpecs()[0]
	stderr := []byte("permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock\n")
	runner := probe.NewFakeRunner().AddTool(ContainerRuntimeDocker, "/usr/bin/docker").
		Script(ContainerRuntimeDocker, spec.versionArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-version.txt")}).
		Script(ContainerRuntimeDocker, spec.infoArgs, probe.FakeResponse{Stderr: stderr, ExitCode: 1}).
		Script(ContainerRuntimeDocker, spec.psArgs, probe.FakeResponse{Stderr: stderr, ExitCode: 1})
	cc, _ := netTestCollect(ContainersProbeID, runner)
	res := NewContainersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q, want permission_denied (reason %q)", res.Status, res.Reason)
	}
	if res.Error == nil || res.Error.Class != probe.ClassPermissionDenied {
		t.Errorf("error %+v", res.Error)
	}
}

// The container list stands even when the inspect call does not answer; the
// two declared attributes are then absent and the result is partial.
func TestContainersProbeWithoutInspectIsPartial(t *testing.T) {
	spec := containerRuntimeSpecs()[0]
	inspect := append(append([]string{}, spec.inspectArgs...), netDockerPSIDs(t)...)
	runner := netDockerRunner(t).
		Script(ContainerRuntimeDocker, inspect, probe.FakeResponse{
			Stderr: []byte("Error response from daemon: the call was refused\n"), ExitCode: 1,
		})
	cc, _ := netTestCollect(ContainersProbeID, runner)
	res := NewContainersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	edge := netArtifact(t, res, "container/docker/app-edge-supervisor")
	for _, k := range []string{"declared_restart_policy", "declared_privileged"} {
		if _, ok := edge.Attributes[k]; ok {
			t.Errorf("attribute %q was recorded although the inspect call failed", k)
		}
	}
	if edge.Attributes["published_ports"] == "" {
		t.Errorf("the container list must survive a failed inspect call")
	}
}

// No runtime binary at all: not_applicable with a reason, in Support and in
// Collect, and no artifact.
func TestContainersProbeWithoutRuntime(t *testing.T) {
	runner := probe.NewFakeRunner()
	p := NewContainersProbe()
	sup := p.Support(context.Background(), netTestHost(runner))
	if sup.Available || sup.Status != trustfreeze.StatusNotApplicable || sup.Reason == "" {
		t.Fatalf("support %+v, want not_applicable with a reason", sup)
	}
	cc, _ := netTestCollect(ContainersProbeID, runner)
	res := p.Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusNotApplicable || res.Reason == "" {
		t.Fatalf("status %q reason %q", res.Status, res.Reason)
	}
	if len(res.NormalizedState) != 0 {
		t.Errorf("artifacts without a runtime: %v", netArtifactIDs(res))
	}
}

// podman is not installed on the trial host, so its absence is what the
// fixture set proves: the docker path runs and nothing claims a podman
// runtime.
func TestContainersProbeIgnoresAnAbsentPodman(t *testing.T) {
	cc, _ := netTestCollect(ContainersProbeID, netDockerRunner(t))
	res := NewContainersProbe().Collect(context.Background(), cc)
	for _, a := range res.NormalizedState {
		if strings.Contains(a.ID, ContainerRuntimePodman) {
			t.Errorf("artifact for an absent runtime: %s", a.ID)
		}
	}
}

func TestContainersProbeDescriptor(t *testing.T) {
	p := NewContainersProbe()
	if err := p.Descriptor().Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if got := p.RequiredTools(); len(got) != 2 || got[0] != "docker" || got[1] != "podman" {
		t.Errorf("required tools %v", got)
	}
	host := netTestHost(netDockerRunner(t))
	host.GOOS = "windows"
	if sup := p.Support(context.Background(), host); sup.Available || sup.Status != trustfreeze.StatusUnsupported {
		t.Errorf("support on another platform: %+v", sup)
	}
}
