package linux

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// linux.containers reports the container runtimes of the host and the
// containers they run (SPEC-0471 TF06-R3). Every call uses an explicit
// format, never the human table, so the parser does not depend on column
// widths or on the words of a locale.
//
// Honest states (SPEC-0471 TF06-R2). No runtime binary in the directories
// the runner searches: unavailable, with a reason that names those
// directories, because not finding a binary is a statement about this
// capture and not about the host (playbook L1). An earlier version answered
// not_applicable with the words "no container runtime on this host", and a
// bastion measured on 2026-09-23 showed what that costs: docker 29.8.0
// answered at /snap/bin/docker, the probe did not look there, and the bundle
// said the host had no container runtime.
// Binary present but the daemon socket refuses the caller:
// permission_denied, carrying what the client printed. Binary present and
// the daemon is not reachable at all: failed, which is a different fact from
// a refusal and must not be reported as one. Runtime present and no
// container running: captured with an empty list, stated explicitly in the
// runtime artifact.
//
// not_applicable is not reachable in this probe. A Linux host can always run
// a container runtime, so its absence is never a property of the platform.
//
// Published ports are exposure, and they are recorded so that they can be
// read together with the listener artifacts: every published host port
// yields the id of the listening socket it must appear as, built with
// ListenerArtifactID, so a container port published on 0.0.0.0 and the
// matching entry of "ss -H -lntup" carry the same artifact id.
//
// An image reference can name an internal registry, and the host name of
// the info line is not repeated here at all, because the identity probe
// already records it with the sensitivity that belongs to it. The container
// artifacts are therefore internal, and the listing is kept as evidence
// because it is the source of exactly those artifacts.
//
// Two limits of this version, stated rather than hidden. The restart policy
// and the privileged flag are not in the output of "docker ps": they come
// from an extra "inspect" call, and a host that refuses that call keeps the
// container artifacts without those two attributes plus a diagnostic. And
// the podman path collects the container list and the client version only,
// because the fields of "podman info" differ from the docker ones and this
// build has no measured podman output to write a template against.
const (
	// ContainersProbeID is the probe id of the container probe.
	ContainersProbeID = "linux.containers"
	// ContainersProbeVersion changes whenever the output of the probe can
	// change.
	ContainersProbeVersion = "1"
	// ContainerRuntimeDocker and ContainerRuntimePodman are the runtimes the
	// probe knows, in the order it tries them.
	ContainerRuntimeDocker = "docker"
	ContainerRuntimePodman = "podman"
)

// Artifact ids of the container probe: one per runtime and one per running
// container.
const (
	ArtifactContainerRuntimePrefix = "container/runtime"
	ArtifactContainerPrefix        = "container"
	artifactTypeContainer          = "container"
	// containerAttrDeclaredPrivileged and containerAttrDeclaredRestartPolicy
	// are written only when the inspect call answered for that container. The
	// capability resolver reads the first one, so both live here as names
	// rather than as literals in two files.
	containerAttrDeclaredPrivileged    = "declared_privileged"
	containerAttrDeclaredRestartPolicy = "declared_restart_policy"
	// containerAttrExecutablePath holds the absolute path the runtime client
	// resolved to, so a bundle says which installation answered: a snap at
	// /snap/bin/docker is a different one from the distribution package at
	// /usr/bin/docker.
	containerAttrExecutablePath  = "executable_path"
	artifactTypeContainerRuntime = "container-runtime"
)

// Format templates. "docker ps" expands a literal backslash t into a tab and
// "docker info" does not, so the separator of the info template is written
// as a template string literal, which both accept. The ps template is the
// one the fixtures were taken with.
const (
	dockerPSFormat      = `{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Ports}}`
	dockerInfoFormat    = `{{.ServerVersion}}{{"\t"}}{{.Driver}}{{"\t"}}{{.OperatingSystem}}{{"\t"}}{{.KernelVersion}}{{"\t"}}{{.Architecture}}{{"\t"}}{{.Containers}}{{"\t"}}{{.ContainersRunning}}{{"\t"}}{{.Images}}{{"\t"}}{{.DockerRootDir}}{{"\t"}}{{.Name}}`
	dockerInspectFormat = `{{.Id}}{{"\t"}}{{.HostConfig.RestartPolicy.Name}}{{"\t"}}{{.HostConfig.Privileged}}`
)

// containersMaxRecords bounds the container artifacts of one capture and
// containersMaxInspectBatch bounds one inspect call (playbook L6). A host
// with thousands of containers would otherwise put one argument per
// container into a single argument vector, which the kernel refuses with
// E2BIG; systemctl show is batched the same way (systemd.go).
const (
	containersMaxRecords      = 2048
	containersMaxInspectBatch = 40
)

// maxPublishedRangePorts bounds how far a published port range is expanded
// into listener ids. A wider range keeps its text and yields no ids.
const maxPublishedRangePorts = 32

// PublishedPort is one entry of the ports column. HostAddress is empty for a
// port that is only exposed by the image and not published on the host.
type PublishedPort struct {
	HostAddress   string
	HostPort      string
	ContainerPort string
	Proto         string
	// Exposure is the class of HostAddress, ExposureNone when the port is
	// not published on the host.
	Exposure string
}

// String renders the port the way it is persisted:
// "0.0.0.0:9113->9113/tcp" for a published port, "8080/tcp" for one that is
// only exposed. An IPv6 host address is written in brackets, whichever of
// the two spellings the runtime used.
func (p PublishedPort) String() string {
	if p.HostAddress == "" {
		return p.ContainerPort + "/" + p.Proto
	}
	return listenerAddressSegment(p.HostAddress, "") + ":" + p.HostPort + "->" + p.ContainerPort + "/" + p.Proto
}

// Container is one container as the runtime listed it.
type Container struct {
	Runtime string
	ID      string
	Image   string
	// ImageDigest is the digest an image reference was pinned to, empty when
	// the reference carries only a tag.
	ImageDigest string
	Names       []string
	State       string
	// Status is the human status column ("Up 2 weeks (healthy)"). It carries
	// the uptime, which is volatile, so it is parsed but not persisted.
	Status string
	Ports  []PublishedPort
	// RestartPolicy and Privileged come from the inspect call; Inspected
	// says whether that call answered for this container.
	RestartPolicy string
	Privileged    bool
	Inspected     bool
}

// Name returns the first name of the container, or its id when it has none.
func (c Container) Name() string {
	if len(c.Names) > 0 && c.Names[0] != "" {
		return c.Names[0]
	}
	return c.ID
}

// ArtifactID returns "container/<runtime>/<name>".
func (c Container) ArtifactID() string {
	return ArtifactContainerPrefix + "/" + c.Runtime + "/" + c.Name()
}

// Exposure returns the widest exposure of the published ports of the
// container, ExposureNone when it publishes nothing on the host.
func (c Container) Exposure() string {
	out := ExposureNone
	for _, p := range c.Ports {
		if netExposureRank(p.Exposure) > netExposureRank(out) {
			out = p.Exposure
		}
	}
	return out
}

// ListenerIDs returns the artifact ids of the listening sockets the
// published ports of the container must appear as, sorted and unique. A
// published port range wider than maxPublishedRangePorts yields no id; the
// second return value names such an entry.
func (c Container) ListenerIDs() ([]string, []string) {
	seen := map[string]bool{}
	var (
		out     []string
		skipped []string
	)
	for _, p := range c.Ports {
		if p.HostAddress == "" || p.HostPort == "" {
			continue
		}
		ports, ok := expandPortRange(p.HostPort)
		if !ok {
			skipped = append(skipped, p.String())
			continue
		}
		for _, port := range ports {
			id := ListenerArtifactID(p.Proto, p.HostAddress, "", port)
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	sort.Strings(skipped)
	return out, skipped
}

// expandPortRange turns "9113" into one port and "8000-8002" into three. A
// range wider than maxPublishedRangePorts or a token that is not numeric
// yields ok false.
func expandPortRange(token string) ([]string, bool) {
	lo, hi, isRange := strings.Cut(token, "-")
	first, err := strconv.Atoi(lo)
	if err != nil || first < 0 {
		return nil, false
	}
	if !isRange {
		return []string{lo}, true
	}
	last, err := strconv.Atoi(hi)
	if err != nil || last < first || last-first+1 > maxPublishedRangePorts {
		return nil, false
	}
	out := make([]string, 0, last-first+1)
	for p := first; p <= last; p++ {
		out = append(out, strconv.Itoa(p))
	}
	return out, true
}

// netExposureRank orders the exposure classes from the narrowest to the
// widest, so that the exposure of a container is the widest of its ports.
func netExposureRank(e string) int {
	switch e {
	case ExposureLoopback:
		return 1
	case ExposureLinkLocal:
		return 2
	case ExposureSpecificAddress:
		return 3
	case ExposureAnyAddress:
		return 4
	case ExposureUnknown:
		return 5
	}
	return 0
}

// ParsePublishedPorts reads the ports column of a container listing:
// entries separated by commas, each either "<address>:<port>-><port>/<proto>"
// for a published port or "<port>/<proto>" for one that is only exposed. The
// address may be an IPv4 address, "[::]" or the bare "::" the runtime prints
// as ":::9113". It is pure.
func ParsePublishedPorts(s string) ([]PublishedPort, []trustfreeze.Diagnostic) {
	var (
		out   []PublishedPort
		diags []trustfreeze.Diagnostic
	)
	for _, raw := range strings.Split(s, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		hostPart, portPart, published := strings.Cut(entry, "->")
		if !published {
			portPart = hostPart
			hostPart = ""
		}
		containerPort, proto, ok := strings.Cut(strings.TrimSpace(portPart), "/")
		if !ok || containerPort == "" || proto == "" {
			diags = append(diags, trustfreeze.Diagnostic{
				Code: netDiagRecordUnparsed, Field: "published_port",
				Message: "port entry " + strconv.Quote(entry) + " has no protocol",
			})
			continue
		}
		p := PublishedPort{ContainerPort: containerPort, Proto: proto, Exposure: ExposureNone}
		if published {
			addr, hostPort, ok := splitLocalEndpoint(strings.TrimSpace(hostPart))
			if !ok {
				diags = append(diags, trustfreeze.Diagnostic{
					Code: netDiagRecordUnparsed, Field: "published_port",
					Message: "port entry " + strconv.Quote(entry) + " has no host port",
				})
				continue
			}
			p.HostAddress, _ = splitAddressZone(addr)
			p.HostPort = hostPort
			p.Exposure = ClassifyExposure(addr)
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, diags
}

// ErrContainerRecord is returned for a listing line that has the wrong
// number of fields.
var ErrContainerRecord = errors.New("linux: unreadable container record")

// ParseDockerPS reads the output of the container listing with the format
// template of this package: six tab separated fields per line (id, image,
// names, state, status, ports). It is pure and reports one diagnostic per
// line it could not read.
func ParseDockerPS(b []byte) ([]Container, []trustfreeze.Diagnostic) {
	var (
		out   []Container
		diags []trustfreeze.Diagnostic
	)
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			diags = append(diags, trustfreeze.Diagnostic{
				Code: netDiagRecordUnparsed, Field: "container",
				Message: fmt.Sprintf("line %d: %d fields, 6 expected", i+1, len(fields)),
			})
			continue
		}
		c := Container{
			ID:     strings.TrimSpace(fields[0]),
			Image:  strings.TrimSpace(fields[1]),
			State:  strings.TrimSpace(fields[3]),
			Status: strings.TrimSpace(fields[4]),
		}
		if _, digest, ok := strings.Cut(c.Image, "@"); ok {
			c.ImageDigest = digest
		}
		for _, n := range strings.Split(fields[2], ",") {
			if n = strings.TrimSpace(n); n != "" {
				c.Names = append(c.Names, n)
			}
		}
		ports, pdiags := ParsePublishedPorts(fields[5])
		c.Ports = ports
		for _, d := range pdiags {
			d.Message = fmt.Sprintf("line %d: %s", i+1, d.Message)
			diags = append(diags, d)
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, diags
}

// ContainerRuntimeInfo is what the info call reports. The three counters are
// parsed but not persisted: two of them count objects this probe does not
// enumerate (images and stopped containers), so a change in them could not
// be explained by any artifact, and the third repeats the container
// artifacts. NodeName is the host name, which already lives in the identity
// artifacts, and is not persisted either.
type ContainerRuntimeInfo struct {
	ServerVersion     string
	StorageDriver     string
	OperatingSystem   string
	KernelVersion     string
	Architecture      string
	Containers        string
	ContainersRunning string
	Images            string
	RootDir           string
	NodeName          string
}

// ErrRuntimeInfo is returned by ParseDockerInfo for output that does not
// have the field count of the info template.
var ErrRuntimeInfo = errors.New("linux: unreadable container runtime info")

// ParseDockerInfo reads the single line the info template produces: ten tab
// separated fields. It is pure.
func ParseDockerInfo(b []byte) (ContainerRuntimeInfo, error) {
	line := netFirstLine(b)
	if line == "" {
		return ContainerRuntimeInfo{}, fmt.Errorf("%w: no output", ErrRuntimeInfo)
	}
	f := strings.Split(line, "\t")
	if len(f) != 10 {
		return ContainerRuntimeInfo{}, fmt.Errorf("%w: %d fields, 10 expected", ErrRuntimeInfo, len(f))
	}
	return ContainerRuntimeInfo{
		ServerVersion:     strings.TrimSpace(f[0]),
		StorageDriver:     strings.TrimSpace(f[1]),
		OperatingSystem:   strings.TrimSpace(f[2]),
		KernelVersion:     strings.TrimSpace(f[3]),
		Architecture:      strings.TrimSpace(f[4]),
		Containers:        strings.TrimSpace(f[5]),
		ContainersRunning: strings.TrimSpace(f[6]),
		Images:            strings.TrimSpace(f[7]),
		RootDir:           strings.TrimSpace(f[8]),
		NodeName:          strings.TrimSpace(f[9]),
	}, nil
}

// ContainerConfig is the part of an inspect answer this probe keeps: the
// declared restart policy and whether the container runs privileged.
type ContainerConfig struct {
	ID            string
	RestartPolicy string
	Privileged    bool
}

// ParseDockerInspect reads the output of the inspect call with the format
// template of this package: three tab separated fields per line (id,
// restart policy name, privileged). It is pure and returns the entries by
// container id.
func ParseDockerInspect(b []byte) (map[string]ContainerConfig, []trustfreeze.Diagnostic) {
	out := map[string]ContainerConfig{}
	var diags []trustfreeze.Diagnostic
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			diags = append(diags, trustfreeze.Diagnostic{
				Code: netDiagRecordUnparsed, Field: "container_config",
				Message: fmt.Sprintf("line %d: %d fields, 3 expected", i+1, len(f)),
			})
			continue
		}
		id := strings.TrimSpace(f[0])
		priv, err := strconv.ParseBool(strings.TrimSpace(f[2]))
		if id == "" || err != nil {
			diags = append(diags, trustfreeze.Diagnostic{
				Code: netDiagRecordUnparsed, Field: "container_config",
				Message: fmt.Sprintf("line %d: id or privileged flag could not be read", i+1),
			})
			continue
		}
		out[id] = ContainerConfig{ID: id, RestartPolicy: strings.TrimSpace(f[1]), Privileged: priv}
	}
	return out, diags
}

// containerRuntimeSpec is one runtime and the calls this build knows for it.
// infoArgs is nil for a runtime whose info fields this build has not
// measured; the probe then records the client version and the containers
// only, instead of guessing a template.
type containerRuntimeSpec struct {
	name        string
	versionArgs []string
	infoArgs    []string
	psArgs      []string
	inspectArgs []string
}

func containerRuntimeSpecs() []containerRuntimeSpec {
	return []containerRuntimeSpec{
		{
			name:        ContainerRuntimeDocker,
			versionArgs: []string{"--version"},
			infoArgs:    []string{"info", "--format", dockerInfoFormat},
			psArgs:      []string{"ps", "--no-trunc", "--format", dockerPSFormat},
			inspectArgs: []string{"inspect", "--format", dockerInspectFormat},
		},
		{
			name:        ContainerRuntimePodman,
			versionArgs: []string{"--version"},
			psArgs:      []string{"ps", "--no-trunc", "--format", dockerPSFormat},
			inspectArgs: []string{"inspect", "--format", dockerInspectFormat},
		},
	}
}

// ContainersProbe collects the container runtimes of a Linux host.
type ContainersProbe struct{}

// NewContainersProbe returns the probe.
func NewContainersProbe() *ContainersProbe { return &ContainersProbe{} }

// Descriptor implements probe.Probe.
func (p *ContainersProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                ContainersProbeID,
		Version:           ContainersProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    30 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactContainerPrefix, ArtifactContainerRuntimePrefix},
	}
}

// RequiredTools implements the optional tool interface of the capture
// package.
func (p *ContainersProbe) RequiredTools() []string {
	return []string{ContainerRuntimeDocker, ContainerRuntimePodman}
}

// EvidenceClaims implements probe.EvidenceClaimer.
func (p *ContainersProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe. Neither runtime binary in the searched
// directories is unavailable, never not_applicable: the probe knows where it
// looked, not what the host has.
func (p *ContainersProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("this build reads Linux container runtimes only, not " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if len(netPresentTools(host, ContainerRuntimeDocker, ContainerRuntimePodman)) == 0 {
		return probe.Unavailable(containerRuntimeMissingReason(host.Runner))
	}
	return probe.Supported()
}

// containerRuntimeMissingReason says what was looked for and where it was
// looked for. Whether a runtime is installed somewhere else is not settled
// by this capture, and the sentence must not settle it either.
func containerRuntimeMissingReason(runner probe.CommandRunner) string {
	return "neither " + ContainerRuntimeDocker + " nor " + ContainerRuntimePodman + " was found " +
		netSearchedDirsPhrase(runner) +
		": whether a container runtime is installed elsewhere on this host is not established by this capture"
}

// runtimeOutcome is what one runtime contributed to the result.
type runtimeOutcome struct {
	listed   bool
	statuses []trustfreeze.ProbeStatus
	reasons  []string
}

// Collect implements probe.Probe.
func (p *ContainersProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	s := newNetProbeState(ctx, cc)
	res := s.base(ContainersProbeID, ContainersProbeVersion, start)
	observed := trustfreeze.FormatTime(start)

	present := map[string]bool{}
	for _, n := range netPresentTools(cc.HostContext, ContainerRuntimeDocker, ContainerRuntimePodman) {
		present[n] = true
	}
	if len(present) == 0 {
		res.Status = trustfreeze.StatusUnavailable
		res.Reason = containerRuntimeMissingReason(cc.Runner)
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassToolMissing, Message: res.Reason}
		s.warn(probe.DiagFieldUnavailable, "runtime", res.Reason)
		return s.finish(res, nil, start)
	}

	var (
		arts     []trustfreeze.Artifact
		outcome  runtimeOutcome
		anyParse bool
	)
	for _, spec := range containerRuntimeSpecs() {
		if !present[spec.name] {
			continue
		}
		a, o, parsed := p.collectRuntime(s, spec, observed)
		arts = append(arts, a...)
		outcome.listed = outcome.listed || o.listed
		outcome.statuses = append(outcome.statuses, o.statuses...)
		outcome.reasons = append(outcome.reasons, o.reasons...)
		anyParse = anyParse || parsed
	}

	res.Status, res.Reason = containerStatus(outcome, anyParse)
	switch res.Status {
	case trustfreeze.StatusPermissionDenied:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassPermissionDenied, Message: res.Reason}
	case trustfreeze.StatusFailed:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTerminated, Message: res.Reason}
	case trustfreeze.StatusTimeout:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTimeout, Message: res.Reason}
	}
	return s.finish(res, arts, start)
}

// containerStatus folds the per runtime outcomes into the probe status. A
// runtime that listed its containers makes the probe captured; every other
// failure lowers it to partial. Without a single listing the probe reports
// the strongest cause it saw, so a refused socket never reads as an empty
// host.
func containerStatus(o runtimeOutcome, parseIssue bool) (trustfreeze.ProbeStatus, string) {
	reason := strings.Join(o.reasons, "; ")
	if o.listed {
		if len(o.reasons) > 0 || parseIssue {
			return trustfreeze.StatusPartial, reason
		}
		return trustfreeze.StatusCaptured, ""
	}
	for _, want := range []trustfreeze.ProbeStatus{
		trustfreeze.StatusPermissionDenied, trustfreeze.StatusTimeout, trustfreeze.StatusUnavailable,
	} {
		for _, st := range o.statuses {
			if st == want {
				return want, reason
			}
		}
	}
	if reason == "" {
		reason = "no container runtime answered"
	}
	return trustfreeze.StatusFailed, reason
}

// collectRuntime runs the calls of one runtime and builds its artifacts.
func (p *ContainersProbe) collectRuntime(s *netProbeState, spec containerRuntimeSpec, observed string) ([]trustfreeze.Artifact, runtimeOutcome, bool) {
	var (
		out        runtimeOutcome
		arts       []trustfreeze.Artifact
		parseIssue bool
	)
	version := s.toolVersion(spec.name, spec.versionArgs, spec.name+"-version.stdout")

	runtimeAttrs := map[string]string{
		"runtime":        spec.name,
		"client_version": version,
	}
	// Which binary answered is part of the answer: /snap/bin/docker and
	// /usr/bin/docker are two installations with separate versions and
	// separate upgrade paths, and a capture that moved from one to the other
	// has to show it as a change rather than as the same runtime.
	if path, err := s.cc.Runner.LookPath(spec.name); err == nil {
		runtimeAttrs[containerAttrExecutablePath] = path
	} else {
		s.warn(netDiagCode(netCommandStatus(err)), containerAttrExecutablePath,
			spec.name+" answered, but its path could not be resolved: "+err.Error())
	}
	fail := func(field string, cmd netCmd, what string) {
		out.statuses = append(out.statuses, cmd.Status)
		out.reasons = append(out.reasons, spec.name+" "+what+": "+cmd.Detail)
		s.warn(netDiagCode(cmd.Status), field, spec.name+" "+what+": "+cmd.Detail)
		s.evidenceIfAny(spec.name+"-"+field+".stderr", "stderr:"+spec.name, cmd.Res.Stderr, cmd.Res.StderrTruncated)
	}

	if spec.infoArgs != nil {
		cmd := s.run(spec.name, spec.infoArgs)
		if cmd.Status != trustfreeze.StatusCaptured {
			fail("info", cmd, "info")
		} else {
			if r := s.truncationCheck(cmd, "info", "the runtime description is incomplete"); r != "" {
				out.reasons = append(out.reasons, spec.name+" info: "+r)
				out.statuses = append(out.statuses, trustfreeze.StatusPartial)
			}
			info, err := ParseDockerInfo(cmd.Res.Stdout.Bytes())
			if err != nil {
				parseIssue = true
				s.warn(netDiagRecordUnparsed, "info", spec.name+" info: "+err.Error())
			} else {
				s.evidence(spec.name+"-info.stdout", "stdout:"+spec.name, cmd.Res.Stdout, cmd.Res.StdoutTruncated)
				for k, v := range map[string]string{
					"server_version":   info.ServerVersion,
					"storage_driver":   info.StorageDriver,
					"operating_system": info.OperatingSystem,
					"kernel_version":   info.KernelVersion,
					"architecture":     info.Architecture,
					"root_dir":         info.RootDir,
				} {
					if v != "" {
						runtimeAttrs[k] = v
					}
				}
			}
		}
	} else {
		s.warn(probe.DiagFieldNotApplicable, "info",
			spec.name+" info is not collected: this build has no measured field set for that runtime")
	}

	cmd := s.run(spec.name, spec.psArgs)
	if cmd.Status != trustfreeze.StatusCaptured {
		fail("ps", cmd, "ps")
		runtimeAttrs["container_count"] = ""
		arts = append(arts, containerRuntimeArtifact(spec.name, runtimeAttrs, trustfreeze.StateUnknown, s.sourceList(), version, observed))
		return arts, out, parseIssue
	}
	s.evidence(spec.name+"-ps.stdout", "stdout:"+spec.name, cmd.Res.Stdout, cmd.Res.StdoutTruncated)
	// A cut listing is an incomplete listing: the containers beyond the cut
	// are not in the bundle, so the count below counts what was read (F2).
	listTruncated := s.truncationCheck(cmd, "container_list",
		"the containers beyond the cut are not in this bundle, and container_count counts what was read")
	if listTruncated != "" {
		out.reasons = append(out.reasons, spec.name+" ps: "+listTruncated)
		out.statuses = append(out.statuses, trustfreeze.StatusPartial)
	}
	containers, diags := ParseDockerPS(cmd.Res.Stdout.Bytes())
	if len(diags) > 0 {
		parseIssue = true
		s.warnings = append(s.warnings, diags...)
	}
	for i := range containers {
		containers[i].Runtime = spec.name
	}
	capped := false
	if len(containers) > containersMaxRecords {
		s.warn(netDiagVolumeCapped, "container",
			fmt.Sprintf("%s reported %d containers; only the first %d are recorded as artifacts",
				spec.name, len(containers), containersMaxRecords))
		out.reasons = append(out.reasons, fmt.Sprintf("%s: more than %d containers; the rest is not recorded", spec.name, containersMaxRecords))
		out.statuses = append(out.statuses, trustfreeze.StatusPartial)
		capped = true
		containers = containers[:containersMaxRecords]
	}
	out.listed = true
	out.statuses = append(out.statuses, trustfreeze.StatusCaptured)

	if len(containers) > 0 && spec.inspectArgs != nil {
		ids := make([]string, 0, len(containers))
		for _, c := range containers {
			if c.ID != "" {
				ids = append(ids, c.ID)
			}
		}
		sort.Strings(ids)
		configs := map[string]ContainerConfig{}
		// One call per batch, never one argument per container: an argument
		// vector grows with the host and the kernel refuses it at some size.
		for start := 0; start < len(ids); start += containersMaxInspectBatch {
			end := start + containersMaxInspectBatch
			if end > len(ids) {
				end = len(ids)
			}
			icmd := s.run(spec.name, append(append([]string{}, spec.inspectArgs...), ids[start:end]...))
			if icmd.Status != trustfreeze.StatusCaptured {
				// The container list stands; the two declared attributes do not.
				out.statuses = append(out.statuses, icmd.Status)
				out.reasons = append(out.reasons, spec.name+" inspect: "+icmd.Detail)
				s.warn(netDiagCode(icmd.Status), "container_config",
					spec.name+" inspect: "+icmd.Detail+"; restart policy and privileged flag were not read")
				continue
			}
			if r := s.truncationCheck(icmd, "container_config", "the restart policy and the privileged flag of the containers beyond the cut were not read"); r != "" {
				out.reasons = append(out.reasons, spec.name+" inspect: "+r)
				out.statuses = append(out.statuses, trustfreeze.StatusPartial)
			}
			batch, idiags := ParseDockerInspect(icmd.Res.Stdout.Bytes())
			if len(idiags) > 0 {
				parseIssue = true
				s.warnings = append(s.warnings, idiags...)
			}
			s.evidence(fmt.Sprintf("%s-inspect-%d.stdout", spec.name, start/containersMaxInspectBatch+1),
				"stdout:"+spec.name, icmd.Res.Stdout, icmd.Res.StdoutTruncated)
			for id, cfg := range batch {
				configs[id] = cfg
			}
		}
		for i := range containers {
			if cfg, ok := configs[containers[i].ID]; ok {
				containers[i].RestartPolicy = cfg.RestartPolicy
				containers[i].Privileged = cfg.Privileged
				containers[i].Inspected = true
			}
		}
	}

	prov := trustfreeze.Provenance{
		Method: "command", Confidence: trustfreeze.ConfidenceProven,
		Sources: s.sourceList(), ObservedAt: observed, ToolVersion: version,
	}
	seen := map[string]bool{}
	kept := 0
	for _, c := range containers {
		id := c.ArtifactID()
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			s.warn(probe.DiagArtifactDropped, "container", "container name is not a usable artifact id: "+err.Error())
			continue
		}
		if seen[id] {
			s.warn(probe.DiagArtifactDropped, "container", "two containers share the id "+id+"; the second was dropped")
			continue
		}
		seen[id] = true
		kept++
		arts = append(arts, containerArtifact(c, prov, s))
	}
	runtimeAttrs["container_count"] = strconv.Itoa(kept)
	if listTruncated != "" || capped {
		runtimeAttrs["container_list_truncated"] = privBool(true)
	}
	arts = append(arts, containerRuntimeArtifact(spec.name, runtimeAttrs, trustfreeze.StateObserved, s.sourceList(), version, observed))
	return arts, out, parseIssue
}

// containerRuntimeArtifact builds the artifact of one runtime.
func containerRuntimeArtifact(name string, attrs map[string]string, state trustfreeze.EvidenceState, sources []string, version, observed string) trustfreeze.Artifact {
	return trustfreeze.Artifact{
		ID: ArtifactContainerRuntimePrefix + "/" + name, Type: artifactTypeContainerRuntime,
		Scope: "device", Source: ContainersProbeID,
		State:      state,
		Attributes: attrs,
		Provenance: trustfreeze.Provenance{
			Method: "command", Confidence: trustfreeze.ConfidenceProven,
			Sources: sources, ObservedAt: observed, ToolVersion: version,
		},
		Sensitivity: trustfreeze.SensitivityInternal,
	}
}

// containerArtifact builds the artifact of one container. The container is
// observed; its restart policy and its privileged flag are declared
// configuration of that observed object, which is why they are named as
// such and only recorded when the inspect call answered.
func containerArtifact(c Container, prov trustfreeze.Provenance, s *netProbeState) trustfreeze.Artifact {
	ports := make([]string, 0, len(c.Ports))
	for _, p := range c.Ports {
		ports = append(ports, p.String())
	}
	listenerIDs, skipped := c.ListenerIDs()
	for _, sk := range skipped {
		s.warn(netDiagRecordUnparsed, "published_port",
			c.ArtifactID()+": the published port range "+sk+" is wider than this version expands into listener ids")
	}
	attrs := map[string]string{
		"runtime":         c.Runtime,
		"name":            c.Name(),
		"container_id":    c.ID,
		"image":           c.Image,
		"container_state": c.State,
		"exposure":        c.Exposure(),
		"published_ports": strings.Join(ports, ","),
	}
	if len(c.Names) > 1 {
		attrs["names"] = strings.Join(c.Names, ",")
	}
	if c.ImageDigest != "" {
		attrs["image_digest"] = c.ImageDigest
	}
	if len(listenerIDs) > 0 {
		attrs["published_listener_ids"] = strings.Join(listenerIDs, ",")
	}
	if c.Inspected {
		attrs[containerAttrDeclaredRestartPolicy] = c.RestartPolicy
		attrs[containerAttrDeclaredPrivileged] = strconv.FormatBool(c.Privileged)
	}
	return trustfreeze.Artifact{
		ID: c.ArtifactID(), Type: artifactTypeContainer, Scope: "device", Source: ContainersProbeID,
		State:       trustfreeze.StateObserved,
		Attributes:  attrs,
		Provenance:  prov,
		Sensitivity: trustfreeze.SensitivityInternal,
	}
}
