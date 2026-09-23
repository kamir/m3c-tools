package linux

// linux.systemd (SPEC-0471 TF06-R3) reports what the systemd SYSTEM manager
// knows about its units, in two layers that are never mixed:
//
//   - DECLARED: one artifact per unit file, from
//     "systemctl list-unit-files --no-legend --no-pager". A unit file on disk
//     declares that a unit may run and whether it is enabled; it says nothing
//     about the present. Enrichment for the selected units comes from
//     "systemctl show" properties that describe the unit file itself
//     (FragmentPath, DropInPaths, Type, ExecStart, User, Group, Restart).
//   - OBSERVED: one artifact per unit the probe asked systemd about, from the
//     runtime properties of the same "systemctl show" call (LoadState,
//     ActiveState, SubState, ConditionResult, NeedDaemonReload).
//
// Enabled and active are two different facts, so they are two attributes on
// two artifacts with two evidence states (playbook L3). A unit can be enabled
// and dead, or disabled and running.
//
// Scope: the system manager only. A "systemctl --user" manager exists per
// logged-in user, has its own unit files and its own runtime state, and is
// reachable only from inside that user's session. This probe never asks for
// it, and says so in the manager artifact and in a diagnostic rather than
// letting the absence read as "there is nothing there" (playbook L1).
//
// Volume: the trial host has 516 unit files (testdata/README.md). Every unit
// file becomes one small artifact; the "systemctl show" calls are limited to
// the units that carry trust weight, selected by SelectUnitsForShow, and the
// selection rule is recorded so a reader knows which units were never asked
// about.

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

// Probe and artifact identity.
const (
	// SystemdProbeID is the probe id.
	SystemdProbeID = "linux.systemd"
	// SystemdProbeVersion changes whenever the output of the probe can change.
	SystemdProbeVersion = "1"

	// ArtifactSystemdManager summarizes the manager that answered.
	ArtifactSystemdManager = "service/systemd/manager"
	// ArtifactSystemdUnitPrefix prefixes the declared artifact of one unit
	// file: the unit name follows, with the characters an artifact id may not
	// carry replaced (systemdUnitIDSuffix).
	ArtifactSystemdUnitPrefix = "service/systemd/unit/"
	// ArtifactSystemdRuntimePrefix prefixes the observed artifact of one unit.
	ArtifactSystemdRuntimePrefix = "service/systemd/runtime/"
)

// systemctlExe is the only executable this probe runs. It is never prefixed
// with an elevation helper (playbook L2); the runner refuses those anyway.
const systemctlExe = "systemctl"

// systemdShowProperties is the explicit property list of every
// "systemctl show" call, in the order testdata/commands.json recorded it.
// systemd answers in its own order, so the list is an input only.
//
// Description is asked for because the measured argv asks for it, and is
// deliberately not persisted: it is free text from the unit file and can name
// a person (playbook L4).
const systemdShowProperties = "Id,Description,LoadState,ActiveState,SubState,UnitFileState,UnitFilePreset,FragmentPath,DropInPaths,Type,ExecStart,User,Group,Restart,ConditionResult,NeedDaemonReload"

// Bounds of the "systemctl show" calls.
const (
	// systemdShowBatch is how many units one call asks about. Batching keeps
	// the number of processes small on a host with hundreds of units.
	systemdShowBatch = 40
	// systemdMaxShowUnits caps the selection, so a host with an unexpected
	// number of units cannot turn one probe into thousands of records. A cut
	// selection is reported, never silent.
	systemdMaxShowUnits = 512
	// systemdMaxIssueDiagnostics caps the per-record diagnostics; the rest is
	// summarized in one diagnostic.
	systemdMaxIssueDiagnostics = 20
)

// Attribute names of the systemd artifacts.
const (
	systemdAttrUnit            = "unit"
	systemdAttrUnitType        = "unit_type"
	systemdAttrEnabledState    = "enabled_state"
	systemdAttrPreset          = "preset"
	systemdAttrFragmentPath    = "fragment_path"
	systemdAttrDropInPaths     = "drop_in_paths"
	systemdAttrServiceType     = "service_type"
	systemdAttrExecStartPath   = "exec_start_path"
	systemdAttrExecStartCount  = "exec_start_count"
	systemdAttrUser            = "user"
	systemdAttrGroup           = "group"
	systemdAttrRestart         = "restart"
	systemdAttrLoadState       = "load_state"
	systemdAttrActiveState     = "active_state"
	systemdAttrSubState        = "sub_state"
	systemdAttrConditionResult = "condition_result"
	systemdAttrDaemonReload    = "need_daemon_reload"
	systemdAttrScope           = "scope"
	systemdAttrUserScope       = "user_scope"
	systemdAttrUnitFileCount   = "unit_file_count"
	systemdAttrObservedCount   = "observed_unit_count"
	systemdAttrSelectionRule   = "observed_selection"
	// systemdAttrTemplate marks a unit file that is a template, and
	// systemdAttrRuntimeState plus systemdAttrRuntimeReason say what that
	// means for its runtime state.
	systemdAttrTemplate      = "template"
	systemdAttrRuntimeState  = "runtime_state"
	systemdAttrRuntimeReason = "runtime_state_reason"
	// systemdAttrTemplateCount is the number of template unit files on the
	// manager artifact.
	systemdAttrTemplateCount = "template_unit_count"
)

// systemdRuntimeNotApplicable is the runtime_state of a template unit, and
// systemdTemplateReason is the reason that goes with it. This is the one
// legitimate not_applicable (playbook L1): the thing cannot exist, so there
// is nothing to observe and nothing to be blind about.
const (
	systemdRuntimeNotApplicable = "not_applicable"
	systemdTemplateReason       = "a template unit is a pattern from which systemd builds instances and has no instance of its own, so the manager holds no runtime state for it"
)

// Diagnostic codes this probe adds to the shared ones.
const (
	// DiagSystemdScopeNotCollected: a manager scope this probe does not ask
	// about. It is a statement about coverage, not a failure.
	DiagSystemdScopeNotCollected = "scope_not_collected"
	// DiagSystemdExitCode: a systemctl call ended with a non-zero exit code.
	// The exit code alone decides nothing (testdata/README.md: a list call
	// answers an empty match with exit 1).
	DiagSystemdExitCode = "tool_exit_code"
	// DiagSystemdUnreadRecord: one output record could not be read.
	DiagSystemdUnreadRecord = "record_not_read"
	// DiagSystemdToolVersionUnknown: the tool version could not be read. An
	// unknown version is a diagnostic, never a guess (playbook L7).
	DiagSystemdToolVersionUnknown = "tool_version_unknown"
	// DiagSystemdUnitNotFound: a unit selected from the unit file list came
	// back from "systemctl show" with LoadState=not-found.
	DiagSystemdUnitNotFound = "unit_not_found"
	// DiagSystemdStateMismatch: the unit file state in the list call and in
	// the show call differ.
	DiagSystemdStateMismatch = "unit_file_state_mismatch"
	// DiagSystemdSelectionTruncated: the show selection hit its cap.
	DiagSystemdSelectionTruncated = "selection_truncated"
	// DiagSystemdTemplateUnit: unit files that are templates were not asked
	// about, because a template has no runtime state to ask for.
	DiagSystemdTemplateUnit = "template_unit_not_queried"
	// DiagSystemdBatchSplit: a "systemctl show" call for several units ended
	// without answering for all of them, and the names it left out were
	// asked for one at a time.
	DiagSystemdBatchSplit = "show_batch_split"
	// DiagSystemdUnitStateNotRead: the manager returned no properties for
	// one unit, so its runtime state stays unknown.
	DiagSystemdUnitStateNotRead = "unit_state_not_read"
)

// systemdUserScopeNotCollected is the value of the user_scope attribute and
// the reason of DiagSystemdScopeNotCollected.
const systemdUserScopeNotCollected = "not_collected"

// systemdSelectionRule names the rule SelectUnitsForShow applies, so a reader
// of the bundle knows which units were never asked about.
const systemdSelectionRule = "timers and sockets, plus enabled service, mount, path and automount units; never alias, masked, transient or template units"

// SystemdProbe implements probe.Probe for linux.systemd.
type SystemdProbe struct{}

// NewSystemdProbe returns the probe.
func NewSystemdProbe() *SystemdProbe { return &SystemdProbe{} }

// Descriptor implements probe.Probe.
func (p *SystemdProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                SystemdProbeID,
		Version:           SystemdProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    60 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides: []string{
			ArtifactSystemdManager,
			ArtifactSystemdRuntimePrefix,
			ArtifactSystemdUnitPrefix,
		},
	}
}

// EvidenceClaims implements probe.EvidenceClaimer: every parser is covered by
// fixture tests that run on any host, and the package compiles for linux.
// Whether the probe ran on a real Linux host is not decided in code
// (SPEC-0471 TF06-R7).
func (p *SystemdProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// RequiredTools names the executables this probe runs, for the doctor check
// that resolves them before a capture (capture.ToolUser).
func (p *SystemdProbe) RequiredTools() []string { return []string{systemctlExe} }

// Support implements probe.Probe. It only checks availability: it resolves
// systemctl through LookPath and never starts it.
//
// A Linux system without systemd has no systemctl, which is a missing tool
// and therefore unavailable (playbook L1). The probe cannot tell that apart
// from a systemctl outside the runner search path, so it does not claim
// not_applicable, which would be a statement about the host.
func (p *SystemdProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("linux.systemd has no source on " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if _, err := host.Runner.LookPath(systemctlExe); err != nil {
		switch {
		case errors.Is(err, probe.ErrPermissionDenied):
			return probe.PermissionDenied("systemctl is not executable: " + err.Error())
		case errors.Is(err, probe.ErrToolMissing):
			return probe.Unavailable("systemctl not found in the runner search path")
		}
		return probe.Unavailable("systemctl: " + err.Error())
	}
	return probe.Supported()
}

// Collect implements probe.Probe.
func (p *SystemdProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	c := &systemdCollector{
		ctx:    ctx,
		cc:     cc,
		start:  cc.Now(),
		status: trustfreeze.StatusCaptured,
		blocks: map[string]ShowBlock{},
	}
	c.collectVersion()
	files, ok := c.collectUnitFiles()
	if !ok {
		return c.result()
	}
	selected := c.collectShow(files)
	c.buildArtifacts(files, selected)
	return c.result()
}

// systemdCollector gathers one Collect call.
type systemdCollector struct {
	ctx   context.Context
	cc    probe.CollectContext
	start time.Time

	status   trustfreeze.ProbeStatus
	errClass string
	reasons  []string

	toolVersion string
	sources     []string
	tools       []trustfreeze.ToolInvocation
	warnings    []trustfreeze.Diagnostic
	artifacts   []trustfreeze.Artifact

	// blocks holds the "systemctl show" answer per unit id.
	blocks map[string]ShowBlock
}

func (c *systemdCollector) warn(code, field, msg string) {
	c.warnings = append(c.warnings, trustfreeze.Diagnostic{Code: code, Field: field, Message: msg})
}

func (c *systemdCollector) addSource(s string) {
	for _, x := range c.sources {
		if x == s {
			return
		}
	}
	c.sources = append(c.sources, s)
}

// degrade lowers a captured run to partial. A terminal status set by fail
// stays untouched.
func (c *systemdCollector) degrade(reason string) {
	if c.status == trustfreeze.StatusCaptured {
		c.status = trustfreeze.StatusPartial
	}
	c.reasons = append(c.reasons, reason)
}

// fail sets the terminal status of a run whose primary source did not answer.
func (c *systemdCollector) fail(status trustfreeze.ProbeStatus, class, reason string) {
	c.status, c.errClass = status, class
	c.reasons = append(c.reasons, reason)
}

// exec runs one systemctl call through the injected runner.
func (c *systemdCollector) exec(args []string) probe.CommandResult {
	res := c.cc.Runner.Run(c.ctx, probe.CommandRequest{
		Executable: systemctlExe,
		Args:       args,
		Redactor:   c.cc.Redactor,
	})
	c.tools = append(c.tools, res.Invocation())
	return res
}

// evidence stores one redacted stream of a call. A refusal by the sink is a
// diagnostic; the engine caps such a run at partial on its own.
func (c *systemdCollector) evidence(name, source string, res probe.CommandResult, stderr bool) {
	data, truncated := res.Stdout, res.StdoutTruncated
	if stderr {
		data, truncated = res.Stderr, res.StderrTruncated
	}
	if len(data.Bytes()) == 0 {
		return
	}
	if _, err := c.cc.AddEvidence(name, source, data, truncated); err != nil {
		c.warn(probe.DiagEvidenceDropped, "", name+": "+err.Error())
	}
}

// collectVersion records the systemctl version (playbook L7).
func (c *systemdCollector) collectVersion() {
	res := c.exec([]string{"--version"})
	switch {
	case res.Err != nil:
		c.warn(DiagSystemdToolVersionUnknown, "", "systemctl --version: "+res.Err.Error())
		return
	case res.RedactionFailed:
		c.warn(DiagSystemdToolVersionUnknown, "", "systemctl --version output could not be redacted and was dropped")
		return
	case res.ExitCode != 0:
		c.warn(DiagSystemdToolVersionUnknown, "", fmt.Sprintf("systemctl --version exited %d", res.ExitCode))
		return
	}
	v, err := ParseSystemctlVersion(res.Stdout.Bytes())
	if err != nil {
		c.warn(DiagSystemdToolVersionUnknown, "", "systemctl --version: "+err.Error())
		return
	}
	c.evidence("systemctl-version.txt", "stdout:systemctl", res, false)
	c.toolVersion = v
}

// collectUnitFiles reads the declared inventory. The bool reports whether the
// run may continue: a primary source that did not answer ends the probe with
// a terminal status.
func (c *systemdCollector) collectUnitFiles() ([]UnitFile, bool) {
	args := []string{"list-unit-files", "--no-legend", "--no-pager"}
	res := c.exec(args)
	if res.Err != nil {
		status, class := systemdFailureFor(res.Err)
		c.fail(status, class, "systemctl list-unit-files: "+res.Err.Error())
		return nil, false
	}
	if res.RedactionFailed {
		c.warn(trustfreeze.DiagRedactionFailed, "", "systemctl list-unit-files output dropped (fail-closed)")
		c.fail(trustfreeze.StatusFailed, probe.ClassRedactionFailed, "systemctl list-unit-files output could not be redacted")
		return nil, false
	}
	c.evidence("systemctl-list-unit-files.txt", "stdout:systemctl", res, false)
	c.evidence("systemctl-list-unit-files.stderr.txt", "stderr:systemctl", res, true)
	out := res.Stdout.Bytes()
	if res.ExitCode != 0 {
		switch {
		case len(out) > 0:
			c.warn(DiagSystemdExitCode, "unit_files", fmt.Sprintf("systemctl list-unit-files exited %d after writing output; the list may be incomplete", res.ExitCode))
			c.degrade("list-unit-files exited " + strconv.Itoa(res.ExitCode))
		case len(res.Stderr.Bytes()) > 0:
			// Output on stderr and nothing on stdout: the manager did not
			// answer the question. The refusal text stays in the evidence and
			// is not retold here (playbook L4).
			c.fail(trustfreeze.StatusFailed, probe.ClassTerminated,
				fmt.Sprintf("systemctl list-unit-files exited %d with no output and %d bytes on stderr", res.ExitCode, len(res.Stderr.Bytes())))
			return nil, false
		default:
			// Empty in and empty out: a genuinely empty result, which is
			// captured with an empty list (playbook L1).
			c.warn(DiagSystemdExitCode, "unit_files", fmt.Sprintf("systemctl list-unit-files exited %d with no output: no unit file is listed", res.ExitCode))
		}
	}
	if res.StdoutTruncated {
		stdoutCap, _ := outputCap(c.cc)
		c.warn(trustfreeze.DiagOutputTruncated, "unit_files",
			truncationNote("systemctl list-unit-files", "stdout", len(out), res.StdoutBytes, stdoutCap,
				"the units beyond the cut were not read"))
		c.degrade("unit file list truncated")
	}
	files, issues := ParseUnitFiles(out)
	c.reportIssues("unit_files", "systemctl list-unit-files", issues)
	c.addSource("command:systemctl list-unit-files")
	sort.SliceStable(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, true
}

// reportIssues turns unread records into diagnostics and lowers the status
// (playbook L1: a partial parse is partial, with one diagnostic per record).
func (c *systemdCollector) reportIssues(field, source string, issues []SystemdLineIssue) {
	if len(issues) == 0 {
		return
	}
	shown := issues
	if len(shown) > systemdMaxIssueDiagnostics {
		shown = shown[:systemdMaxIssueDiagnostics]
	}
	for _, is := range shown {
		c.warn(DiagSystemdUnreadRecord, field, fmt.Sprintf("%s line %d: %s", source, is.Line, is.Reason))
	}
	if rest := len(issues) - len(shown); rest > 0 {
		c.warn(DiagSystemdUnreadRecord, field, fmt.Sprintf("%s: %d further records were not read", source, rest))
	}
	c.degrade(fmt.Sprintf("%d record(s) of %s were not read", len(issues), source))
}

// collectShow asks the manager about the selected units and returns them in
// the order they were asked about.
//
// A call that names several units can stop before it has answered for all of
// them: measured on an Ubuntu 22.04 bastion, one name the manager refuses
// ends the whole call, so the units before the refused name are answered for
// and the units after it are not
// (testdata/systemd/systemctl-show-batch-aborted.txt). The blocks that did
// arrive are kept, and the names that went unanswered are asked for again,
// one at a time, so one bad name costs one unit instead of a batch. The work
// is bounded by systemdMaxShowUnits, which caps the selection itself.
func (c *systemdCollector) collectShow(files []UnitFile) []string {
	selected, cut := SelectUnitsForShow(files, systemdMaxShowUnits)
	if cut {
		c.warn(DiagSystemdSelectionTruncated, "", fmt.Sprintf("more than %d units matched the selection rule; the rest was not asked about", systemdMaxShowUnits))
		c.degrade("unit selection truncated")
	}
	if len(selected) == 0 {
		return nil
	}
	asked := false
	for i := 0; i < len(selected); i += systemdShowBatch {
		end := i + systemdShowBatch
		if end > len(selected) {
			end = len(selected)
		}
		batch := selected[i:end]
		name := fmt.Sprintf("systemctl-show-%02d.txt", i/systemdShowBatch+1)
		if !c.showCall(batch, name) {
			// The call did not run at all (tool missing, refused, killed at
			// the deadline). Asking again one name at a time would repeat the
			// same failure, so the whole batch stays unanswered and
			// buildArtifacts reports it.
			c.degrade("runtime state of " + strconv.Itoa(len(batch)) + " unit(s) not read")
			continue
		}
		asked = true
		missing := c.missingUnits(batch)
		if len(missing) == 0 || len(batch) == 1 {
			continue
		}
		c.warn(DiagSystemdBatchSplit, "runtime_state", fmt.Sprintf(
			"systemctl show answered for %d of %d unit(s) starting at %s and stopped there; the remaining %d unit(s) were asked for one at a time",
			len(batch)-len(missing), len(batch), batch[0], len(missing)))
		base := strings.TrimSuffix(name, ".txt")
		for j, u := range missing {
			c.showCall([]string{u}, fmt.Sprintf("%s-retry-%02d.txt", base, j+1))
		}
	}
	if asked {
		c.addSource("command:systemctl show")
	}
	return selected
}

// showCall issues one "systemctl show" call, stores every property block it
// could read and reports whether the call ran and was parsed at all. A call
// that never produced output is a diagnostic and no blocks; the status is
// lowered by the caller, which knows how many units that cost.
func (c *systemdCollector) showCall(units []string, evidenceName string) bool {
	args := append([]string{"show", "--no-pager", "-p", systemdShowProperties}, units...)
	res := c.exec(args)
	switch {
	case res.Err != nil:
		c.warn(systemdDiagForError(res.Err), "runtime_state", fmt.Sprintf("systemctl show for %d unit(s) starting at %s: %s", len(units), units[0], res.Err.Error()))
		return false
	case res.RedactionFailed:
		c.warn(trustfreeze.DiagRedactionFailed, "runtime_state", "systemctl show output dropped (fail-closed)")
		return false
	}
	c.evidence(evidenceName, "stdout:systemctl", res, false)
	c.evidence(strings.TrimSuffix(evidenceName, ".txt")+".stderr.txt", "stderr:systemctl", res, true)
	if res.ExitCode != 0 {
		c.warn(DiagSystemdExitCode, "runtime_state", fmt.Sprintf("systemctl show exited %d for %d unit(s) starting at %s", res.ExitCode, len(units), units[0]))
	}
	if res.StdoutTruncated {
		stdoutCap, _ := outputCap(c.cc)
		c.warn(trustfreeze.DiagOutputTruncated, "runtime_state",
			truncationNote("systemctl show", "stdout", len(res.Stdout.Bytes()), res.StdoutBytes, stdoutCap,
				"the runtime state of the units beyond the cut was not read"))
		c.degrade("runtime state truncated")
	}
	blocks, issues := ParseShowBlocks(res.Stdout.Bytes())
	c.reportIssues("runtime_state", "systemctl show", issues)
	for _, b := range blocks {
		id := b.First(ShowPropID)
		if id == "" {
			continue
		}
		c.blocks[id] = b
	}
	return true
}

// missingUnits lists the units of a call the manager returned no property
// block for, in the order they were asked about.
func (c *systemdCollector) missingUnits(units []string) []string {
	var out []string
	for _, u := range units {
		if _, ok := c.blocks[u]; !ok {
			out = append(out, u)
		}
	}
	return out
}

// buildArtifacts turns the two layers into artifacts.
func (c *systemdCollector) buildArtifacts(files []UnitFile, selected []string) {
	prov := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     c.sortedSources(),
		ObservedAt:  trustfreeze.FormatTime(c.start),
		ToolVersion: c.toolVersion,
	}

	observedCount, templateCount := 0, 0
	for _, f := range files {
		// Both artifacts of a unit share the sanitized suffix, so one check
		// covers both ids.
		suffix := systemdUnitIDSuffix(f.Name)
		id := ArtifactSystemdUnitPrefix + suffix
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			c.warn(probe.DiagArtifactDropped, systemdAttrUnit, "unit name yields no valid artifact id")
			c.degrade("a unit artifact was dropped")
			continue
		}
		attrs := map[string]string{
			systemdAttrUnit:         f.Name,
			systemdAttrEnabledState: f.State,
		}
		if f.Type != "" {
			attrs[systemdAttrUnitType] = f.Type
		}
		if f.Preset != "" {
			attrs[systemdAttrPreset] = f.Preset
		}
		// A template unit cannot run: only an instance of it can. Its runtime
		// state is not_applicable WITH the reason, which is the one case where
		// not_applicable is a statement about the thing and not about the
		// capture (playbook L1).
		template := IsTemplateUnit(f.Name)
		if template {
			templateCount++
			attrs[systemdAttrTemplate] = "true"
			attrs[systemdAttrRuntimeState] = systemdRuntimeNotApplicable
			attrs[systemdAttrRuntimeReason] = systemdTemplateReason
		}
		block, shown := c.blocks[f.Name]
		if shown {
			c.addDeclaredFromShow(attrs, f, block)
		}
		c.artifacts = append(c.artifacts, trustfreeze.Artifact{
			ID: id, Type: "systemd-unit", Scope: "system", Source: SystemdProbeID,
			// A unit file declares what may run; it is not an observation of
			// the present (playbook L3).
			State:       trustfreeze.StateDeclared,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
		if !shown || template {
			continue
		}
		if load := block.First(ShowPropLoadState); load == ShowLoadStateNotFound {
			// The unit file list named it and the manager does not know it:
			// a real gap in the answer, not an unread record.
			c.warn(DiagSystemdUnitNotFound, systemdAttrUnit, f.Name+" is listed as a unit file and the manager reports LoadState=not-found")
			continue
		}
		c.artifacts = append(c.artifacts, trustfreeze.Artifact{
			ID: ArtifactSystemdRuntimePrefix + suffix, Type: "systemd-unit-runtime", Scope: "system", Source: SystemdProbeID,
			// What the manager says right now.
			State:       trustfreeze.StateObserved,
			Attributes:  systemdRuntimeAttributes(f.Name, block),
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
		observedCount++
	}

	c.artifacts = append(c.artifacts, trustfreeze.Artifact{
		ID: ArtifactSystemdManager, Type: "systemd-manager", Scope: "system", Source: SystemdProbeID,
		State: trustfreeze.StateObserved,
		Attributes: map[string]string{
			systemdAttrScope:         "system",
			systemdAttrUserScope:     systemdUserScopeNotCollected,
			systemdAttrUnitFileCount: strconv.Itoa(len(files)),
			systemdAttrObservedCount: strconv.Itoa(observedCount),
			systemdAttrTemplateCount: strconv.Itoa(templateCount),
			systemdAttrSelectionRule: systemdSelectionRule,
		},
		Provenance:  prov,
		Sensitivity: trustfreeze.SensitivityInternal,
	})
	// Coverage, stated instead of implied: the user managers are a scope of
	// their own and this probe never asks for them (playbook L1).
	c.warn(DiagSystemdScopeNotCollected, systemdAttrUserScope,
		"systemd user managers are not collected: this probe asks the system manager only")
	if templateCount > 0 {
		// Coverage, stated instead of implied: these units exist, they were
		// deliberately not asked about, and that is not a gap.
		c.warn(DiagSystemdTemplateUnit, systemdAttrTemplate,
			fmt.Sprintf("%d unit file(s) are templates and were not asked about: %s", templateCount, systemdTemplateReason))
	}
	// A unit the probe asked about and got no answer for has no observed
	// state, and the run is partial: the question was asked and is open. Each
	// such unit is named, so a reader sees which ones, and only those.
	missing := c.missingUnits(selected)
	if len(missing) == 0 {
		return
	}
	shown := missing
	if len(shown) > systemdMaxIssueDiagnostics {
		shown = shown[:systemdMaxIssueDiagnostics]
	}
	for _, u := range shown {
		c.warn(DiagSystemdUnitStateNotRead, "runtime_state",
			u+": the manager returned no properties for this unit, so its runtime state is unknown")
	}
	if rest := len(missing) - len(shown); rest > 0 {
		c.warn(DiagSystemdUnitStateNotRead, "runtime_state",
			fmt.Sprintf("%d further unit(s) have no observed state", rest))
	}
	c.warn(trustfreeze.DiagFieldMissing, "runtime_state",
		fmt.Sprintf("%d of %d selected unit(s) have no observed state", len(missing), len(selected)))
	c.degrade(fmt.Sprintf("runtime state of %d selected unit(s) is unknown", len(missing)))
}

// addDeclaredFromShow copies the unit file facts of a show answer into the
// declared attributes.
func (c *systemdCollector) addDeclaredFromShow(attrs map[string]string, f UnitFile, b ShowBlock) {
	if v := b.First(ShowPropFragmentPath); v != "" {
		attrs[systemdAttrFragmentPath] = v
	}
	if v := b.First(ShowPropDropInPaths); v != "" {
		attrs[systemdAttrDropInPaths] = v
	}
	if v := b.First(ShowPropType); v != "" {
		attrs[systemdAttrServiceType] = v
	}
	if v := b.First(ShowPropUser); v != "" {
		attrs[systemdAttrUser] = v
	}
	if v := b.First(ShowPropGroup); v != "" {
		attrs[systemdAttrGroup] = v
	}
	if v := b.First(ShowPropRestart); v != "" {
		attrs[systemdAttrRestart] = v
	}
	if p := ParseExecStartPath(b.First(ShowPropExecStart)); p != "" {
		attrs[systemdAttrExecStartPath] = p
	}
	if n := b.Count(ShowPropExecStart); n > 1 {
		attrs[systemdAttrExecStartCount] = strconv.Itoa(n)
	}
	// Two sources for the same declared fact: a mismatch means the unit file
	// changed since the manager loaded it.
	if s := b.First(ShowPropUnitFileState); s != "" && s != f.State {
		c.warn(DiagSystemdStateMismatch, systemdAttrEnabledState,
			fmt.Sprintf("%s: list-unit-files says %q, show says %q", f.Name, f.State, s))
	}
}

// systemdRuntimeAttributes builds the observed attribute set of one unit.
func systemdRuntimeAttributes(unit string, b ShowBlock) map[string]string {
	attrs := map[string]string{systemdAttrUnit: unit}
	for attr, prop := range map[string]string{
		systemdAttrLoadState:       ShowPropLoadState,
		systemdAttrActiveState:     ShowPropActiveState,
		systemdAttrSubState:        ShowPropSubState,
		systemdAttrConditionResult: ShowPropConditionResult,
		systemdAttrDaemonReload:    ShowPropNeedDaemonReload,
	} {
		if v := b.First(prop); v != "" {
			attrs[attr] = v
		}
	}
	return attrs
}

func (c *systemdCollector) sortedSources() []string {
	out := append([]string(nil), c.sources...)
	sort.Strings(out)
	return out
}

// result builds the persisted result.
func (c *systemdCollector) result() trustfreeze.ProbeResult {
	for i := range c.artifacts {
		if d, err := trustfreeze.ComputeArtifactDigest(c.artifacts[i]); err == nil {
			c.artifacts[i].Digest = d
		}
	}
	trustfreeze.SortArtifacts(c.artifacts)
	res := trustfreeze.ProbeResult{
		ProbeID:         SystemdProbeID,
		ProbeVersion:    SystemdProbeVersion,
		Status:          c.status,
		Reason:          strings.Join(c.reasons, "; "),
		Support:         c.cc.Support.Record(),
		StartedAt:       trustfreeze.FormatTime(c.start),
		DurationMS:      c.cc.Now().Sub(c.start).Milliseconds(),
		Privilege:       c.cc.Privilege,
		Tools:           c.tools,
		NormalizedState: c.artifacts,
		Warnings:        c.warnings,
	}
	if c.errClass != "" {
		res.Error = &trustfreeze.ProbeError{Class: c.errClass, Message: res.Reason}
	}
	return res
}

// systemdFailureFor maps a runner error to the honest probe status
// (playbook L1): a missing tool is unavailable, a refusal is
// permission_denied, a deadline is timeout, everything else failed.
func systemdFailureFor(err error) (trustfreeze.ProbeStatus, string) {
	switch {
	case errors.Is(err, probe.ErrToolMissing):
		return trustfreeze.StatusUnavailable, probe.ClassToolMissing
	case errors.Is(err, probe.ErrPermissionDenied):
		return trustfreeze.StatusPermissionDenied, probe.ClassPermissionDenied
	case errors.Is(err, probe.ErrTimeout):
		return trustfreeze.StatusTimeout, probe.ClassTimeout
	}
	return trustfreeze.StatusFailed, probe.ErrorClass(err)
}

// systemdDiagForError names the field diagnostic of a failed call.
func systemdDiagForError(err error) string {
	switch {
	case errors.Is(err, probe.ErrToolMissing):
		return probe.DiagFieldUnavailable
	case errors.Is(err, probe.ErrPermissionDenied):
		return probe.DiagFieldPermissionDenied
	case errors.Is(err, probe.ErrTimeout):
		return probe.DiagFieldTimeout
	}
	return probe.DiagFieldFailed
}

// systemdUnitIDSuffix builds the artifact id suffix of one unit. A unit name
// may carry characters an artifact id may not (systemd escapes a hyphen in a
// path as the four characters backslash x 2 d, as in
// "system-systemd\x2dcryptsetup.slice"), so those are replaced. The unit name
// itself stays in the unit attribute, unchanged.
func systemdUnitIDSuffix(unit string) string {
	var b strings.Builder
	b.Grow(len(unit))
	for _, r := range unit {
		switch {
		case r <= 0x20, r == 0x7f, r == '\\', r == '~', r == '/', r == ':':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Pure parsers. Everything below works on bytes only, so every shape is table
// tested from the fixtures on any operating system.
// ---------------------------------------------------------------------------

// SystemdLineIssue is one output record a parser of this probe could not read.
// Reason is a stable string and carries no line content, so a diagnostic built
// from it never leaks what the line said.
type SystemdLineIssue struct {
	// Line is the 1-based line number in the parsed output.
	Line int
	// Reason is one of the SystemdIssue constants.
	Reason string
}

// Reasons of a SystemdLineIssue.
const (
	SystemdIssueFieldCount    = "expected two or three columns"
	SystemdIssueNoUnitType    = "unit name has no type suffix"
	SystemdIssueNotAssignment = "not a property assignment"
	SystemdIssueEmptyProperty = "empty property name"
)

// UnitFile is one row of "systemctl list-unit-files --no-legend --no-pager".
// Every value is recorded as the tool printed it: the set of unit file states
// grows between systemd versions (the trial host shows nine of them), so no
// value is checked against a closed list here.
type UnitFile struct {
	// Name is the full unit name, for example "ssh.service".
	Name string
	// Type is the suffix after the last dot, for example "service". It is
	// empty when the name has no suffix.
	Type string
	// State is the UnitFileState column: enabled, enabled-runtime, disabled,
	// static, masked, alias, indirect, generated, transient and whatever else
	// a systemd version prints.
	State string
	// Preset is the UnitFilePreset column, empty when the column says "-" or
	// when the systemd version prints only two columns.
	Preset string
}

// ParseUnitFiles reads the unit file list. Columns are separated by runs of
// spaces and a unit name never contains white space, so the split is by
// fields and never by byte offset (the column two offset of a given host is
// an artifact of its longest unit name).
//
// Empty lines are skipped. A row with any other column count is returned as
// an issue and no row: the caller reports one diagnostic per issue and the
// probe is partial, never silently short.
func ParseUnitFiles(b []byte) ([]UnitFile, []SystemdLineIssue) {
	var (
		out    []UnitFile
		issues []SystemdLineIssue
	)
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 3 {
			issues = append(issues, SystemdLineIssue{Line: i + 1, Reason: SystemdIssueFieldCount})
			continue
		}
		u := UnitFile{Name: fields[0], State: fields[1]}
		if len(fields) == 3 && fields[2] != "-" {
			u.Preset = fields[2]
		}
		if d := strings.LastIndexByte(u.Name, '.'); d > 0 && d < len(u.Name)-1 {
			u.Type = u.Name[d+1:]
		} else {
			issues = append(issues, SystemdLineIssue{Line: i + 1, Reason: SystemdIssueNoUnitType})
		}
		out = append(out, u)
	}
	return out, issues
}

// IsTemplateUnit reports whether name is a systemd TEMPLATE unit.
//
// A unit name is "<prefix>@<instance>.<type>". A template is the form with an
// EMPTY instance part, written as an "@" immediately before the type suffix:
// "getty@.service", "autovt@.service", "apport-forward@.service". systemd
// builds instances from it ("getty@tty1.service"), and only an instance has a
// runtime state.
//
// The detector is the name grammar and nothing else, because asking the
// manager is exactly what fails: measured on an Ubuntu 22.04 bastion, a
// "systemctl show" call that names a template exits 1 with
// "Failed to get properties: Unit name getty@.service is neither a valid
// invocation ID nor unit name." and stops there, so every name after it in
// the same call goes unanswered
// (testdata/systemd/systemctl-show-template.stderr.txt).
//
// A name with no prefix before the "@", or with no type suffix, is not a
// template; it is a name this parser cannot read as one, and the caller then
// treats it like any other unit.
func IsTemplateUnit(name string) bool {
	d := strings.LastIndexByte(name, '.')
	return d > 1 && d < len(name)-1 && name[d-1] == '@'
}

// Property names of the "systemctl show" call.
const (
	ShowPropID               = "Id"
	ShowPropLoadState        = "LoadState"
	ShowPropActiveState      = "ActiveState"
	ShowPropSubState         = "SubState"
	ShowPropUnitFileState    = "UnitFileState"
	ShowPropUnitFilePreset   = "UnitFilePreset"
	ShowPropFragmentPath     = "FragmentPath"
	ShowPropDropInPaths      = "DropInPaths"
	ShowPropType             = "Type"
	ShowPropExecStart        = "ExecStart"
	ShowPropUser             = "User"
	ShowPropGroup            = "Group"
	ShowPropRestart          = "Restart"
	ShowPropConditionResult  = "ConditionResult"
	ShowPropNeedDaemonReload = "NeedDaemonReload"
)

// ShowLoadStateNotFound is the only truthful signal that a unit does not
// exist: "systemctl show" answers a question about an unknown unit with exit
// code 0 and a full set of empty properties (testdata/README.md).
const ShowLoadStateNotFound = "not-found"

// ShowBlock is the answer of "systemctl show" for one unit.
type ShowBlock struct {
	// Values holds every property in output order. A property systemd prints
	// more than once (ExecStart of a unit with several commands) keeps all of
	// its values.
	Values map[string][]string
	// Order lists the property names in first-seen order.
	Order []string
}

// First returns the first value of key, or the empty string.
func (b ShowBlock) First(key string) string {
	v := b.Values[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Count returns how often systemd printed key.
func (b ShowBlock) Count(key string) int { return len(b.Values[key]) }

// ParseShowBlocks splits the output of "systemctl show" into one block per
// unit.
//
// Two properties of the format decide the split. systemd answers in ITS
// property order, not in the order asked for, so a block is never recognized
// by a fixed first key. And only the single unit shape was measured on the
// trial host (testdata/commands.json), so the split accepts both separators a
// multi unit call can produce: a blank line between blocks, and a second Id
// property. Id is the unit identity and systemd prints exactly one per unit.
//
// A value may contain "=" (an ExecStart record does), so the split of a line
// is at the FIRST "=" only. A line without "=" and a line with an empty
// property name are issues and are dropped.
func ParseShowBlocks(b []byte) ([]ShowBlock, []SystemdLineIssue) {
	var (
		out     []ShowBlock
		issues  []SystemdLineIssue
		current ShowBlock
	)
	flush := func() {
		if len(current.Order) > 0 {
			out = append(out, current)
		}
		current = ShowBlock{}
	}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			flush()
			continue
		}
		eq := strings.IndexByte(line, '=')
		switch {
		case eq < 0:
			issues = append(issues, SystemdLineIssue{Line: i + 1, Reason: SystemdIssueNotAssignment})
			continue
		case eq == 0:
			issues = append(issues, SystemdLineIssue{Line: i + 1, Reason: SystemdIssueEmptyProperty})
			continue
		}
		key, value := line[:eq], line[eq+1:]
		if key == ShowPropID && len(current.Values[ShowPropID]) > 0 {
			flush()
		}
		if current.Values == nil {
			current.Values = map[string][]string{}
		}
		if _, seen := current.Values[key]; !seen {
			current.Order = append(current.Order, key)
		}
		current.Values[key] = append(current.Values[key], value)
	}
	flush()
	return out, issues
}

// ParseSystemctlVersion returns the first line of "systemctl --version", for
// example "systemd 255 (255.4-1ubuntu8.17)". The line names the upstream
// version and the distribution package, and a parser is only valid for the
// versions it was measured against (playbook L7). The feature flag line that
// follows is not part of the version.
func ParseSystemctlVersion(b []byte) (string, error) {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		return systemdCapValue(line), nil
	}
	return "", errors.New("linux.systemd: systemctl --version printed no line")
}

// systemdMaxValueBytes caps a single recorded value, so an unexpected tool
// answer cannot inflate an artifact (playbook L6).
const systemdMaxValueBytes = 200

func systemdCapValue(s string) string {
	if len(s) <= systemdMaxValueBytes {
		return s
	}
	return strings.ToValidUTF8(s[:systemdMaxValueBytes], "")
}

// ParseExecStartPath returns the path of a systemd ExecStart property value,
// for example "/usr/sbin/sshd" from
//
//	{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ... }
//
// The rest of the record is deliberately not returned. The argument vector of
// a unit can carry a credential that the unit file passes on the command line
// (playbook L4), and start_time, stop_time, pid, code and status are volatile
// (playbook L8). The fragment path is recorded beside it, so a reader who
// needs the full command line knows which file to open.
//
// An empty or unparsable value returns the empty string; the caller then
// records no attribute rather than a guess.
func ParseExecStartPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "path="); ok {
			return systemdCapValue(strings.TrimSpace(v))
		}
	}
	return ""
}

// Unit types SelectUnitsForShow asks the manager about.
var (
	// systemdActivationTypes are the activation points of a host: a timer or
	// a socket starts something without anybody logging in, so its runtime
	// state matters whatever its enablement says.
	systemdActivationTypes = map[string]bool{"socket": true, "timer": true}
	// systemdEnabledTypes are asked about when they are enabled: enabled
	// means the unit is declared to start.
	systemdEnabledTypes = map[string]bool{
		"automount": true, "mount": true, "path": true, "service": true,
	}
	// systemdEnabledStates are the unit file states that declare a start.
	systemdEnabledStates = map[string]bool{"enabled": true, "enabled-runtime": true}
	// systemdSkipStates are unit file states no runtime question is asked
	// about: an alias is a second name for another unit, and a masked unit
	// cannot start at all.
	systemdSkipStates = map[string]bool{
		"alias": true, "masked": true, "masked-runtime": true,
	}
)

// SelectUnitsForShow returns the units whose runtime state the probe asks
// systemd about, sorted by unit name, and whether the selection was cut at
// max.
//
// The rule is systemdSelectionRule and it is recorded in the manager
// artifact, because it decides what the bundle can and cannot say: a static
// service that a socket started is running on the host and is not in this
// selection, so its runtime state is absent from the bundle by design and not
// by accident. Transient units (the scope of a running container) are left
// out on purpose: they are the subject of linux.containers, and their names
// change with every restart.
func SelectUnitsForShow(files []UnitFile, max int) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		switch {
		case f.Name == "", seen[f.Name]:
			continue
		case IsTemplateUnit(f.Name):
			// A template has no instance and therefore no runtime state, and
			// a call that names one is refused and takes the rest of its
			// batch with it. It is recorded as a template instead.
			continue
		case systemdSkipStates[f.State], f.State == "transient":
			continue
		case systemdActivationTypes[f.Type]:
		case systemdEnabledTypes[f.Type] && systemdEnabledStates[f.State]:
		default:
			continue
		}
		seen[f.Name] = true
		out = append(out, f.Name)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		return out[:max], true
	}
	return out, false
}
