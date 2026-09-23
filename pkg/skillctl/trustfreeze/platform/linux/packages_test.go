package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// The fixtures of testdata are transcribed from a real Ubuntu 24.04.1 host and
// sanitized; testdata/README.md names the tool versions and the substitutions.
// These tests run on any operating system, because every parser is a pure
// function over bytes and every command goes through the fake runner
// (SPEC-0467 R9).

var invTestTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// invFixtureEntry is one entry of testdata/commands.json: the argv a fixture
// was taken with, the stream it holds and the exit code of that run.
type invFixtureEntry struct {
	Path    string   `json:"path"`
	Probe   string   `json:"probe"`
	Command []string `json:"command"`
	// ProbeCommand is the argv the probe issues where it differs from the
	// argv the fixture was taken with. It is empty when they are the same.
	// The index keeps both, so neither claim drifts unnoticed (F14).
	ProbeCommand []string `json:"probe_command,omitempty"`
	Stream       string   `json:"stream"`
	ExitCode     int      `json:"exit_code"`
}

type invFixtureIndex struct {
	Schema   string            `json:"schema"`
	Fixtures []invFixtureEntry `json:"fixtures"`
}

const invFixtureSchema = "trust-freeze/linux-fixtures/v1"

func invIndex(t *testing.T) invFixtureIndex {
	t.Helper()
	var idx invFixtureIndex
	if err := json.Unmarshal(invBytes(t, "commands.json"), &idx); err != nil {
		t.Fatalf("commands.json: %v", err)
	}
	if idx.Schema != invFixtureSchema {
		t.Fatalf("commands.json schema %q, want %q", idx.Schema, invFixtureSchema)
	}
	return idx
}

func invEntry(t *testing.T, path string) invFixtureEntry {
	t.Helper()
	for _, e := range invIndex(t).Fixtures {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("commands.json has no entry for %s", path)
	return invFixtureEntry{}
}

func invBytes(t *testing.T, rel string) []byte {
	t.Helper()
	// #nosec G304 -- test data from this repository; the path is built in the
	// test itself and never comes from an input.
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("fixture %s: %v", rel, err)
	}
	return b
}

// invScript scripts one fixture on the fake runner, with exactly the argv,
// stream and exit code that commands.json records for it. A probe that calls
// its tool with other arguments therefore fails the test instead of silently
// passing: the fixture index is the contract.
func invScript(t *testing.T, r *probe.FakeRunner, path string) *probe.FakeRunner {
	t.Helper()
	e := invEntry(t, path)
	if len(e.Command) == 0 {
		t.Fatalf("commands.json entry %s has no command", path)
	}
	resp := probe.FakeResponse{ExitCode: e.ExitCode}
	argv := e.Command
	if len(e.ProbeCommand) > 0 {
		// The probe issues another argv than the one the fixture was taken
		// with; the index says which, and the script follows the probe.
		argv = e.ProbeCommand
	}
	switch e.Stream {
	case "stdout":
		resp.Stdout = invBytes(t, path)
	case "stderr":
		resp.Stderr = invBytes(t, path)
	default:
		t.Fatalf("commands.json entry %s has unknown stream %q", path, e.Stream)
	}
	return r.Script(argv[0], argv[1:], resp)
}

// invScriptRaw scripts a response that no fixture carries in this argv shape,
// for example a refusal fixture applied to the argv the probe really uses.
func invScriptRaw(r *probe.FakeRunner, exe string, args []string, resp probe.FakeResponse) *probe.FakeRunner {
	return r.Script(exe, args, resp)
}

// invRun runs Support and then Collect, the way the capture engine does, and
// returns the result together with the evidence the probe handed over.
func invRun(t *testing.T, p probe.Probe, runner probe.CommandRunner) (trustfreeze.ProbeResult, []probe.EvidenceItem) {
	t.Helper()
	ev := probe.NewEvidenceBuffer(p.Descriptor().ID, probe.Limits{})
	host := probe.HostContext{
		GOOS: "linux", GOARCH: "amd64",
		Hostname:  func() (string, error) { return "host-a.example", nil },
		Files:     probe.FakeFiles{},
		Runner:    runner,
		Clock:     trustfreeze.FixedClock{T: invTestTime},
		Privilege: probe.PrivilegeUser,
	}
	ctx := context.Background()
	support := p.Support(ctx, host)
	if err := support.Validate(); err != nil {
		t.Fatalf("support result: %v", err)
	}
	if !support.Available {
		t.Fatalf("probe %s is not available: %s (%s)", p.Descriptor().ID, support.Status, support.Reason)
	}
	res := p.Collect(ctx, probe.CollectContext{
		HostContext: host,
		ProbeID:     p.Descriptor().ID,
		Redactor:    redact.Default(),
		Limits:      probe.Limits{},
		Evidence:    ev,
		Support:     support,
	})
	return res, ev.Close()
}

func invArtifact(t *testing.T, res trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no artifact %s (%d artifacts)", id, len(res.NormalizedState))
	return trustfreeze.Artifact{}
}

func invHasArtifact(res trustfreeze.ProbeResult, id string) bool {
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return true
		}
	}
	return false
}

func invWarning(res trustfreeze.ProbeResult, code string) (trustfreeze.Diagnostic, bool) {
	for _, w := range res.Warnings {
		if w.Code == code {
			return w, true
		}
	}
	return trustfreeze.Diagnostic{}, false
}

func invWantWarning(t *testing.T, res trustfreeze.ProbeResult, code string) trustfreeze.Diagnostic {
	t.Helper()
	w, ok := invWarning(res, code)
	if !ok {
		t.Fatalf("no diagnostic %s in %+v", code, res.Warnings)
	}
	return w
}

func invWantNoWarning(t *testing.T, res trustfreeze.ProbeResult, code string) {
	t.Helper()
	if w, ok := invWarning(res, code); ok {
		t.Fatalf("unexpected diagnostic %s: %s", code, w.Message)
	}
}

func invWantAttr(t *testing.T, a trustfreeze.Artifact, name, want string) {
	t.Helper()
	if got := a.Attributes[name]; got != want {
		t.Fatalf("%s attribute %s = %q, want %q (all %v)", a.ID, name, got, want, a.Attributes)
	}
}

func invEvidenceNames(items []probe.EvidenceItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Name)
	}
	return out
}

func invContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// invPackagesRunner scripts the whole happy path of linux.packages.
func invPackagesRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	r := probe.NewFakeRunner()
	invScript(t, r, "packages/dpkg-query-w.txt")
	invScript(t, r, "packages/apt-mark-showmanual.txt")
	invScript(t, r, "packages/snap-list.txt")
	invScript(t, r, "packages/dpkg-query-version.txt")
	invScript(t, r, "packages/apt-mark-version.txt")
	invScript(t, r, "packages/snap-version.txt")
	return r
}

// TestPackagesProbeArgvMatchesFixtureIndex pins the calls of the probe to the
// argv every fixture was taken with (SPEC-0471 TF06-R3): the format string
// reaches dpkg-query as backslash t, not as a tab.
func TestPackagesProbeArgvMatchesFixtureIndex(t *testing.T) {
	e := invEntry(t, "packages/dpkg-query-w.txt")
	want := []string{"dpkg-query", "-W", DpkgQueryFormat}
	if !reflect.DeepEqual(e.Command, want) {
		t.Fatalf("commands.json argv %q, probe argv %q", e.Command, want)
	}
	if strings.ContainsRune(DpkgQueryFormat, '\t') {
		t.Fatal("the dpkg-query format string must not contain a real tab")
	}
}

func TestParseDpkgQueryFixture(t *testing.T) {
	pkgs, issues := ParseDpkgQuery(invBytes(t, "packages/dpkg-query-w.txt"))
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	if len(pkgs) != 51 {
		t.Fatalf("parsed %d packages, want 51", len(pkgs))
	}
	if got := pkgs[0]; got != (DpkgPackage{Name: "accountsservice", Version: "23.13.9-2ubuntu6.1", Architecture: "amd64", Status: "ii"}) {
		t.Fatalf("first package %+v", got)
	}
	byName := map[string]DpkgPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	// Multiarch qualified name, epoch version, and the name apt-mark uses.
	zlib, ok := byName["zlib1g:amd64"]
	if !ok {
		t.Fatalf("no multiarch qualified package in %d entries", len(pkgs))
	}
	if zlib.Version != "1:1.3.dfsg-3.1ubuntu2.2" || zlib.Architecture != "amd64" || zlib.BaseName() != "zlib1g" {
		t.Fatalf("zlib1g:amd64 parsed as %+v (base name %q)", zlib, zlib.BaseName())
	}
	if !zlib.Installed() {
		t.Fatal("status ii must count as installed")
	}
	// Architecture "all" occurs, and so does a removed package whose
	// configuration files are still on disk.
	residual, ok := byName["linux-image-6.11.0-17-generic"]
	if !ok {
		t.Fatal("no residual config package in the fixture")
	}
	if residual.Status != "rc" {
		t.Fatalf("status %q, want rc", residual.Status)
	}
	if residual.Installed() {
		t.Fatal("status rc must not count as installed")
	}
	if byName["adduser"].Architecture != "all" {
		t.Fatalf("adduser architecture %q, want all", byName["adduser"].Architecture)
	}
}

func TestParseDpkgQueryIssues(t *testing.T) {
	// Constructed input, not a fixture: a shape the host never produced but
	// that a parser must refuse instead of inventing a record.
	in := []byte("ok\t1.0\tamd64\tii \nbroken-line-without-fields\n\nalso-ok\t2.0\tall\tii \n\t1.0\tall\tii \n")
	pkgs, issues := ParseDpkgQuery(in)
	if len(pkgs) != 2 {
		t.Fatalf("parsed %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	if len(issues) != 2 {
		t.Fatalf("issues %+v, want 2", issues)
	}
	if issues[0].Line != 2 || issues[1].Line != 5 {
		t.Fatalf("issue lines %d and %d, want 2 and 5", issues[0].Line, issues[1].Line)
	}
	for _, is := range issues {
		if strings.Contains(is.Reason, "broken-line-without-fields") {
			t.Fatalf("an issue reason repeats the record: %q", is.Reason)
		}
	}
}

func TestParseAptMarkShowManualFixture(t *testing.T) {
	names := ParseAptMarkShowManual(invBytes(t, "packages/apt-mark-showmanual.txt"))
	if len(names) != 82 {
		t.Fatalf("parsed %d manual packages, want 82", len(names))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("result is not sorted and free of duplicates at %d: %q, %q", i, names[i-1], names[i])
		}
	}
	if !invContains(names, "vim") || !invContains(names, "build-essential") {
		t.Fatalf("expected names missing from %d entries", len(names))
	}
}

// TestParseSnapListIsLocaleIndependent is the point of the two snap fixtures:
// the same host at the same moment, once with LC_ALL=C and once with a
// language set. The header words and every column width differ, the records
// do not. A parser that keys on the header text or on byte offsets fails here.
func TestParseSnapListIsLocaleIndependent(t *testing.T) {
	plain, issues := ParseSnapList(invBytes(t, "packages/snap-list.txt"))
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	localized, issues := ParseSnapList(invBytes(t, "packages/snap-list-localized.txt"))
	if len(issues) != 0 {
		t.Fatalf("localized issues %+v", issues)
	}
	if len(plain) != 23 {
		t.Fatalf("parsed %d snaps, want 23 (24 lines, one of them the header)", len(plain))
	}
	if !reflect.DeepEqual(plain, localized) {
		t.Fatalf("the two locales parsed differently:\n%+v\n%+v", plain, localized)
	}
	if plain[0] != (SnapPackage{Name: "bare", Version: "1.0", Revision: "5", Tracking: "latest/stable", Publisher: "canonical**", Notes: "base"}) {
		t.Fatalf("first snap %+v", plain[0])
	}
	var firefox SnapPackage
	for _, s := range plain {
		if s.Name == "firefox" {
			firefox = s
		}
	}
	if firefox.Tracking != "latest/stable/…" {
		t.Fatalf("firefox tracking %q", firefox.Tracking)
	}
	if !firefox.TrackingTruncated() {
		t.Fatal("a tracking value the tool shortened must be recognized as such")
	}
	if plain[0].TrackingTruncated() {
		t.Fatal("a complete tracking value must not be reported as shortened")
	}
}

func TestParseSnapListIssues(t *testing.T) {
	// Constructed: header plus one row with a missing column.
	in := []byte("Name  Version  Rev  Tracking  Publisher  Notes\nok  1.0  5  latest/stable  canonical  -\nbroken  1.0  5\n")
	snaps, issues := ParseSnapList(in)
	if len(snaps) != 1 || len(issues) != 1 || issues[0].Line != 3 {
		t.Fatalf("snaps %+v issues %+v", snaps, issues)
	}
}

func TestParseToolVersions(t *testing.T) {
	cases := []struct {
		name  string
		parse func([]byte) string
		file  string
		want  string
	}{
		{"dpkg-query", ParseDpkgQueryVersion, "packages/dpkg-query-version.txt", "1.22.6"},
		{"apt-mark", ParseAptMarkVersion, "packages/apt-mark-version.txt", "2.7.14"},
		{"snap", ParseSnapVersion, "packages/snap-version.txt", "2.76.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.parse(invBytes(t, tc.file)); got != tc.want {
				t.Fatalf("version %q, want %q", got, tc.want)
			}
			if got := tc.parse([]byte("something else entirely\n")); got != "" {
				t.Fatalf("unrecognized output yielded %q, want the empty string", got)
			}
		})
	}
}

func TestPackagesProbeCollectsFixtures(t *testing.T) {
	res, evidence := invRun(t, NewPackagesProbe(), invPackagesRunner(t))
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s, reason %q, warnings %+v", res.Status, res.Reason, res.Warnings)
	}
	if len(res.NormalizedState) != 51+23 {
		t.Fatalf("%d artifacts, want 74", len(res.NormalizedState))
	}
	zlib := invArtifact(t, res, "os/package/zlib1g:amd64")
	invWantAttr(t, zlib, "name", "zlib1g:amd64")
	invWantAttr(t, zlib, "version", "1:1.3.dfsg-3.1ubuntu2.2")
	invWantAttr(t, zlib, "architecture", "amd64")
	invWantAttr(t, zlib, "manager", "dpkg")
	invWantAttr(t, zlib, "dpkg_status", "ii")
	invWantAttr(t, zlib, "installed", "true")
	// zlib1g is pulled in as a dependency; the manual list does not name it.
	invWantAttr(t, zlib, "install_reason", "automatic")
	// apt-transport-https is one of the two packages that appear both in the
	// dpkg subset and in the manual list of the fixtures.
	invWantAttr(t, invArtifact(t, res, "os/package/apt-transport-https"), "install_reason", "manual")
	invWantAttr(t, invArtifact(t, res, "os/package/linux-image-6.11.0-17-generic"), "installed", "false")
	if zlib.State != trustfreeze.StateObserved || zlib.Sensitivity != trustfreeze.SensitivityPublic {
		t.Fatalf("state %q sensitivity %q", zlib.State, zlib.Sensitivity)
	}
	if zlib.Digest == "" {
		t.Fatal("artifact digest is empty")
	}
	// Tool versions are recorded, per playbook L7.
	if zlib.Provenance.ToolVersion != "dpkg-query 1.22.6, apt-mark 2.7.14" {
		t.Fatalf("tool version %q", zlib.Provenance.ToolVersion)
	}
	if zlib.Provenance.ObservedAt != trustfreeze.FormatTime(invTestTime) {
		t.Fatalf("observed at %q", zlib.Provenance.ObservedAt)
	}
	snap := invArtifact(t, res, "os/snap/firefox")
	invWantAttr(t, snap, "manager", "snap")
	invWantAttr(t, snap, "revision", "8763")
	invWantAttr(t, snap, "publisher", "mozilla**")
	if snap.Provenance.ToolVersion != "snap 2.76.3" {
		t.Fatalf("snap tool version %q", snap.Provenance.ToolVersion)
	}
	if _, ok := snap.Attributes["notes"]; ok {
		t.Fatalf("a snap without notes must not carry the placeholder: %v", snap.Attributes)
	}
	invWantAttr(t, invArtifact(t, res, "os/snap/code"), "notes", "classic")
	// snap shortens the tracking column, which is recorded once, not per snap.
	if w := invWantWarning(t, res, invDiagValueTruncatedByTool); !strings.Contains(w.Message, "tracking") {
		t.Fatalf("diagnostic %q", w.Message)
	}
	// Every artifact is sorted by id and every tool run is recorded.
	for i := 1; i < len(res.NormalizedState); i++ {
		if res.NormalizedState[i-1].ID >= res.NormalizedState[i].ID {
			t.Fatalf("artifacts are not sorted at %d", i)
		}
	}
	if len(res.Tools) != 6 {
		t.Fatalf("%d tool records, want 6: %+v", len(res.Tools), res.Tools)
	}
	names := invEvidenceNames(evidence)
	for _, want := range []string{"dpkg-query-w.stdout", "apt-mark-showmanual.stdout", "snap-list.stdout", "dpkg-query-version.stdout"} {
		if !invContains(names, want) {
			t.Fatalf("evidence %v does not contain %s", names, want)
		}
	}
}

func TestPackagesProbeWithoutSnapIsNotApplicableForSnaps(t *testing.T) {
	r := probe.NewFakeRunner()
	invScript(t, r, "packages/dpkg-query-w.txt")
	invScript(t, r, "packages/apt-mark-showmanual.txt")
	invScript(t, r, "packages/dpkg-query-version.txt")
	invScript(t, r, "packages/apt-mark-version.txt")
	res, _ := invRun(t, NewPackagesProbe(), r)
	// A host without snapd is a complete answer, not a broken probe.
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s, reason %q", res.Status, res.Reason)
	}
	w := invWantWarning(t, res, probe.DiagFieldNotApplicable)
	if w.Field != "snap" || !strings.Contains(w.Message, "not applicable") {
		t.Fatalf("diagnostic %+v", w)
	}
	if len(res.NormalizedState) != 51 {
		t.Fatalf("%d artifacts, want 51", len(res.NormalizedState))
	}
	for _, a := range res.NormalizedState {
		if strings.HasPrefix(a.ID, ArtifactSnapPrefix) {
			t.Fatalf("snap artifact %s on a host without snap", a.ID)
		}
	}
}

func TestPackagesProbeWithoutAptMarkIsPartial(t *testing.T) {
	r := probe.NewFakeRunner()
	invScript(t, r, "packages/dpkg-query-w.txt")
	invScript(t, r, "packages/dpkg-query-version.txt")
	invScript(t, r, "packages/snap-list.txt")
	invScript(t, r, "packages/snap-version.txt")
	res, _ := invRun(t, NewPackagesProbe(), r)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s, want partial (reason %q)", res.Status, res.Reason)
	}
	w := invWantWarning(t, res, probe.DiagFieldUnavailable)
	if w.Field != "install_reason" {
		t.Fatalf("diagnostic %+v", w)
	}
	if _, ok := invArtifact(t, res, "os/package/apt-transport-https").Attributes["install_reason"]; ok {
		t.Fatal("install_reason must be absent when apt-mark could not be asked, never guessed")
	}
}

// TestPackagesProbeWithoutDpkgIsUnavailable: a missing tool is unavailable and
// never an empty inventory (playbook L1).
func TestPackagesProbeWithoutDpkgIsUnavailable(t *testing.T) {
	p := NewPackagesProbe()
	got := p.Support(context.Background(), probe.HostContext{GOOS: "linux", Runner: probe.NewFakeRunner()})
	if got.Available || got.Status != trustfreeze.StatusUnavailable {
		t.Fatalf("support %+v", got)
	}
	if !strings.Contains(got.Reason, "dpkg-query") {
		t.Fatalf("reason %q", got.Reason)
	}
}

// TestPackagesProbeDeniedDpkgIsPermissionDenied: a tool that is present but
// not executable is permission_denied, never unavailable (playbook L1).
func TestPackagesProbeDeniedDpkgIsPermissionDenied(t *testing.T) {
	r := probe.NewFakeRunner().DenyTool("dpkg-query", "/usr/bin/dpkg-query")
	got := NewPackagesProbe().Support(context.Background(), probe.HostContext{GOOS: "linux", Runner: r})
	if got.Available || got.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("support %+v", got)
	}
}

func TestPackagesProbeUnsupportedPlatform(t *testing.T) {
	got := NewPackagesProbe().Support(context.Background(), probe.HostContext{GOOS: "darwin", Runner: probe.NewFakeRunner()})
	if got.Available || got.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("support %+v", got)
	}
}

// TestPackagesProbeDpkgFailureIsNotAnEmptyInventory uses the real refusal of
// the fixture (exit 1, one line on stderr) on the argv the probe uses.
func TestPackagesProbeDpkgFailureIsNotAnEmptyInventory(t *testing.T) {
	e := invEntry(t, "packages/dpkg-query-w-unknown.stderr.txt")
	if e.ExitCode != 1 {
		t.Fatalf("fixture exit code %d, want 1", e.ExitCode)
	}
	r := probe.NewFakeRunner()
	invScriptRaw(r, "dpkg-query", []string{"-W", DpkgQueryFormat}, probe.FakeResponse{
		Stderr:   invBytes(t, e.Path),
		ExitCode: e.ExitCode,
	})
	res, evidence := invRun(t, NewPackagesProbe(), r)
	if res.Status != trustfreeze.StatusFailed {
		t.Fatalf("status %s, want failed", res.Status)
	}
	if len(res.NormalizedState) != 0 {
		t.Fatalf("%d artifacts on a failed read", len(res.NormalizedState))
	}
	if !strings.Contains(res.Reason, "status 1") {
		t.Fatalf("reason %q does not name the exit code", res.Reason)
	}
	if res.Error == nil {
		t.Fatal("a failed probe must carry an error class")
	}
	if names := invEvidenceNames(evidence); !invContains(names, "dpkg-query-w.stderr") {
		t.Fatalf("the refusal was not kept as evidence: %v", names)
	}
}

// TestPackagesProbeTruncatedOutputIsPartial drives the probe through the
// recording runner the capture engine uses, with an output limit small enough
// to cut the package list.
func TestPackagesProbeTruncatedOutputIsPartial(t *testing.T) {
	limits := probe.Limits{MaxStdoutBytes: 512}
	runner := probe.NewRecordingRunner(invPackagesRunner(t), limits, redact.Default())
	res, _ := invRun(t, NewPackagesProbe(), runner)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s, want partial", res.Status)
	}
	w := invWantWarning(t, res, trustfreeze.DiagOutputTruncated)
	if !strings.Contains(w.Message, "package list is incomplete") {
		t.Fatalf("diagnostic %q", w.Message)
	}
	if len(res.NormalizedState) == 0 || len(res.NormalizedState) >= 51 {
		t.Fatalf("%d artifacts: a cut list must keep what was read and no more", len(res.NormalizedState))
	}
}

func TestPackagesProbeDescriptorAndTools(t *testing.T) {
	p := NewPackagesProbe()
	d := p.Descriptor()
	if err := d.Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if d.ID != "linux.packages" || d.Version != PackagesProbeVersion {
		t.Fatalf("descriptor %+v", d)
	}
	if d.RequiredPrivilege != probe.PrivilegeUser {
		t.Fatalf("privilege %q: the probe must never need elevation (playbook L2)", d.RequiredPrivilege)
	}
	if !reflect.DeepEqual(p.RequiredTools(), []string{"apt-mark", "dpkg-query", "snap"}) {
		t.Fatalf("required tools %q", p.RequiredTools())
	}
	for _, id := range []string{ArtifactPackagePrefix + "zlib1g:amd64", ArtifactSnapPrefix + "firefox"} {
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			t.Fatalf("artifact id %s: %v", id, err)
		}
	}
}

// TestPackagesProbeNeverRunsAnElevationHelper is the code level of playbook L2:
// no tool of this probe is a helper that raises privileges.
func TestPackagesProbeNeverRunsAnElevationHelper(t *testing.T) {
	r := invPackagesRunner(t)
	res, _ := invRun(t, NewPackagesProbe(), r)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s", res.Status)
	}
	for _, call := range r.Calls() {
		switch call.Executable {
		case "sudo", "doas", "pkexec", "run0", "su", "runuser":
			t.Fatalf("the probe called the elevation helper %q", call.Executable)
		}
		for _, a := range call.Args {
			if strings.Contains(a, "sudo ") {
				t.Fatalf("an argument looks like a shell line: %q", a)
			}
		}
	}
}

// TestInventoryDiagnosticsAreBounded pins the volume rule of playbook L6: a
// tool output with thousands of unreadable records must not produce thousands
// of diagnostics.
func TestInventoryDiagnosticsAreBounded(t *testing.T) {
	var in bytes.Buffer
	for i := 0; i < invMaxIssueDiagnostics*3; i++ {
		in.WriteString("broken\n")
	}
	c := invNewCollector(context.Background(), probe.CollectContext{})
	_, issues := ParseDpkgQuery(in.Bytes())
	c.addIssues("dpkg-query", issues)
	if len(c.warnings) != invMaxIssueDiagnostics+1 {
		t.Fatalf("%d diagnostics for %d unparsed records, want %d", len(c.warnings), len(issues), invMaxIssueDiagnostics+1)
	}
	last := c.warnings[len(c.warnings)-1].Message
	if !strings.Contains(last, "not listed individually") {
		t.Fatalf("the last diagnostic does not account for the rest: %q", last)
	}
	if len(c.partial) == 0 {
		t.Fatal("unparsed records must cap the probe at partial")
	}
}

func TestInvJoinNames(t *testing.T) {
	names := []string{"a", "b", "c"}
	if got, dropped := invJoinNames(names, 3); got != "a,b,c" || dropped != 0 {
		t.Fatalf("joined %q dropped %d", got, dropped)
	}
	if got, dropped := invJoinNames(names, 2); got != "a,b" || dropped != 1 {
		t.Fatalf("joined %q dropped %d", got, dropped)
	}
}

// An artifact id is text, but dpkg-query output is bytes. A mutation battery
// turned one byte of a package name into an invalid UTF-8 sequence, and the id
// os/package/ac\xff\xfecountsservice reached a bundle. A record whose name is
// not valid UTF-8 is an unparsable record: it is reported as record_unparsed,
// it caps the probe at partial, and it yields no artifact.
func TestPackagesProbeRejectsNonUTF8PackageName(t *testing.T) {
	const broken = "ac\xff\xfecountsservice"
	r := probe.NewFakeRunner()
	invScriptRaw(r, "dpkg-query", []string{"-W", DpkgQueryFormat}, probe.FakeResponse{
		Stdout: []byte(broken + "\t23.13.9-2ubuntu6.1\tamd64\tii \nok-package\t1.0\tamd64\tii \n"),
	})
	invScript(t, r, "packages/apt-mark-showmanual.txt")
	invScript(t, r, "packages/dpkg-query-version.txt")
	invScript(t, r, "packages/apt-mark-version.txt")
	res, _ := invRun(t, NewPackagesProbe(), r)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s, want partial: warnings %+v", res.Status, res.Warnings)
	}
	w := invWantWarning(t, res, invDiagRecordUnparsed)
	if !strings.Contains(w.Message, "line 1") || !strings.Contains(w.Message, "UTF-8") {
		t.Errorf("diagnostic %q names neither the line nor the reason", w.Message)
	}
	if invHasArtifact(res, "os/package/"+broken) {
		t.Error("the broken name reached an artifact id")
	}
	for _, a := range res.NormalizedState {
		if !utf8.ValidString(a.ID) {
			t.Errorf("artifact id %q is not valid UTF-8", a.ID)
		}
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			t.Errorf("artifact id %q: %v", a.ID, err)
		}
	}
	// The intact record of the same output still becomes an artifact: one bad
	// record is dropped, the inventory is not.
	invWantAttr(t, invArtifact(t, res, "os/package/ok-package"), "version", "1.0")
}
