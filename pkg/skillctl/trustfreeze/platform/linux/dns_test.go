package linux

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// The fixtures under testdata/dns are transcribed from two real Ubuntu hosts
// and sanitized, with one composed file that says so in testdata/README.md.
// The tests below run on any operating system: every command goes through the
// fake runner and every file through the fake file reader (SPEC-0467 R9).

// dnsRunner scripts the two calls of the resolver probe with the fixtures of
// one host class. suffix is "" for the trial host (systemd 255) and "-2204"
// for the bastion (systemd 249).
func dnsRunner(t *testing.T, suffix string) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().AddTool(DNSTool, "/usr/bin/resolvectl").
		WithSearchDirs("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/snap/bin").
		Script(DNSTool, []string{"--version"}, probe.FakeResponse{
			Stdout: netFixture(t, "dns/resolvectl-version"+suffix+".txt")}).
		Script(DNSTool, []string{"status", "--no-pager"}, probe.FakeResponse{
			Stdout: netFixture(t, "dns/resolvectl-status"+suffix+".txt")})
}

// dnsFiles is the declared state of a stock systemd-resolved host.
func dnsFiles(t *testing.T) probe.FakeFiles {
	t.Helper()
	return probe.FakeFiles{Files: map[string][]byte{
		DNSResolvConfPath: netFixture(t, "dns/resolv-conf-stub.txt"),
	}}
}

// dnsTestCollect builds a collect context with a runner and a file reader.
// The runner is handed over as it is, so a fake that reports the directories
// it resolves bare names in still reports them to the probe.
func dnsTestCollect(runner probe.CommandRunner, files probe.FileReader) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(DNSProbeID, probe.Limits{})
	host := netTestHost(runner)
	host.Files = files
	return probe.CollectContext{
		HostContext: host,
		ProbeID:     DNSProbeID,
		Redactor:    redact.Default(),
		Evidence:    ev,
		Support:     probe.Supported(),
	}, ev
}

// dnsLinkByName returns the parsed link, or fails.
func dnsLinkByName(t *testing.T, s ResolverStatus, name string) ResolverScope {
	t.Helper()
	for _, l := range s.Links {
		if l.Name == name {
			return l
		}
	}
	var names []string
	for _, l := range s.Links {
		names = append(names, l.Name)
	}
	t.Fatalf("no link %q; got %v", name, names)
	return ResolverScope{}
}

// TF06-R3: the resolver of the trial host as systemd 255 printed it. The
// alignment of this output is a document-wide constant, which is one of the
// two reasons nothing here is read by column.
func TestParseResolvectlStatusTrialFixture(t *testing.T) {
	st, diags := ParseResolvectlStatus(netFixture(t, "dns/resolvectl-status.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if st.ResolvConfMode != "stub" {
		t.Errorf("resolv.conf mode %q, want stub", st.ResolvConfMode)
	}
	if st.Global.DNSSECMode != "no" || st.Global.DNSSECSupport != "unsupported" {
		t.Errorf("global DNSSEC %q/%q", st.Global.DNSSECMode, st.Global.DNSSECSupport)
	}
	if st.Global.DNSOverTLS != dnsNo || st.Global.LLMNR != dnsNo || st.Global.MDNS != dnsNo {
		t.Errorf("global protocols %+v", st.Global)
	}
	if len(st.Links) != 4 {
		t.Fatalf("%d links, want 4", len(st.Links))
	}
	up := dnsLinkByName(t, st, "enp5s0")
	if !slices.Equal(up.Scopes, []string{"DNS"}) || up.ScopesNone {
		t.Errorf("the resolving link %+v", up)
	}
	if up.CurrentDNSServer != "203.0.113.254" || !slices.Equal(up.DNSServers, []string{"203.0.113.254"}) {
		t.Errorf("the resolving link %+v", up)
	}
	if up.DefaultRoute != dnsYes {
		t.Errorf("the resolving link is not the default route link: %+v", up)
	}
	// A container bridge resolves nothing, and "none" is a value, not a gap.
	quiet := dnsLinkByName(t, st, "docker0")
	if !quiet.ScopesNone || len(quiet.Scopes) != 0 || quiet.DefaultRoute != dnsNo {
		t.Errorf("the quiet link %+v", quiet)
	}
}

// The second host class, and the reason there are two: systemd 249 aligns the
// labels per block, so the same label is indented differently in two blocks of
// one output. A parser that counted characters would read one block and miss
// the next.
func TestParseResolvectlStatusBastionFixture(t *testing.T) {
	st, diags := ParseResolvectlStatus(netFixture(t, "dns/resolvectl-status-2204.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if st.ResolvConfMode != "stub" {
		t.Errorf("resolv.conf mode %q", st.ResolvConfMode)
	}
	if len(st.Links) != 4 {
		t.Fatalf("%d links, want 4", len(st.Links))
	}
	up := dnsLinkByName(t, st, "enp2s0")
	if up.CurrentDNSServer != "198.51.100.254" || up.LLMNR != dnsYes {
		t.Errorf("the resolving link %+v", up)
	}
	// This block is the one whose labels sit at another column than the
	// block above it.
	quiet := dnsLinkByName(t, st, "wlo1")
	if !quiet.ScopesNone || quiet.LLMNR != dnsYes || quiet.DefaultRoute != dnsNo {
		t.Errorf("the quiet link %+v", quiet)
	}
}

// The composed fixture: several links, several servers, search domains, a
// routing-only domain and the DNSSEC and DNSOverTLS modes neither real host
// had. testdata/README.md says which half of this file was measured.
func TestParseResolvectlStatusMultipleServersAndDomains(t *testing.T) {
	st, diags := ParseResolvectlStatus(netFixture(t, "dns/resolvectl-status-multilink.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diags)
	}
	if st.ResolvConfMode != "foreign" {
		t.Errorf("resolv.conf mode %q, want foreign", st.ResolvConfMode)
	}
	if st.Global.DNSSECMode != "yes" || st.Global.DNSOverTLS != dnsYes {
		t.Errorf("global %+v", st.Global)
	}
	if !slices.Equal(st.Global.DNSServers, []string{"203.0.113.53"}) {
		t.Errorf("global servers %v", st.Global.DNSServers)
	}
	first := dnsLinkByName(t, st, "eth0")
	if !slices.Equal(first.DNSServers, []string{"203.0.113.53", "203.0.113.54", "2001:db8::53"}) {
		t.Errorf("link servers %v", first.DNSServers)
	}
	if !slices.Equal(first.SearchDomains, []string{"example.", "internal.example."}) {
		t.Errorf("search domains %v", first.SearchDomains)
	}
	// "~." is not a search domain: it routes every query to this link. Folding
	// the two together would turn a routing rule into a name suffix.
	if !slices.Equal(first.RoutingOnlyDomains, []string{"~."}) {
		t.Errorf("routing only domains %v", first.RoutingOnlyDomains)
	}
	if !slices.Equal(first.Scopes, []string{"DNS", "LLMNR/IPv4", "LLMNR/IPv6"}) {
		t.Errorf("scopes %v", first.Scopes)
	}
	second := dnsLinkByName(t, st, "eth1")
	if second.DNSSECMode != "allow-downgrade" || second.DNSSECSupport != "supported" {
		t.Errorf("link DNSSEC %q/%q", second.DNSSECMode, second.DNSSECSupport)
	}
	if second.DNSOverTLS != dnsNo {
		t.Errorf("link DNSOverTLS %q", second.DNSOverTLS)
	}
}

// A label a newer systemd prints and this build does not record is named, so
// the gap is visible. It is not a parse failure: the fields the probe declares
// were all read.
func TestParseResolvectlStatusNamesAnUnreadLabel(t *testing.T) {
	st, diags := ParseResolvectlStatus([]byte(
		"Global\n         Protocols: -LLMNR\nFallback DNS Servers: 203.0.113.53\n  resolv.conf mode: stub\n"))
	if len(diags) != 0 {
		t.Fatalf("an unread label produced a diagnostic of its own: %v", diags)
	}
	if !slices.Equal(st.UnreadLabels, []string{"Fallback DNS Servers"}) {
		t.Fatalf("unread labels %v", st.UnreadLabels)
	}
	if st.ResolvConfMode != "stub" {
		t.Errorf("the line after the unread one was lost: %q", st.ResolvConfMode)
	}
}

// A line that belongs to no block, and a link header without a name: both are
// records the parser could not place, and both are reported.
func TestParseResolvectlStatusReportsUnplaceableLines(t *testing.T) {
	st, diags := ParseResolvectlStatus([]byte("DNS Servers: 203.0.113.53\n\nLink 2 ()\n"))
	if len(diags) != 2 {
		t.Fatalf("diagnostics %v, want two", diags)
	}
	for _, d := range diags {
		if d.Code != netDiagRecordUnparsed {
			t.Errorf("diagnostic code %q", d.Code)
		}
	}
	if len(st.Links) != 0 {
		t.Errorf("a link without a name became an artifact: %+v", st.Links)
	}
}

// The declared half: the stub file both measured hosts carry, byte for byte
// the same on Ubuntu 22.04 and 24.04.
func TestParseResolvConfStub(t *testing.T) {
	conf, diags := ParseResolvConf(netFixture(t, "dns/resolv-conf-stub.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if !slices.Equal(conf.Nameservers, []string{dnsStubAddress}) {
		t.Errorf("nameservers %v", conf.Nameservers)
	}
	if !conf.StubResolver {
		t.Error("a file naming 127.0.0.53 does not report the stub resolver")
	}
	if !slices.Equal(conf.SearchDomains, []string{"."}) || conf.SearchFrom != "search" {
		t.Errorf("search %v from %q", conf.SearchDomains, conf.SearchFrom)
	}
	if !slices.Equal(conf.Options, []string{"edns0", "trust-ad"}) {
		t.Errorf("options %v", conf.Options)
	}
}

// The uplink form of the same file, which systemd-resolved writes beside the
// stub one: it names the real server and is therefore not a stub file.
func TestParseResolvConfUplink(t *testing.T) {
	conf, diags := ParseResolvConf(netFixture(t, "dns/resolv-conf-uplink.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diags)
	}
	if !slices.Equal(conf.Nameservers, []string{"203.0.113.254"}) {
		t.Errorf("nameservers %v", conf.Nameservers)
	}
	if conf.StubResolver {
		t.Error("a file naming an uplink server reports the stub resolver")
	}
}

// A host without systemd-resolved: the file is the whole declared state, with
// several servers and a search list.
func TestParseResolvConfStatic(t *testing.T) {
	conf, diags := ParseResolvConf(netFixture(t, "dns/resolv-conf-static.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diags)
	}
	if !slices.Equal(conf.Nameservers, []string{"203.0.113.53", "198.51.100.53"}) {
		t.Errorf("nameservers %v", conf.Nameservers)
	}
	if !slices.Equal(conf.SearchDomains, []string{"lab.example", "internal.lab.example"}) {
		t.Errorf("search domains %v", conf.SearchDomains)
	}
	if !slices.Equal(conf.Options, []string{"timeout:2", "attempts:3", "rotate"}) {
		t.Errorf("options %v", conf.Options)
	}
	if conf.StubResolver {
		t.Error("a static file reports the stub resolver")
	}
}

// resolv.conf(5): search and domain are mutually exclusive and the last
// instance wins. A parser that merged them would report a search list the
// resolver never uses.
func TestParseResolvConfSearchAndDomainLastWins(t *testing.T) {
	conf, _ := ParseResolvConf([]byte("search a.example b.example\ndomain c.example\n"))
	if !slices.Equal(conf.SearchDomains, []string{"c.example"}) || conf.SearchFrom != "domain" {
		t.Errorf("domain after search: %v from %q", conf.SearchDomains, conf.SearchFrom)
	}
	conf, _ = ParseResolvConf([]byte("domain c.example\nsearch a.example b.example\n"))
	if !slices.Equal(conf.SearchDomains, []string{"a.example", "b.example"}) || conf.SearchFrom != "search" {
		t.Errorf("search after domain: %v from %q", conf.SearchDomains, conf.SearchFrom)
	}
}

// A comment, a directive without a value and a directive this build does not
// record: three different things, and only the middle one is a broken line.
func TestParseResolvConfCommentsAndUnknownDirectives(t *testing.T) {
	conf, diags := ParseResolvConf([]byte(
		"# a comment\n; another one\nsortlist 203.0.113.0/24\nnameserver\nnameserver 203.0.113.53\n"))
	if !slices.Equal(conf.Nameservers, []string{"203.0.113.53"}) {
		t.Errorf("nameservers %v", conf.Nameservers)
	}
	codes := map[string]int{}
	for _, d := range diags {
		codes[d.Code]++
	}
	if codes[dnsDiagDirectiveUnread] != 1 || codes[netDiagRecordUnparsed] != 1 {
		t.Fatalf("diagnostics %v", diags)
	}
}

// The whole probe over the trial host fixtures.
func TestDNSProbeCapturedOnTheTrialFixtures(t *testing.T) {
	cc, ev := dnsTestCollect(dnsRunner(t, ""), dnsFiles(t))
	res := NewDNSProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q, warnings %v)", res.Status, res.Reason, res.Warnings)
	}
	global := netArtifact(t, res, ArtifactDNSResolver)
	if global.State != trustfreeze.StateObserved {
		t.Errorf("the resolver artifact is %q, want observed", global.State)
	}
	for k, v := range map[string]string{
		"resolv_conf_mode":     "stub",
		"dnssec_mode":          "no",
		"dnssec_support":       "unsupported",
		"dns_over_tls":         dnsNo,
		"link_count":           "4",
		"resolving_link_count": "1",
	} {
		if global.Attributes[k] != v {
			t.Errorf("resolver attribute %s is %q, want %q", k, global.Attributes[k], v)
		}
	}
	link := netArtifact(t, res, "dns/link/enp5s0")
	if link.Attributes["current_dns_server"] != "203.0.113.254" || link.Attributes["resolves"] != "true" {
		t.Errorf("link attributes %v", link.Attributes)
	}
	if link.Attributes["dns_servers"] != "203.0.113.254" || link.Attributes["server_count"] != "1" {
		t.Errorf("link attributes %v", link.Attributes)
	}
	// The link index resolvectl prints beside the name is not recorded: a
	// recreated veth gets a new index without the host changing.
	if _, ok := link.Attributes["link_index"]; ok {
		t.Errorf("the link artifact records the volatile link index: %v", link.Attributes)
	}
	file := netArtifact(t, res, ArtifactDNSResolvConf)
	if file.State != trustfreeze.StateDeclared {
		t.Errorf("the resolv.conf artifact is %q, want declared", file.State)
	}
	if file.Attributes["systemd_resolved_stub"] != "true" || file.Attributes["read"] != "true" {
		t.Errorf("resolv.conf attributes %v", file.Attributes)
	}
	if !strings.Contains(global.Provenance.ToolVersion, "systemd 255") {
		t.Errorf("tool version %q", global.Provenance.ToolVersion)
	}
	names := netEvidenceNames(ev)
	for _, want := range []string{"resolv.conf.txt", "resolvectl-status.txt"} {
		if !slices.Contains(names, want) {
			t.Errorf("evidence %v does not carry %q", names, want)
		}
	}
}

// Playbook L3, and the reason this probe exists at all: the file is declared
// and the runtime state is observed, and neither artifact carries the other's
// values. On this host the two disagree on purpose, because the file names the
// local stub and resolvectl names the uplink the stub forwards to.
func TestDNSProbeNeverMixesDeclaredAndObserved(t *testing.T) {
	cc, _ := dnsTestCollect(dnsRunner(t, ""), dnsFiles(t))
	res := NewDNSProbe().Collect(context.Background(), cc)

	file := netArtifact(t, res, ArtifactDNSResolvConf)
	if file.State != trustfreeze.StateDeclared {
		t.Fatalf("the file artifact is %q", file.State)
	}
	for k, v := range file.Attributes {
		if strings.Contains(v, "203.0.113.254") {
			t.Errorf("the declared artifact carries the observed uplink server in %s: %q", k, v)
		}
	}
	link := netArtifact(t, res, "dns/link/enp5s0")
	if link.State != trustfreeze.StateObserved {
		t.Fatalf("the link artifact is %q", link.State)
	}
	for k, v := range link.Attributes {
		if strings.Contains(v, dnsStubAddress) {
			t.Errorf("the observed artifact carries the declared stub address in %s: %q", k, v)
		}
	}
	// The one attribute that says something about the file sits on the file
	// artifact, not on the resolver one.
	if _, ok := netArtifact(t, res, ArtifactDNSResolver).Attributes["systemd_resolved_stub"]; ok {
		t.Error("the observed artifact judges the declared file")
	}
}

// A host without systemd-resolved is the file only, with state declared and a
// diagnostic saying why. The reason names the directories that were searched,
// because a failed lookup cannot tell a host without the tool from a host
// whose tool is elsewhere.
func TestDNSProbeWithoutResolvectlIsTheDeclaredFileOnly(t *testing.T) {
	dirs := []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/snap/bin"}
	runner := probe.NewFakeRunner().WithSearchDirs(dirs...)
	cc, _ := dnsTestCollect(runner, dnsFiles(t))
	res := NewDNSProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	ids := netArtifactIDs(res)
	if !slices.Equal(ids, []string{ArtifactDNSResolvConf}) {
		t.Fatalf("artifacts %v, want the declared file alone", ids)
	}
	file := netArtifact(t, res, ArtifactDNSResolvConf)
	if file.State != trustfreeze.StateDeclared {
		t.Errorf("the file artifact is %q, want declared", file.State)
	}
	w := tfWarning(t, res, dnsDiagResolverUnknown)
	for _, dir := range dirs {
		if !strings.Contains(w.Message, dir) {
			t.Errorf("the diagnostic does not name the searched directory %s: %q", dir, w.Message)
		}
	}
	if strings.Contains(w.Message, "has no resolver") {
		t.Errorf("the diagnostic claims the host has no resolver: %q", w.Message)
	}
}

// Measured on both hosts on 2026-09-24, and the reason this probe never asks
// for JSON: systemd 249 refuses "--json=short" with exit 1, and systemd 255
// accepts the flag and prints the same human text with exit 0. An accepted
// flag is therefore no evidence of a JSON answer, so the probe must not send
// one and then decode what comes back as JSON.
func TestDNSProbeDoesNotAskForJSON(t *testing.T) {
	runner := dnsRunner(t, "")
	cc, _ := dnsTestCollect(runner, dnsFiles(t))
	if res := NewDNSProbe().Collect(context.Background(), cc); res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q", res.Status)
	}
	for _, call := range runner.Calls() {
		for _, arg := range call.Args {
			if strings.Contains(arg, "--json") {
				t.Fatalf("the probe asked for JSON: %s %v", call.Executable, call.Args)
			}
		}
	}
	// The refusal of the older host is kept as a fixture so that the reason
	// above stays checkable, and the shape stays the shape that was measured.
	stderr := string(netFixture(t, "dns/resolvectl-json-unsupported.stderr.txt"))
	if !strings.Contains(stderr, "unrecognized option") || !strings.Contains(stderr, "--json=short") {
		t.Fatalf("the recorded refusal does not name the rejected option: %q", stderr)
	}
}

// resolvectl exits non-zero when systemd-resolved does not answer its bus
// call, which is the shape of a host where the service is installed but not
// running. No observed artifact, the declared file still read, and the status
// says the observed half is missing.
func TestDNSProbeResolvectlFailureKeepsTheDeclaredFile(t *testing.T) {
	runner := dnsRunner(t, "").Script(DNSTool, []string{"status", "--no-pager"}, probe.FakeResponse{
		Stderr:   []byte("Failed to get global data: Could not activate remote peer.\n"),
		ExitCode: 1,
	})
	cc, _ := dnsTestCollect(runner, dnsFiles(t))
	res := NewDNSProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	if slices.Contains(netArtifactIDs(res), ArtifactDNSResolver) {
		t.Fatalf("a failed status call still produced an observed artifact: %v", netArtifactIDs(res))
	}
	if !slices.Contains(netArtifactIDs(res), ArtifactDNSResolvConf) {
		t.Fatalf("the declared file was dropped over a failed command: %v", netArtifactIDs(res))
	}
	w := tfWarning(t, res, dnsDiagResolverUnknown)
	if !strings.Contains(w.Message, "Could not activate remote peer") {
		t.Errorf("the diagnostic does not name the cause: %q", w.Message)
	}
}

// A file the account may not read is permission_denied, never an empty
// configuration. The artifact still names the path that was asked for, so the
// bundle says what is missing instead of leaving it out.
//
// The refusal shape is real: on the trial host /run/systemd/resolve/netif is
// mode 0700 and owned by systemd-resolve, and an unprivileged read of a file
// under it answers "Permission denied" exactly like this.
func TestDNSProbeUnreadableResolvConfIsPermissionDenied(t *testing.T) {
	files := probe.FakeFiles{Errs: map[string]error{DNSResolvConfPath: fs.ErrPermission}}
	cc, _ := dnsTestCollect(dnsRunner(t, ""), files)
	res := NewDNSProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q, want permission_denied (reason %q)", res.Status, res.Reason)
	}
	if res.Error == nil || res.Error.Class != probe.ClassPermissionDenied {
		t.Fatalf("error %+v", res.Error)
	}
	file := netArtifact(t, res, ArtifactDNSResolvConf)
	if file.State != trustfreeze.StateUnknown {
		t.Errorf("an unread file is %q, want unknown", file.State)
	}
	if file.Attributes["read"] != "false" || file.Attributes["path"] != DNSResolvConfPath {
		t.Errorf("attributes %v", file.Attributes)
	}
	if _, ok := file.Attributes["nameservers"]; ok {
		t.Errorf("an unread file produced nameservers: %v", file.Attributes)
	}
	// The observed half was read and stays in the bundle.
	if !slices.Contains(netArtifactIDs(res), ArtifactDNSResolver) {
		t.Errorf("the observed state was dropped over an unreadable file: %v", netArtifactIDs(res))
	}
}

// The declared state of both measured hosts is reachable only through a
// symlink: /etc/resolv.conf points at ../run/systemd/resolve/stub-resolv.conf,
// and probe.RootedFileReader checks the RESOLVED path against its roots too.
// This test measures the mechanism that makes the one-file root list enough,
// under a temporary directory and without touching any real path, and it is
// the guard that keeps the root list from being widened to the whole resolver
// run directory on a guess.
func TestDNSAllowedRootsCoverTheSymlinkTarget(t *testing.T) {
	if !slices.Equal(DNSAllowedRoots(), []string{DNSResolvConfPath}) {
		t.Fatalf("roots %v, want the one file", DNSAllowedRoots())
	}
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	run := filepath.Join(dir, "run", "systemd", "resolve")
	for _, d := range []string{etc, run} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(run, "stub-resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver "+dnsStubAddress+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(etc, "resolv.conf")
	if err := os.Symlink(filepath.Join("..", "run", "systemd", "resolve", "stub-resolv.conf"), link); err != nil {
		t.Fatal(err)
	}
	// Rooted at the symlink itself: the reader resolves it once, at
	// construction, and reads through it.
	b, err := probe.NewRootedFileReader([]string{link}, 0).ReadFile(link)
	if err != nil {
		t.Fatalf("a reader rooted at the symlink could not read through it: %v", err)
	}
	if conf, _ := ParseResolvConf(b); !conf.StubResolver {
		t.Errorf("the file read through the symlink did not parse: %q", b)
	}
	// Rooted somewhere else: the target is outside the allowed set and the
	// read is refused, which is what keeps the root list meaningful.
	if _, err := probe.NewRootedFileReader([]string{etc + "-other"}, 0).ReadFile(link); err == nil {
		t.Fatal("a reader rooted elsewhere read the file")
	}
}

// On Linux the probe is available even without resolvectl, because the
// declared state is a file. On another operating system it is unsupported.
func TestDNSProbeSupport(t *testing.T) {
	host := netTestHost(probe.NewFakeRunner())
	if res := NewDNSProbe().Support(context.Background(), host); !res.Available {
		t.Fatalf("unavailable on linux without the tool: %+v", res)
	}
	res := NewDNSProbe().Support(context.Background(), probe.HostContext{GOOS: "windows"})
	if res.Available || res.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("support %+v", res)
	}
}

// Every artifact carries a digest and a valid id, and two runs over the same
// fixtures produce the same bytes (playbook L8).
func TestDNSProbeArtifactsAreWellFormedAndDeterministic(t *testing.T) {
	var digests [2][]string
	for i := range digests {
		cc, _ := dnsTestCollect(dnsRunner(t, ""), dnsFiles(t))
		res := NewDNSProbe().Collect(context.Background(), cc)
		for _, a := range res.NormalizedState {
			if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
				t.Errorf("artifact id %q: %v", a.ID, err)
			}
			if a.Digest == "" {
				t.Errorf("artifact %q has no digest", a.ID)
			}
			if a.Source != DNSProbeID {
				t.Errorf("artifact %q names the source %q", a.ID, a.Source)
			}
			digests[i] = append(digests[i], a.ID+" "+a.Digest)
		}
	}
	if !slices.Equal(digests[0], digests[1]) {
		t.Fatal("two runs over the same fixtures produced different artifacts")
	}
	if !slices.IsSorted(digests[0]) {
		t.Fatalf("the artifacts are not sorted by id: %v", digests[0])
	}
}

// A file the root list of this capture refuses is a GAP IN THE CAPTURE, never a
// property of the host. The trap this guards (review of T-03b, finding 1): the
// refusal used to fold into privNotApplicable, which privStatus counts as read
// and never degrades for, so a probe whose file was never opened reported
// captured with no reason at all.
//
// This host does not reach the case today, and dns.go says why: NewRootedFileReader
// resolves every root, so the /etc/resolv.conf symlink carries its target into the
// root set (TestDNSProbeReadsResolvConfThroughASymlink). The state is still wrong
// where a future root list is narrower than a probe's paths, and a status nobody
// can distinguish from success is the worst kind of wrong.
func TestDNSProbeOutsideRootsDegradesAndNamesTheGap(t *testing.T) {
	files := probe.FakeFiles{Errs: map[string]error{DNSResolvConfPath: probe.ErrOutsideRoots}}
	cc, _ := dnsTestCollect(dnsRunner(t, ""), files)
	res := NewDNSProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial: the declared file was refused by the root list (reason %q)", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "outside the roots") {
		t.Errorf("reason %q does not say that a path lies outside the roots", res.Reason)
	}
	var named bool
	for _, w := range res.Warnings {
		if w.Code == privDiagOutsideRoots && strings.Contains(w.Message, DNSResolvConfPath) {
			named = true
		}
		if w.Code == probe.DiagFieldNotApplicable {
			t.Errorf("a root list refusal is reported as not_applicable: %q", w.Message)
		}
	}
	if !named {
		t.Errorf("no %s diagnostic names %s; warnings %v", privDiagOutsideRoots, DNSResolvConfPath, res.Warnings)
	}
	// The observed half was read, so the bundle still carries it: a refused
	// file degrades the status, it does not throw away what was measured.
	file := netArtifact(t, res, ArtifactDNSResolvConf)
	if file.Attributes["read"] != "false" || file.State != trustfreeze.StateUnknown {
		t.Errorf("the resolv.conf artifact is %q with attributes %v", file.State, file.Attributes)
	}
	if got := netArtifact(t, res, ArtifactDNSResolver).State; got != trustfreeze.StateObserved {
		t.Errorf("the observed resolver artifact is %q, want observed", got)
	}
}
