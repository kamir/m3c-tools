package linux

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// The fixtures under testdata/routes are transcribed from two real Ubuntu
// hosts and sanitized; testdata/README.md names the host class, the tool
// versions and every substitution. The tests below run on any operating
// system, because every tool call goes through the fake runner (SPEC-0467 R9).

// routesRunner scripts the four calls of the routing probe with the fixtures
// of one host class. suffix is "" for the trial host (iproute2 6.1.0) and
// "-2204" for the bastion (iproute2 5.15.0).
func routesRunner(t *testing.T, suffix string) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().AddTool(RoutesTool, "/usr/sbin/ip").
		WithSearchDirs("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/snap/bin").
		Script(RoutesTool, []string{"-V"}, probe.FakeResponse{
			Stdout: netFixture(t, "routes/ip-version"+suffix+".txt")}).
		Script(RoutesTool, []string{"-j", "route", "show"}, probe.FakeResponse{
			Stdout: netFixture(t, "routes/ip-j-route-show"+suffix+".json")}).
		Script(RoutesTool, []string{"-6", "-j", "route", "show"}, probe.FakeResponse{
			Stdout: netFixture(t, "routes/ip-6-j-route-show"+suffix+".json")}).
		Script(RoutesTool, []string{"-j", "addr", "show"}, probe.FakeResponse{
			Stdout: netFixture(t, "routes/ip-j-addr-show"+suffix+".json")})
}

// routeByID returns the parsed route whose base id matches, or fails.
func routeByID(t *testing.T, routes []Route, id string) Route {
	t.Helper()
	for _, r := range routes {
		if r.BaseArtifactID() == id {
			return r
		}
	}
	var ids []string
	for _, r := range routes {
		ids = append(ids, r.BaseArtifactID())
	}
	t.Fatalf("no route %q; got %v", id, ids)
	return Route{}
}

// TF06-R3: every row of the trial host document is read, and the fields a
// reader of a routing table needs are the ones iproute2 printed.
func TestParseIPRoutesReadsEveryRowOfTheTrialFixture(t *testing.T) {
	routes, diags := ParseIPRoutes(routeFamilyIPv4, netFixture(t, "routes/ip-j-route-show.json"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if len(routes) != 9 {
		t.Fatalf("got %d routes, want 9", len(routes))
	}
	def := routeByID(t, routes, "network/route/ipv4/main/enp5s0/default")
	if !def.IsDefault() {
		t.Error("the default route does not report itself as one")
	}
	if def.Gateway != "203.0.113.254" || def.Device != "enp5s0" || def.Protocol != "dhcp" {
		t.Errorf("default route %+v", def)
	}
	if def.Metric != "100" || def.PreferredSource != "203.0.113.10" || def.Table != routeTableMain {
		t.Errorf("default route %+v", def)
	}
	// A bridge whose cable is down still has a route, and the flag is the
	// only thing that says the route leads nowhere at the moment.
	down := routeByID(t, routes, "network/route/ipv4/main/br-c1c2c3c4c5c6/100.66.0.0/16")
	if !slices.Contains(down.Flags, "linkdown") {
		t.Errorf("the linkdown flag was dropped: %+v", down)
	}
	if down.Scope != "link" || down.Protocol != "kernel" {
		t.Errorf("bridge route %+v", down)
	}
}

// The second host class, and the reason there are two: iproute2 5.15.0 omits
// the protocol field entirely for a route the boot scripts installed, so a
// parser that required the field would drop the row.
func TestParseIPRoutesReadsTheBastionFixture(t *testing.T) {
	routes, diags := ParseIPRoutes(routeFamilyIPv4, netFixture(t, "routes/ip-j-route-show-2204.json"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if len(routes) != 4 {
		t.Fatalf("got %d routes, want 4", len(routes))
	}
	noProto := routeByID(t, routes, "network/route/ipv4/main/enp2s0/169.254.0.0/16")
	if noProto.Protocol != "" {
		t.Errorf("a route without a protocol field invented one: %q", noProto.Protocol)
	}
	if noProto.Metric != "1000" || noProto.Scope != "link" {
		t.Errorf("route without protocol %+v", noProto)
	}
	def := routeByID(t, routes, "network/route/ipv4/main/enp2s0/default")
	if def.Protocol != "static" || def.Gateway != "198.51.100.254" {
		t.Errorf("default route %+v", def)
	}
}

// Four IPv6 routes of the trial host share the destination fe80::/64 and
// differ only in the device, so the device has to be part of the id.
func TestParseIPRoutesIPv6KeepsOneArtifactPerDevice(t *testing.T) {
	routes, diags := ParseIPRoutes(routeFamilyIPv6, netFixture(t, "routes/ip-6-j-route-show.json"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	ids := map[string]bool{}
	linkLocal := 0
	for _, r := range routes {
		if ids[r.BaseArtifactID()] {
			t.Fatalf("two IPv6 routes share the id %q", r.BaseArtifactID())
		}
		ids[r.BaseArtifactID()] = true
		if r.Destination == "fe80::/64" {
			linkLocal++
		}
	}
	if linkLocal != 4 {
		t.Fatalf("%d link-local routes, want 4", linkLocal)
	}
	ula := routeByID(t, routes, "network/route/ipv6/main/br-b1b2b3b4b5b6/2001:db8:1a2b:3c4d::/64")
	if ula.Preference != "medium" || ula.Metric != "256" {
		t.Errorf("IPv6 route %+v", ula)
	}
}

// A genuinely empty result is zero routes and no diagnostic. Measured on both
// hosts: "ip -j route show <prefix not in the table>" prints the two bytes of
// an empty JSON array and exits 0.
func TestParseIPRoutesEmptyDocumentIsZeroRoutes(t *testing.T) {
	routes, diags := ParseIPRoutes(routeFamilyIPv6, netFixture(t, "routes/ip-j-route-show-empty.json"))
	if len(routes) != 0 || len(diags) != 0 {
		t.Fatalf("got %d routes and %v, want zero and none", len(routes), diags)
	}
}

// An aborted dump is a statement about the tool, not about the host. Measured
// on both hosts: iproute2 prints a bare "[" on stdout, the cause on stderr,
// and exits 2. A parser that read stdout alone would report a syntax error.
func TestParseIPRoutesAbortedDumpIsADiagnostic(t *testing.T) {
	routes, diags := ParseIPRoutes(routeFamilyIPv6, netFixture(t, "routes/ip-6-j-route-show-aborted.json"))
	if len(routes) != 0 {
		t.Fatalf("got %d routes out of an aborted dump", len(routes))
	}
	if len(diags) != 1 || diags[0].Code != routeDiagJSONUnreadable {
		t.Fatalf("diagnostics %v, want one %s", diags, routeDiagJSONUnreadable)
	}
}

// A row without a destination or a device cannot be turned into an artifact
// with a stable id, so it is dropped with a diagnostic and the rest survives.
func TestParseIPRoutesDropsARowWithoutIdentity(t *testing.T) {
	routes, diags := ParseIPRoutes(routeFamilyIPv4,
		[]byte(`[{"dst":"default","dev":"eth0"},{"dst":"10.0.0.0/8"},{"dev":"eth1"}]`))
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if len(diags) != 2 {
		t.Fatalf("diagnostics %v, want two", diags)
	}
	for _, d := range diags {
		if d.Code != netDiagRecordUnparsed {
			t.Errorf("diagnostic code %q", d.Code)
		}
	}
}

// TF06-R3: the addresses that give a route its meaning, with the lease state
// of a DHCP address recorded and its countdown deliberately not.
func TestParseIPAddressesReadsTheTrialFixture(t *testing.T) {
	addrs, diags := ParseIPAddresses(netFixture(t, "routes/ip-j-addr-show.json"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	if len(addrs) != 10 {
		t.Fatalf("got %d addresses, want 10", len(addrs))
	}
	byID := map[string]Address{}
	for _, a := range addrs {
		byID[a.ArtifactID()] = a
	}
	lease, ok := byID["network/address/ipv4/enp5s0/203.0.113.10/24"]
	if !ok {
		t.Fatalf("no address of the primary interface; got %v", netSortedKeys(byID))
	}
	if !lease.Dynamic || lease.Permanent {
		t.Errorf("a DHCP address must be dynamic and not permanent: %+v", lease)
	}
	if lease.Scope != "global" || lease.DeviceState != "UP" || lease.Label != "enp5s0" {
		t.Errorf("DHCP address %+v", lease)
	}
	loop, ok := byID["network/address/ipv4/lo/127.0.0.1/8"]
	if !ok {
		t.Fatal("no loopback address")
	}
	if loop.Dynamic || !loop.Permanent {
		t.Errorf("the loopback address must be permanent and not dynamic: %+v", loop)
	}
	// An interface with no address contributes no artifact, and an interface
	// whose carrier is gone still does: the flag carries that fact.
	down, ok := byID["network/address/ipv4/br-c1c2c3c4c5c6/100.66.0.1/16"]
	if !ok {
		t.Fatal("no address of the bridge whose carrier is down")
	}
	if down.DeviceState != "DOWN" || !slices.Contains(down.DeviceFlags, "NO-CARRIER") {
		t.Errorf("bridge address %+v", down)
	}
}

// The bastion carries an interface with an empty addr_info list, which must
// produce no artifact and no diagnostic: an interface without an address is a
// fact, not a parse problem.
func TestParseIPAddressesBastionInterfaceWithoutAddress(t *testing.T) {
	addrs, diags := ParseIPAddresses(netFixture(t, "routes/ip-j-addr-show-2204.json"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for a fixture that parses cleanly: %v", diags)
	}
	devices := map[string]int{}
	for _, a := range addrs {
		devices[a.Device]++
	}
	if devices["eno2"] != 0 || devices["wlo1"] != 0 {
		t.Errorf("an interface without an address produced artifacts: %v", devices)
	}
	if devices["enp2s0"] != 2 || devices["lo"] != 2 || devices["docker0"] != 1 {
		t.Errorf("addresses per device %v", devices)
	}
}

// Two default routes over one interface that differ in metric and gateway.
// Neither of them may be dropped, the ids must stay distinct and deterministic,
// and the id must be built from the GATEWAY: the metric is volatile.
func TestRouteDisambiguateKeepsEveryRoute(t *testing.T) {
	routes := []Route{
		{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Metric: "100", Gateway: "203.0.113.254"},
		{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Metric: "200", Gateway: "203.0.113.2"},
		{Family: routeFamilyIPv4, Destination: "192.0.2.0/24", Device: "eth0", Table: routeTableMain},
	}
	ids, collisions, metricIDs := routeDisambiguate(routes)
	if len(collisions) != 1 || collisions[0] != "network/route/ipv4/main/eth0/default" {
		t.Fatalf("collisions %v", collisions)
	}
	if len(metricIDs) != 0 {
		t.Errorf("the gateway told these routes apart, so no id needs the metric: %v", metricIDs)
	}
	if ids[0] == ids[1] {
		t.Fatalf("the colliding routes kept one id: %q", ids[0])
	}
	for i, want := range []string{
		"network/route/ipv4/main/eth0/default/via=203.0.113.254",
		"network/route/ipv4/main/eth0/default/via=203.0.113.2",
		"network/route/ipv4/main/eth0/192.0.2.0/24",
	} {
		if ids[i] != want {
			t.Errorf("id %d is %q, want %q", i, ids[i], want)
		}
		if err := trustfreeze.ValidateArtifactID(ids[i]); err != nil {
			t.Errorf("id %q: %v", ids[i], err)
		}
	}
}

// B5, at the one place it can actually fail: a volatile value must not sit in an
// artifact ID, because compare pairs artifacts by id and no normalization rule
// reaches inside one (review of T-03b, finding 3 of the summary).
//
// The measured case is a DHCP metric that moves while the routes stay: the ids
// must be the same before and after. Where the metric is the ONLY thing the
// kernel keeps two routes apart by, it has to go into the id or the two routes
// collapse into one, and then a diagnostic says so instead of the drift being a
// surprise.
func TestRouteIDIsStableWhenTheMetricMoves(t *testing.T) {
	before := []Route{
		{Family: routeFamilyIPv4, Destination: "default", Device: "enp5s0", Table: routeTableMain, Metric: "100", Gateway: "203.0.113.254", Protocol: "dhcp"},
		{Family: routeFamilyIPv4, Destination: "default", Device: "enp5s0", Table: routeTableMain, Metric: "600", Gateway: "203.0.113.9", Protocol: "static"},
	}
	after := []Route{
		{Family: routeFamilyIPv4, Destination: "default", Device: "enp5s0", Table: routeTableMain, Metric: "1024", Gateway: "203.0.113.254", Protocol: "dhcp"},
		{Family: routeFamilyIPv4, Destination: "default", Device: "enp5s0", Table: routeTableMain, Metric: "600", Gateway: "203.0.113.9", Protocol: "static"},
	}
	idsBefore, _, metricBefore := routeDisambiguate(before)
	idsAfter, _, metricAfter := routeDisambiguate(after)
	if len(metricBefore) != 0 || len(metricAfter) != 0 {
		t.Fatalf("no id needs the metric here; before %v, after %v", metricBefore, metricAfter)
	}
	for i := range idsBefore {
		if idsBefore[i] != idsAfter[i] {
			t.Errorf("the metric moved and the id of route %d moved with it: %q then %q; compare would report one route removed and one added",
				i, idsBefore[i], idsAfter[i])
		}
		if strings.Contains(idsBefore[i], "metric=") {
			t.Errorf("id %q carries the volatile metric although the gateway tells the routes apart", idsBefore[i])
		}
	}

	// The corner where the metric IS the identity: same gateway, two metrics.
	// The id has to carry it, and the group is reported so a reader knows.
	same := []Route{
		{Family: routeFamilyIPv4, Destination: "default", Device: "enp5s0", Table: routeTableMain, Metric: "100", Gateway: "203.0.113.254"},
		{Family: routeFamilyIPv4, Destination: "default", Device: "enp5s0", Table: routeTableMain, Metric: "1024", Gateway: "203.0.113.254"},
	}
	ids, collisions, metricIDs := routeDisambiguate(same)
	if len(collisions) != 1 || len(metricIDs) != 1 {
		t.Fatalf("collisions %v, metric ids %v", collisions, metricIDs)
	}
	if ids[0] == ids[1] {
		t.Fatalf("both routes kept the id %q", ids[0])
	}
	for _, id := range ids {
		if !strings.Contains(id, "metric=") {
			t.Errorf("id %q does not carry the metric, which is the only thing that tells these two routes apart", id)
		}
	}
}

// Two routes that agree on metric and gateway as well: the position within
// the group is the last thing left, and it is appended to every member, so no
// member silently keeps the shorter id.
func TestRouteDisambiguateBreaksARemainingTie(t *testing.T) {
	routes := []Route{
		{Family: routeFamilyIPv6, Destination: "fe80::/64", Device: "eth0", Table: routeTableMain},
		{Family: routeFamilyIPv6, Destination: "fe80::/64", Device: "eth0", Table: routeTableMain},
	}
	ids, collisions, metricIDs := routeDisambiguate(routes)
	if len(collisions) != 1 {
		t.Fatalf("collisions %v", collisions)
	}
	if len(metricIDs) != 0 {
		t.Errorf("neither route carries a metric, so no id can carry one: %v", metricIDs)
	}
	if ids[0] == ids[1] {
		t.Fatalf("both ids are %q", ids[0])
	}
	for _, id := range ids {
		if id == "network/route/ipv6/main/eth0/fe80::/64" {
			t.Errorf("a member of a colliding group kept the base id: %q", id)
		}
	}
}

// The metric is the value the routing table changes without the host changing,
// so it lives under its own attribute key. The key is a dedicated one rather
// than the generic "metric", because the versioned normalization rule set
// drops attribute keys across every artifact family at once (T-03b playbook
// B5); a shared key would blind some other probe's metric too.
func TestRouteMetricHasItsOwnAttributeKey(t *testing.T) {
	r := Route{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Metric: "100"}
	attrs := routeAttributes(r)
	if attrs["route_metric"] != "100" {
		t.Fatalf("the metric is not under route_metric: %v", attrs)
	}
	if _, ok := attrs["metric"]; ok {
		t.Fatal("the metric is under the generic key metric, which normalization cannot drop safely")
	}
	// The rule set is loaded here so that the day route_metric is added to it,
	// this test says whether the key it drops is the key the probe writes.
	rs, err := compare.LoadRuleSet("")
	if err != nil {
		t.Fatalf("load rule set: %v", err)
	}
	if slices.Contains(rs.VolatileAttributes, "metric") {
		t.Fatal("the rule set drops the generic key metric, which this probe must therefore not use")
	}
}

// The whole probe over the trial host fixtures: the set artifact names the
// default route, the counts are the counts of what was read, and the status is
// captured because every source answered.
func TestRoutesProbeCapturedOnTheTrialFixtures(t *testing.T) {
	cc, ev := netTestCollect(RoutesProbeID, routesRunner(t, ""))
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q, warnings %v)", res.Status, res.Reason, res.Warnings)
	}
	set := netArtifact(t, res, ArtifactRoutes)
	want := map[string]string{
		"ipv4_route_count":         "9",
		"ipv6_route_count":         "5",
		"ipv4_routes_read":         "true",
		"ipv6_routes_read":         "true",
		"ipv4_default_route":       "network/route/ipv4/main/enp5s0/default",
		"ipv4_default_gateway":     "203.0.113.254",
		"ipv4_default_device":      "enp5s0",
		"ipv4_default_route_count": "1",
		"ipv6_default_route":       "none",
		"address_count":            "10",
		"device_count":             "6",
		"tables_queried":           routeTableMain,
		"route_list_capped":        "false",
	}
	for k, v := range want {
		if set.Attributes[k] != v {
			t.Errorf("set attribute %s is %q, want %q", k, set.Attributes[k], v)
		}
	}
	// One artifact per route, one per address, one set.
	if got := len(res.NormalizedState); got != 9+5+10+1 {
		t.Errorf("%d artifacts, want %d", got, 9+5+10+1)
	}
	def := netArtifact(t, res, "network/route/ipv4/main/enp5s0/default")
	if def.Attributes["default_route"] != "true" || def.State != trustfreeze.StateObserved {
		t.Errorf("the default route artifact %+v", def)
	}
	addr := netArtifact(t, res, "network/address/ipv4/enp5s0/203.0.113.10/24")
	if addr.Attributes["address_class"] != ExposureSpecificAddress || addr.Attributes["dynamic"] != "true" {
		t.Errorf("the address artifact %+v", addr.Attributes)
	}
	if addr.Attributes["permanent"] != "false" {
		t.Errorf("a DHCP address claims to be permanent: %v", addr.Attributes)
	}
	for _, k := range []string{"valid_life_time", "preferred_life_time", "lifetime"} {
		if _, ok := addr.Attributes[k]; ok {
			t.Errorf("the address artifact records the lease countdown %q, which changes every second", k)
		}
	}
	// The tool version is recorded, because a parser is valid only for the
	// versions it was measured against (playbook L7).
	if !strings.Contains(def.Provenance.ToolVersion, "iproute2-6.1.0") {
		t.Errorf("tool version %q", def.Provenance.ToolVersion)
	}
	names := netEvidenceNames(ev)
	for _, want := range []string{"ip-6-route-show.json", "ip-addr-show.json", "ip-route-show.json", "ip-version.stdout"} {
		if !slices.Contains(names, want) {
			t.Errorf("evidence %v does not carry %q", names, want)
		}
	}
}

// The second host class through the whole probe, so the fields only it has are
// covered end to end as well.
func TestRoutesProbeCapturedOnTheBastionFixtures(t *testing.T) {
	cc, _ := netTestCollect(RoutesProbeID, routesRunner(t, "-2204"))
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q)", res.Status, res.Reason)
	}
	set := netArtifact(t, res, ArtifactRoutes)
	if set.Attributes["ipv4_route_count"] != "4" || set.Attributes["ipv6_route_count"] != "2" {
		t.Errorf("counts %v", set.Attributes)
	}
	if set.Attributes["ipv6_default_route"] != "none" {
		t.Errorf("a host without an IPv6 default route must say so: %v", set.Attributes)
	}
	if set.Attributes["ipv4_default_gateway"] != "198.51.100.254" {
		t.Errorf("default gateway %v", set.Attributes)
	}
}

// TF06-R3, and the explicit instruction of the T-03b playbook: a host with no
// IPv6 route is captured with zero IPv6 routes. It is never not_applicable,
// because the absence of a route is an answer and not a missing feature.
func TestRoutesProbeNoIPv6RouteIsCapturedWithZero(t *testing.T) {
	runner := routesRunner(t, "").Script(RoutesTool, []string{"-6", "-j", "route", "show"},
		probe.FakeResponse{Stdout: netFixture(t, "routes/ip-j-route-show-empty.json")})
	cc, _ := netTestCollect(RoutesProbeID, runner)
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, want captured (reason %q)", res.Status, res.Reason)
	}
	if res.Status == trustfreeze.StatusNotApplicable {
		t.Fatal("zero IPv6 routes must never be not_applicable")
	}
	set := netArtifact(t, res, ArtifactRoutes)
	if set.Attributes["ipv6_route_count"] != "0" || set.Attributes["ipv6_routes_read"] != "true" {
		t.Errorf("set attributes %v", set.Attributes)
	}
	if set.Attributes["ipv6_default_route"] != "none" {
		t.Errorf("set attributes %v", set.Attributes)
	}
}

// The other half of the same question: a call that did NOT answer must not
// leave a zero behind. An unread family has no count at all, so an aborted
// dump can never be read as an empty table (playbook L1).
func TestRoutesProbeUnreadIPv6FamilyRecordsNoCount(t *testing.T) {
	runner := routesRunner(t, "").Script(RoutesTool, []string{"-6", "-j", "route", "show"},
		probe.FakeResponse{
			Stdout:   netFixture(t, "routes/ip-6-j-route-show-aborted.json"),
			Stderr:   netFixture(t, "routes/ip-6-j-route-show-aborted.stderr.txt"),
			ExitCode: 2,
		})
	cc, _ := netTestCollect(RoutesProbeID, runner)
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	if res.Reason == "" {
		t.Fatal("a partial result must say what is missing")
	}
	set := netArtifact(t, res, ArtifactRoutes)
	if _, ok := set.Attributes["ipv6_route_count"]; ok {
		t.Errorf("an unread family got a count: %v", set.Attributes)
	}
	if set.Attributes["ipv6_routes_read"] != "false" {
		t.Errorf("set attributes %v", set.Attributes)
	}
	if set.Attributes["ipv4_route_count"] != "9" {
		t.Errorf("the family that did answer lost its count: %v", set.Attributes)
	}
}

// A tool that exits non-zero with a message rather than a document: the status
// carries the failure and the family stays unread.
func TestRoutesProbeFailedCallIsPartial(t *testing.T) {
	runner := routesRunner(t, "").Script(RoutesTool, []string{"-j", "addr", "show"},
		probe.FakeResponse{
			Stderr:   netFixture(t, "routes/ip-route-show-nosuchdev.stderr.txt"),
			ExitCode: 1,
		})
	cc, _ := netTestCollect(RoutesProbeID, runner)
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	set := netArtifact(t, res, ArtifactRoutes)
	if set.Attributes["address_list_read"] != "false" {
		t.Errorf("set attributes %v", set.Attributes)
	}
	if _, ok := set.Attributes["address_count"]; ok {
		t.Errorf("an unread address list got a count: %v", set.Attributes)
	}
}

// A refused start of the tool is permission_denied, never unavailable and
// never an empty routing table. No refusal of "ip route show" was measured on
// either host, because reading the routing table needs no privileges; the
// refusal is therefore simulated at the runner, which is where the OS reports
// it.
func TestRoutesProbeRefusedToolIsPermissionDenied(t *testing.T) {
	runner := probe.NewFakeRunner().AddTool(RoutesTool, "/usr/sbin/ip").
		Script(RoutesTool, []string{"-V"}, probe.FakeResponse{PermissionDenied: true, ErrMessage: "permission denied"}).
		Script(RoutesTool, []string{"-j", "route", "show"}, probe.FakeResponse{PermissionDenied: true, ErrMessage: "permission denied"}).
		Script(RoutesTool, []string{"-6", "-j", "route", "show"}, probe.FakeResponse{PermissionDenied: true, ErrMessage: "permission denied"}).
		Script(RoutesTool, []string{"-j", "addr", "show"}, probe.FakeResponse{PermissionDenied: true, ErrMessage: "permission denied"})
	cc, _ := netTestCollect(RoutesProbeID, runner)
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q, want permission_denied (reason %q)", res.Status, res.Reason)
	}
	if res.Error == nil || res.Error.Class != probe.ClassPermissionDenied {
		t.Fatalf("error %+v", res.Error)
	}
	set := netArtifact(t, res, ArtifactRoutes)
	for _, k := range []string{"ipv4_route_count", "ipv6_route_count", "address_count"} {
		if _, ok := set.Attributes[k]; ok {
			t.Errorf("a refused capture reported %s: %v", k, set.Attributes)
		}
	}
}

// A missing "ip" is unavailable and the reason names the directories that were
// searched, because a failed lookup cannot tell a host without the tool from a
// host whose tool is somewhere this build does not look. It is never
// not_applicable: a host has a routing table either way.
func TestRoutesProbeSupportMissingToolNamesTheSearchedDirectories(t *testing.T) {
	dirs := []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/snap/bin"}
	runner := probe.NewFakeRunner().WithSearchDirs(dirs...)
	host := netTestHost(runner)
	res := NewRoutesProbe().Support(context.Background(), host)

	if res.Available {
		t.Fatal("available without the tool")
	}
	if res.Status != trustfreeze.StatusUnavailable {
		t.Fatalf("status %q, want unavailable", res.Status)
	}
	for _, dir := range dirs {
		if !strings.Contains(res.Reason, dir) {
			t.Errorf("reason %q does not name the searched directory %s", res.Reason, dir)
		}
	}
	if strings.Contains(res.Reason, "no routing table") {
		t.Errorf("the reason claims the host has no routing table: %q", res.Reason)
	}
}

// On another operating system the probe is unsupported, and the reason says so
// rather than pretending the feature does not exist.
func TestRoutesProbeSupportOtherPlatform(t *testing.T) {
	res := NewRoutesProbe().Support(context.Background(), probe.HostContext{GOOS: "darwin"})
	if res.Available || res.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("support %+v", res)
	}
}

// A listing the output cap cut must never be reported as captured, and the
// diagnostic must name the stream and the cap. A cut JSON document does not
// parse at all, which is why the cut is read before the document is.
func TestRoutesProbeTruncatedDocumentIsPartial(t *testing.T) {
	runner := routesRunner(t, "").Script(RoutesTool, []string{"-j", "route", "show"},
		probe.FakeResponse{Stdout: routeManyRows(400)})
	cc, _ := tfLimitedCollect(RoutesProbeID, runner, probe.FakeFiles{}, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewRoutesProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut document, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
	set := netArtifact(t, res, ArtifactRoutes)
	if _, ok := set.Attributes["ipv4_route_count"]; ok {
		t.Errorf("a cut document produced a route count: %v", set.Attributes)
	}
	if set.Attributes["ipv4_routes_read"] != "false" {
		t.Errorf("set attributes %v", set.Attributes)
	}
}

// routeManyRows builds a route document of n rows of equal length, so a byte
// cap cuts it in the middle of a row and the document no longer parses.
func routeManyRows(n int) []byte {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"dst":"10.%d.%d.0/24","dev":"eth0","protocol":"kernel","scope":"link","flags":[]}`,
			i/256, i%256)
	}
	b.WriteString("]\n")
	return []byte(b.String())
}

// Every artifact of this probe carries a digest and a valid id, which is what
// the bundle writer and the diff depend on.
func TestRoutesProbeArtifactsAreWellFormed(t *testing.T) {
	cc, _ := netTestCollect(RoutesProbeID, routesRunner(t, ""))
	res := NewRoutesProbe().Collect(context.Background(), cc)
	seen := map[string]bool{}
	for _, a := range res.NormalizedState {
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			t.Errorf("artifact id %q: %v", a.ID, err)
		}
		if seen[a.ID] {
			t.Errorf("duplicate artifact id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Digest == "" {
			t.Errorf("artifact %q has no digest", a.ID)
		}
		if a.Source != RoutesProbeID {
			t.Errorf("artifact %q names the source %q", a.ID, a.Source)
		}
		if err := a.ValidateAttributeClasses(); err != nil {
			t.Errorf("artifact %q: %v", a.ID, err)
		}
	}
}

// Two runs over the same fixtures produce the same artifacts, byte for byte
// (playbook L8). The order of the ip output is not the order of the artifacts.
func TestRoutesProbeIsDeterministic(t *testing.T) {
	var digests [2][]string
	for i := range digests {
		cc, _ := netTestCollect(RoutesProbeID, routesRunner(t, ""))
		res := NewRoutesProbe().Collect(context.Background(), cc)
		for _, a := range res.NormalizedState {
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

// TF06-R3 with playbook L1: a document that is not the JSON array iproute2
// prints, a row without an interface name, and an address row without the three
// fields an address needs are each a named diagnostic, never a silent drop.
// The inputs are written here and not taken from a fixture, because no host of
// this laboratory prints them: a fixture claiming it did would be a false
// record.
func TestParseIPAddressesNamesEveryRecordItDropped(t *testing.T) {
	if addrs, diags := ParseIPAddresses([]byte("not json")); addrs != nil || len(diags) != 1 ||
		diags[0].Code != routeDiagJSONUnreadable {
		t.Fatalf("a document that is not JSON gave %d address(es) and %v", len(addrs), diags)
	}
	addrs, diags := ParseIPAddresses([]byte(`[
	  {"addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24}]},
	  {"ifname":"eth0","addr_info":[
	    {"family":"inet","local":"198.51.100.7","prefixlen":24},
	    {"family":"mpls","local":"198.51.100.8","prefixlen":24},
	    {"family":"inet","prefixlen":24},
	    {"family":"inet","local":"198.51.100.9"}]}]`))
	if len(addrs) != 1 || addrs[0].Local != "198.51.100.7" {
		t.Fatalf("addresses %+v, want only the one complete record", addrs)
	}
	if len(diags) != 4 {
		t.Fatalf("%d diagnostic(s) for one unnamed interface and three unreadable addresses: %v", len(diags), diags)
	}
	for _, d := range diags {
		if d.Code != netDiagRecordUnparsed {
			t.Errorf("diagnostic code %q", d.Code)
		}
	}
	// The unnamed interface is reported by its position, because it has no
	// name to report it by.
	if !strings.Contains(diags[0].Message, "interface 1") {
		t.Errorf("the first diagnostic does not place the unnamed interface: %q", diags[0].Message)
	}
	// An unknown address family is dropped rather than recorded under a family
	// this package invented for it.
	if got := routeAddressFamily("mpls"); got != "" {
		t.Errorf("routeAddressFamily(\"mpls\") = %q, want the empty family", got)
	}
}

// routeLess is the tie-breaker of the artifact order. Two routes that agree on
// everything it compares must not order one before the other, or the order of
// two captures of an unchanged host could differ (playbook L8).
func TestRouteLessIsATotalOrderWithoutAPreferenceForEqualRoutes(t *testing.T) {
	a := Route{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Metric: "100", Gateway: "203.0.113.254"}
	b := a
	if routeLess(a, b) || routeLess(b, a) {
		t.Error("two equal routes order each other")
	}
	b.Metric = "200"
	if !routeLess(a, b) || routeLess(b, a) {
		t.Error("the metric does not break the tie")
	}
	c := a
	c.Gateway = "203.0.113.2"
	if !routeLess(c, a) || routeLess(a, c) {
		t.Error("the gateway does not break the tie of two routes with the same metric")
	}
}

// The metric is read as a number where the preferred default route is decided.
// A route without a metric is metric 0, which is what the kernel means when it
// prints none, and a value this parser cannot read is 0 as well: the artifact
// still carries the metric as the tool printed it, so the unreadable value is
// in the bundle and only the ORDERING falls back.
func TestRouteMetricValueReadsTheKernelDefault(t *testing.T) {
	for _, tc := range []struct {
		metric string
		want   int64
	}{{"", 0}, {"0", 0}, {"100", 100}, {"1024", 1024}, {"low", 0}, {"-1", -1}} {
		if got := routeMetricValue(Route{Metric: tc.metric}); got != tc.want {
			t.Errorf("routeMetricValue(%q) = %d, want %d", tc.metric, got, tc.want)
		}
	}
}

// routeDefaults answers two questions per family: which default route the
// kernel prefers (the lowest metric) and how many there are. A tie in the
// metric is broken by the base id, so the answer is deterministic.
func TestRouteDefaultsPrefersTheLowestMetricAndCountsThemAll(t *testing.T) {
	high := Route{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Metric: "200", Gateway: "203.0.113.254"}
	low := Route{Family: routeFamilyIPv4, Destination: "default", Device: "eth1", Table: routeTableMain, Metric: "100", Gateway: "203.0.113.2"}
	plain := Route{Family: routeFamilyIPv4, Destination: "192.0.2.0/24", Device: "eth0", Table: routeTableMain}
	got := routeDefaults([]Route{high, low, plain})
	if len(got) != 1 {
		t.Fatalf("families %v, want ipv4 only", got)
	}
	if d := got[routeFamilyIPv4]; d.count != 2 || d.route.Device != "eth1" {
		t.Errorf("default route %+v, want two counted and the metric 100 route preferred", d)
	}
	// The reverse input order must not change the answer, and the branch that
	// keeps the route it already has has to run too.
	if d := routeDefaults([]Route{low, high, plain})[routeFamilyIPv4]; d.count != 2 || d.route.Device != "eth1" {
		t.Errorf("the order of the rows changed the preferred route: %+v", d)
	}
	// A tie in the metric is broken by the base id, never by the input order.
	tieA := Route{Family: routeFamilyIPv6, Destination: "default", Device: "eth0", Table: routeTableMain, Gateway: "2001:db8::1"}
	tieB := Route{Family: routeFamilyIPv6, Destination: "default", Device: "eth1", Table: routeTableMain, Gateway: "2001:db8::2"}
	first := routeDefaults([]Route{tieA, tieB})[routeFamilyIPv6]
	second := routeDefaults([]Route{tieB, tieA})[routeFamilyIPv6]
	if first.route.BaseArtifactID() != second.route.BaseArtifactID() || first.count != 2 {
		t.Errorf("a tie is decided by the input order: %+v and %+v", first, second)
	}
}

// The address class is the exposure vocabulary of the listener probe, applied
// to an address. An address this build cannot parse is "unknown", which is a
// recorded statement and not an absent attribute.
func TestRouteAddressClassUsesTheExposureVocabulary(t *testing.T) {
	for _, tc := range []struct{ local, want string }{
		{"127.0.0.1", ExposureLoopback},
		{"::1", ExposureLoopback},
		{"169.254.1.1", ExposureLinkLocal},
		{"fe80::1", ExposureLinkLocal},
		{"0.0.0.0", ExposureAnyAddress},
		{"::", ExposureAnyAddress},
		{"203.0.113.10", ExposureSpecificAddress},
		{"2001:db8::10", ExposureSpecificAddress},
		{"", ExposureUnknown},
		{"203.0.113.10/24", ExposureUnknown},
	} {
		if got := routeAddressClass(tc.local); got != tc.want {
			t.Errorf("routeAddressClass(%q) = %q, want %q", tc.local, got, tc.want)
		}
	}
	if got := addressAttributes(Address{Family: routeFamilyIPv4, Device: "lo", Local: "127.0.0.1", PrefixLength: "8"})["address_class"]; got != ExposureLoopback {
		t.Errorf("the address artifact does not carry the class: %q", got)
	}
}

// Playbook L6: a flag list longer than the cap is recorded cut, and the cut is
// stated beside it, so a reader never takes a cut list for the whole one. The
// flag counts of this scenario exceed what any interface of this laboratory
// carries, so the input is built here.
func TestRouteAndAddressFlagsStateTheirTruncation(t *testing.T) {
	long := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		long = append(long, fmt.Sprintf("FLAG-%02d", i))
	}
	attrs := routeAttributes(Route{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Flags: long})
	if attrs["route_flags_truncated"] != "true" {
		t.Errorf("a cut flag list does not say so: %v", attrs)
	}
	if len(attrs["route_flags"]) > routesMaxValueBytes {
		t.Errorf("the recorded flags are %d bytes, the cap is %d", len(attrs["route_flags"]), routesMaxValueBytes)
	}
	addr := addressAttributes(Address{Family: routeFamilyIPv4, Device: "eth0", Local: "203.0.113.10", PrefixLength: "24", DeviceFlags: long})
	if addr["device_flags_truncated"] != "true" {
		t.Errorf("a cut device flag list does not say so: %v", addr)
	}
	// A short list is recorded whole and says nothing about a cut.
	short := routeAttributes(Route{Family: routeFamilyIPv4, Destination: "default", Device: "eth0", Table: routeTableMain, Flags: []string{"onlink"}})
	if short["route_flags"] != "onlink" || short["route_flags_truncated"] != "" {
		t.Errorf("a short flag list was reported as cut: %v", short)
	}
}

// TF06-R7: what this build may claim about its own evidence, and what it may
// not. The parsers are fixture tested and the package cross compiles; whether
// the probe ran on a real Linux host is not decided in code.
func TestRoutesProbeEvidenceClaims(t *testing.T) {
	claims := NewRoutesProbe().EvidenceClaims()
	levels := claims[probe.PlatformLinux]
	if len(levels) != 2 || levels[0] != probe.FixtureTested || levels[1] != probe.CrossCompiled {
		t.Fatalf("claims %+v", claims)
	}
	if _, ok := claims[probe.PlatformWindows]; ok {
		t.Fatalf("a linux probe must claim nothing for windows: %+v", claims)
	}
}

// A volume cap that dropped records makes the run partial even when every call
// answered, and the reason says so instead of leaving the gap unstated.
func TestRoutesStatusReportsTheVolumeCapAsPartial(t *testing.T) {
	read := []routeSource{{what: "ipv4 routes", read: true}, {what: "ipv6 routes", read: true}}
	if st, reason := routesStatus(read, nil); st != trustfreeze.StatusCaptured || reason != "" {
		t.Fatalf("two clean calls gave %q with %q", st, reason)
	}
	capped := []trustfreeze.Diagnostic{{Code: netDiagVolumeCapped, Field: "route_count"}}
	st, reason := routesStatus(read, capped)
	if st != trustfreeze.StatusPartial {
		t.Fatalf("a capped run is %q, want partial", st)
	}
	if !strings.Contains(reason, "volume cap") {
		t.Errorf("the reason does not name the cap: %q", reason)
	}
	if routeHasVolumeWarning(nil) || !routeHasVolumeWarning(capped) {
		t.Error("the volume warning is not recognized by its code")
	}
	if routeHasVolumeWarning([]trustfreeze.Diagnostic{{Code: netDiagRecordUnparsed}}) {
		t.Error("an unparsed record was read as a volume cap")
	}
}
