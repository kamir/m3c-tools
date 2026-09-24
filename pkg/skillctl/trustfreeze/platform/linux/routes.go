package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// linux.network.routes reports where this host sends traffic and through
// which interface (SPEC-0471 TF06-R3). The routing table is part of the
// attack surface: a listener says what can reach the host, a route says what
// the host can reach, and the default route says through whom.
//
// Sources, all three read with the JSON output of iproute2 so that nothing is
// parsed by column: "ip -j route show" and "ip -6 -j route show" for the two
// address families, and "ip -j addr show" for the addresses that give a route
// its meaning. Measured on two hosts (iproute2 6.1.0 on Ubuntu 24.04.1 and
// 5.15.0 on Ubuntu 22.04.5): the JSON is one compact line, a field the kernel
// did not report is absent rather than empty (a route installed by the boot
// scripts carries no "protocol" at all), and an empty result is the two bytes
// "[]". That last one matters twice over, because a dump the tool aborts
// prints a bare "[" on stdout with the cause on stderr and exit 2, so a
// parser that reads stdout without the exit code would see a truncated
// document and call it a syntax error rather than a failure of the tool.
//
// What this probe does NOT claim: it reads the main routing table only, the
// one "ip route show" prints without arguments. A host with policy routing
// keeps rules and further tables that this capture never opened, so the set
// artifact names the table it asked for instead of implying there is only one.
const (
	// RoutesProbeID is the probe id of the routing table probe.
	RoutesProbeID = "linux.network.routes"
	// RoutesProbeVersion changes whenever the output of the probe can change.
	RoutesProbeVersion = "1"
	// RoutesTool is the executable the probe runs.
	RoutesTool = "ip"
)

// Volume caps of one capture (playbook L6). A bastion that runs containers
// carries one link-local route per veth, so the route count grows with the
// container count, not with the size of the network.
const (
	routesMaxRecords    = 4096
	routesMaxValueBytes = 200
)

// Artifact ids of the routing probe.
const (
	// ArtifactRoutes is the set artifact that states the result even when a
	// family has no route at all.
	ArtifactRoutes = "network/routes"
	// ArtifactRoutePrefix is the id prefix of one route.
	ArtifactRoutePrefix = "network/route"
	// ArtifactAddressPrefix is the id prefix of one interface address.
	ArtifactAddressPrefix = "network/address"

	artifactTypeRoute    = "route"
	artifactTypeAddress  = "address"
	artifactTypeRouteSet = "route-set"
)

// Diagnostic codes of this probe.
const (
	// routeDiagIDDisambiguated marks a group of routes that share family,
	// table, device and destination. See routeDisambiguate.
	routeDiagIDDisambiguated = "route_id_disambiguated"
	// routeDiagIDCarriesMetric marks a group of routes that only the METRIC
	// tells apart, so their artifact ids carry a value the normalization rule
	// set treats as volatile. See routeDisambiguate.
	routeDiagIDCarriesMetric = "route_id_carries_metric"
	// routeDiagJSONUnreadable marks output that is not the JSON document the
	// tool is documented to print.
	routeDiagJSONUnreadable = "json_unreadable"
)

// The default route is what a reader looks for first, so it is spelled out
// once: iproute2 prints the destination of a default route as the literal
// "default", for both families.
const routeDestinationDefault = "default"

// routeTableMain is the table "ip route show" answers for when no table is
// named. The kernel reports the table in the JSON only when it is not this
// one, so an absent field means main and is recorded as such.
const routeTableMain = "main"

// Route is one row of "ip -j route show". Every field is the string iproute2
// printed, because a route is compared as the tool reported it; only Metric
// is kept apart, since it is the one value the normalization rule set has to
// be able to drop (T-03b playbook B5).
type Route struct {
	// Family is "ipv4" or "ipv6", from the call that produced the row and not
	// from the row itself: "ip -j route show" and "ip -6 -j route show" are
	// two questions, and a row does not say which one it answers.
	Family string
	// Destination is the prefix, or "default".
	Destination string
	Gateway     string
	Device      string
	// Table is the routing table, "main" when the row does not name one.
	Table string
	// Metric is the route priority as a string, empty when the kernel
	// reported none.
	Metric string
	// Protocol is who installed the route ("kernel", "dhcp", "static", and
	// absent for the boot scripts).
	Protocol string
	Scope    string
	// PreferredSource is the address the host uses as the source of a packet
	// it sends over this route.
	PreferredSource string
	// Preference is the IPv6 route preference ("low", "medium", "high").
	Preference string
	// Flags are the flags iproute2 printed, for example "linkdown".
	Flags []string
}

// IsDefault reports whether this is a default route.
func (r Route) IsDefault() bool { return r.Destination == routeDestinationDefault }

// BaseArtifactID returns the id of the route before disambiguation:
// "network/route/<family>/<table>/<device>/<destination>".
//
// The destination comes last because it can carry a prefix length, and a
// trailing "/24" reads as part of the prefix where a middle one would read as
// another id segment. Neither the metric nor the gateway is in the id: the
// metric has to stay normalizable (B5), and a changed gateway is drift a
// reader wants to see as a changed route rather than as one route removed and
// another added.
func (r Route) BaseArtifactID() string {
	return strings.Join([]string{ArtifactRoutePrefix, r.Family, r.Table, r.Device, r.Destination}, "/")
}

// Address is one address of one interface from "ip -j addr show".
type Address struct {
	// Family is "ipv4" or "ipv6", derived from the "family" field of the row
	// ("inet" and "inet6").
	Family string
	Device string
	// Local is the address without the prefix length.
	Local string
	// PrefixLength is the prefix length as printed.
	PrefixLength string
	Scope        string
	// Label is the interface label of an IPv4 alias, often the device name.
	Label string
	// Dynamic says the address came from a lease (DHCP or router
	// advertisement) rather than from the configuration.
	Dynamic bool
	// Permanent says the address has no lifetime that runs out. The lifetime
	// itself is a counter that changes every second, so it is not recorded:
	// a value that differs between two captures of an unchanged host would be
	// drift that is not drift (playbook L8).
	Permanent bool
	// DeviceState is the operational state of the interface the address sits
	// on ("UP", "DOWN", "UNKNOWN"), which is what decides whether the address
	// is reachable at all.
	DeviceState string
	// DeviceFlags are the interface flags, for example "NO-CARRIER".
	DeviceFlags []string
}

// ArtifactID returns the id of the address:
// "network/address/<family>/<device>/<local>/<prefixlength>".
func (a Address) ArtifactID() string {
	return strings.Join([]string{ArtifactAddressPrefix, a.Family, a.Device, a.Local, a.PrefixLength}, "/")
}

// Address families as this probe spells them. They are the values the
// listener probe uses, so the same address family reads the same in both.
const (
	routeFamilyIPv4 = familyIPv4
	routeFamilyIPv6 = familyIPv6
)

// ipRouteRow is one element of the "ip -j route show" document. Only the
// fields this probe records are declared; iproute2 adds fields per route type
// (nexthops of a multipath route, cache attributes) that are deliberately not
// read, so the decoder must not be strict here.
type ipRouteRow struct {
	Dst      string   `json:"dst"`
	Gateway  string   `json:"gateway"`
	Dev      string   `json:"dev"`
	Table    string   `json:"table"`
	Metric   *int64   `json:"metric"`
	Protocol string   `json:"protocol"`
	Scope    string   `json:"scope"`
	PrefSrc  string   `json:"prefsrc"`
	Pref     string   `json:"pref"`
	Flags    []string `json:"flags"`
}

// ipAddrRow is one element of the "ip -j addr show" document.
type ipAddrRow struct {
	IfName    string   `json:"ifname"`
	OperState string   `json:"operstate"`
	Flags     []string `json:"flags"`
	AddrInfo  []struct {
		Family            string `json:"family"`
		Local             string `json:"local"`
		PrefixLen         *int64 `json:"prefixlen"`
		Scope             string `json:"scope"`
		Label             string `json:"label"`
		Dynamic           bool   `json:"dynamic"`
		ValidLifeTime     *int64 `json:"valid_life_time"`
		PreferredLifeTime *int64 `json:"preferred_life_time"`
	} `json:"addr_info"`
}

// routeLifetimeForever is the lifetime iproute2 prints for an address that
// does not expire (0xffffffff seconds). Anything smaller is a lease that is
// counting down.
const routeLifetimeForever int64 = 4294967295

// ParseIPRoutes parses the document "ip -j route show" printed, for the
// address family the caller asked for. It is pure: it reads bytes and returns
// routes plus one diagnostic per record it could not read, so it is table
// tested from fixtures on any operating system.
//
// A document that is not a JSON array at all yields no routes and one
// diagnostic, because that is a statement about the tool and not about the
// host: it is what a caller sees when iproute2 aborted a dump halfway.
func ParseIPRoutes(family string, b []byte) ([]Route, []trustfreeze.Diagnostic) {
	var (
		rows  []ipRouteRow
		diags []trustfreeze.Diagnostic
	)
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, []trustfreeze.Diagnostic{{
			Code:    routeDiagJSONUnreadable,
			Field:   "route_list",
			Message: fmt.Sprintf("the %s route document is not the JSON array iproute2 prints: %v", family, err),
		}}
	}
	out := make([]Route, 0, len(rows))
	for i, row := range rows {
		if strings.TrimSpace(row.Dst) == "" || strings.TrimSpace(row.Dev) == "" {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:  netDiagRecordUnparsed,
				Field: "route",
				Message: fmt.Sprintf("%s route %d has no destination or no device and was dropped",
					family, i+1),
			})
			continue
		}
		r := Route{
			Family:          family,
			Destination:     strings.TrimSpace(row.Dst),
			Gateway:         strings.TrimSpace(row.Gateway),
			Device:          strings.TrimSpace(row.Dev),
			Table:           strings.TrimSpace(row.Table),
			Protocol:        strings.TrimSpace(row.Protocol),
			Scope:           strings.TrimSpace(row.Scope),
			PreferredSource: strings.TrimSpace(row.PrefSrc),
			Preference:      strings.TrimSpace(row.Pref),
			Flags:           routeCleanFlags(row.Flags),
		}
		if r.Table == "" {
			r.Table = routeTableMain
		}
		if row.Metric != nil {
			r.Metric = strconv.FormatInt(*row.Metric, 10)
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return routeLess(out[i], out[j]) })
	return out, diags
}

// routeLess orders two routes by everything that identifies them, so the
// order of the artifacts does not depend on the order iproute2 happened to
// dump them in (playbook L8).
func routeLess(a, b Route) bool {
	for _, p := range [][2]string{
		{a.BaseArtifactID(), b.BaseArtifactID()},
		{a.Metric, b.Metric},
		{a.Gateway, b.Gateway},
	} {
		if p[0] != p[1] {
			return p[0] < p[1]
		}
	}
	return false
}

// routeCleanFlags returns the flags, trimmed, sorted and without empties.
func routeCleanFlags(in []string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// ParseIPAddresses parses the document "ip -j addr show" printed.
func ParseIPAddresses(b []byte) ([]Address, []trustfreeze.Diagnostic) {
	var (
		rows  []ipAddrRow
		diags []trustfreeze.Diagnostic
	)
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, []trustfreeze.Diagnostic{{
			Code:    routeDiagJSONUnreadable,
			Field:   "address_list",
			Message: fmt.Sprintf("the address document is not the JSON array iproute2 prints: %v", err),
		}}
	}
	var out []Address
	for i, row := range rows {
		dev := strings.TrimSpace(row.IfName)
		if dev == "" {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    netDiagRecordUnparsed,
				Field:   "address",
				Message: fmt.Sprintf("interface %d has no name and its addresses were dropped", i+1),
			})
			continue
		}
		for j, info := range row.AddrInfo {
			fam := routeAddressFamily(info.Family)
			local := strings.TrimSpace(info.Local)
			if fam == "" || local == "" || info.PrefixLen == nil {
				diags = append(diags, trustfreeze.Diagnostic{
					Code:  netDiagRecordUnparsed,
					Field: "address",
					Message: fmt.Sprintf("address %d of %s has no family, no address or no prefix length and was dropped",
						j+1, dev),
				})
				continue
			}
			out = append(out, Address{
				Family:       fam,
				Device:       dev,
				Local:        local,
				PrefixLength: strconv.FormatInt(*info.PrefixLen, 10),
				Scope:        strings.TrimSpace(info.Scope),
				Label:        strings.TrimSpace(info.Label),
				Dynamic:      info.Dynamic,
				Permanent:    routeLifetimePermanent(info.ValidLifeTime) && routeLifetimePermanent(info.PreferredLifeTime),
				DeviceState:  strings.TrimSpace(row.OperState),
				DeviceFlags:  routeCleanFlags(row.Flags),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ArtifactID() < out[j].ArtifactID() })
	return out, diags
}

// routeLifetimePermanent reports whether a lifetime means "does not expire".
// An absent lifetime is read as permanent, which is what iproute2 means when
// it omits the field.
func routeLifetimePermanent(v *int64) bool {
	return v == nil || *v >= routeLifetimeForever
}

// routeAddressFamily maps the iproute2 family name to the family this package
// spells. An unknown family yields the empty string, which drops the record
// with a diagnostic rather than inventing a family for it.
func routeAddressFamily(s string) string {
	switch strings.TrimSpace(s) {
	case "inet":
		return routeFamilyIPv4
	case "inet6":
		return routeFamilyIPv6
	}
	return ""
}

// routeDisambiguate assigns the artifact id of every route and reports the
// groups that needed more than their base id, plus the groups whose id had to
// carry the metric.
//
// Family, table, device and destination do not identify a route on their own:
// two default routes over the same interface with different metrics, or with
// different gateways, are two routes the kernel keeps apart. Dropping the
// second one would delete a route from the baseline, so instead EVERY member of
// a colliding group gets a distinguishing value appended.
//
// WHICH value is not a detail, and this is the reason the order below is what
// it is (review of T-03b, finding 3 of the summary). The metric is declared
// volatile in the normalization rule set, because a DHCP lease or a reordering
// of the network stack changes it without the route changing. A value inside an
// artifact ID is out of reach of every rule set: compare pairs artifacts BY id,
// so an id that carries the metric turns a metric change into one route removed
// and one route added, which is exactly what B5 promises will not happen. The
// gateway, in contrast, is where the packets go and changes only when the
// topology does.
//
// So the gateway comes first and alone. The metric is appended only to a group
// the gateway does not separate, which is the case where the metric is the one
// thing the kernel itself keeps those routes apart by and leaving it out would
// merge two routes into one id. Such a group is reported separately
// (routeDiagIDCarriesMetric), because then the volatility is in the id and a
// reader of a diff has to know it. Last resort is the position within the
// group. The result is deterministic for a given routing table.
func routeDisambiguate(routes []Route) (ids, collisions, metricIDs []string) {
	groups := map[string][]int{}
	for i, r := range routes {
		base := r.BaseArtifactID()
		groups[base] = append(groups[base], i)
	}
	ids = make([]string, len(routes))
	for _, base := range netSortedKeys(groups) {
		idx := groups[base]
		if len(idx) == 1 {
			ids[idx[0]] = base
			continue
		}
		collisions = append(collisions, base)
		for _, i := range idx {
			ids[i] = base + routeViaSuffix(routes[i])
		}
		if routeIDsUnique(ids, idx) {
			continue
		}
		for _, i := range idx {
			ids[i] = base + routeViaSuffix(routes[i]) + routeMetricSuffix(routes[i])
		}
		if routeAnyMetric(routes, idx) {
			// A metric really went into an id. A group where nobody has one
			// falls through to the position below and carries no volatile
			// value, so it is not reported here.
			metricIDs = append(metricIDs, base)
		}
		// Two routes that agree on gateway and metric as well: the position
		// within the group is the only thing left, and it is appended to all
		// of them so that no member silently keeps the shorter id.
		routeBreakRemainingTies(ids, idx)
	}
	sort.Strings(collisions)
	sort.Strings(metricIDs)
	return ids, collisions, metricIDs
}

// routeViaSuffix is the gateway part of a disambiguated id, empty for a route
// without a gateway (a link-scope route has none).
func routeViaSuffix(r Route) string {
	if r.Gateway == "" {
		return ""
	}
	return "/via=" + r.Gateway
}

// routeMetricSuffix is the metric part of a disambiguated id, empty for a route
// the kernel printed without one.
func routeMetricSuffix(r Route) string {
	if r.Metric == "" {
		return ""
	}
	return "/metric=" + r.Metric
}

// routeIDsUnique reports whether the members of one group have distinct ids.
func routeIDsUnique(ids []string, idx []int) bool {
	seen := map[string]bool{}
	for _, i := range idx {
		if seen[ids[i]] {
			return false
		}
		seen[ids[i]] = true
	}
	return true
}

// routeAnyMetric reports whether any member of the group carries a metric, so
// that a group which needed the metric appended is only reported as
// metric-bearing when a metric really went into an id.
func routeAnyMetric(routes []Route, idx []int) bool {
	for _, i := range idx {
		if routes[i].Metric != "" {
			return true
		}
	}
	return false
}

// routeBreakRemainingTies appends a position to every id of idx that is still
// shared with another member of the same group.
func routeBreakRemainingTies(ids []string, idx []int) {
	count := map[string]int{}
	for _, i := range idx {
		count[ids[i]]++
	}
	for n, i := range idx {
		if count[ids[i]] > 1 {
			ids[i] += "/" + strconv.Itoa(n+1)
		}
	}
}

// RoutesProbe collects the routing table and the interface addresses.
type RoutesProbe struct{}

// NewRoutesProbe returns the probe.
func NewRoutesProbe() *RoutesProbe { return &RoutesProbe{} }

// Descriptor implements probe.Probe.
func (p *RoutesProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                RoutesProbeID,
		Version:           RoutesProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    15 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactAddressPrefix, ArtifactRoutePrefix, ArtifactRoutes},
	}
}

// RequiredTools implements the optional tool interface of the capture
// package: doctor resolves these names and never runs them.
func (p *RoutesProbe) RequiredTools() []string { return []string{RoutesTool} }

// EvidenceClaims implements probe.EvidenceClaimer. The parsers are covered by
// fixture tests that run on any host, and the package compiles for Linux.
// Whether the probe ran on a real Linux host is not decided in code
// (SPEC-0471 TF06-R7).
func (p *RoutesProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe: availability only, nothing is collected.
// A missing "ip" is unavailable and names the directories that were searched,
// never not_applicable: a host still has a routing table when the binary this
// build looks for is somewhere else.
func (p *RoutesProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("ip is a Linux tool; no routing table source for " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if _, err := host.Runner.LookPath(RoutesTool); err != nil {
		if probe.ErrorClass(err) == probe.ClassPermissionDenied {
			return probe.PermissionDenied(RoutesTool + " is not executable by this account")
		}
		return probe.Unavailable(routesToolMissingReason(host.Runner))
	}
	return probe.Supported()
}

// routesToolMissingReason names the tool, where it was looked for, and what
// the bundle therefore does not know.
func routesToolMissingReason(runner probe.CommandRunner) string {
	return RoutesTool + " was not found " + netSearchedDirsPhrase(runner) +
		": the routing table and the addresses of this host are not established by this capture"
}

// routeSource is the outcome of one of the three calls this probe makes.
type routeSource struct {
	// what names the call in a reason a person reads.
	what string
	// status is the honest status of the call.
	status trustfreeze.ProbeStatus
	// detail is the cause, empty on success.
	detail string
	// read says the call answered and its document parsed.
	read bool
}

// Collect implements probe.Probe.
func (p *RoutesProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	s := newNetProbeState(ctx, cc)
	res := s.base(RoutesProbeID, RoutesProbeVersion, start)
	version := s.toolVersion(RoutesTool, []string{"-V"}, "ip-version.stdout")
	observed := trustfreeze.FormatTime(start)

	v4, src4 := p.routes(s, routeFamilyIPv4, []string{"-j", "route", "show"}, "ip-route-show.json")
	v6, src6 := p.routes(s, routeFamilyIPv6, []string{"-6", "-j", "route", "show"}, "ip-6-route-show.json")
	addrs, srcA := p.addresses(s)

	routes := append(append([]Route(nil), v4...), v6...)
	sort.SliceStable(routes, func(i, j int) bool { return routeLess(routes[i], routes[j]) })
	capped := false
	if len(routes) > routesMaxRecords {
		s.warn(netDiagVolumeCapped, "route",
			fmt.Sprintf("%d routes; only the first %d are recorded as artifacts", len(routes), routesMaxRecords))
		routes = routes[:routesMaxRecords]
		capped = true
	}
	if len(addrs) > routesMaxRecords {
		s.warn(netDiagVolumeCapped, "address",
			fmt.Sprintf("%d addresses; only the first %d are recorded as artifacts", len(addrs), routesMaxRecords))
		addrs = addrs[:routesMaxRecords]
		capped = true
	}

	prov := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     s.sourceList(),
		ObservedAt:  observed,
		ToolVersion: version,
	}
	arts := make([]trustfreeze.Artifact, 0, len(routes)+len(addrs)+1)
	ids, collisions, metricIDs := routeDisambiguate(routes)
	for _, base := range collisions {
		s.warn(routeDiagIDDisambiguated, "route",
			"several routes share "+base+
				"; the gateway was appended to the id of each of them, so no route is dropped")
	}
	for _, base := range metricIDs {
		// The metric is volatile (normalization rule set, attribute
		// route_metric) and it is now inside an id, where no rule set can
		// reach it. A reader of a diff has to know that, because a metric
		// change on one of these routes reads as one removed and one added.
		s.warn(routeDiagIDCarriesMetric, "route",
			"the routes that share "+base+
				" are told apart only by their metric, so their ids carry it; the metric is volatile, and a change of it on one of these routes reads as one route removed and one added")
	}
	defaults := routeDefaults(routes)
	for i, r := range routes {
		arts = append(arts, trustfreeze.Artifact{
			ID: ids[i], Type: artifactTypeRoute, Scope: "device", Source: RoutesProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  routeAttributes(r),
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	for _, a := range addrs {
		arts = append(arts, trustfreeze.Artifact{
			ID: a.ArtifactID(), Type: artifactTypeAddress, Scope: "device", Source: RoutesProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  addressAttributes(a),
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	arts = append(arts, trustfreeze.Artifact{
		ID: ArtifactRoutes, Type: artifactTypeRouteSet, Scope: "device", Source: RoutesProbeID,
		State: trustfreeze.StateObserved,
		Attributes: routeSetAttributes(routeSetInput{
			v4: v4, v6: v6, addrs: addrs,
			src4: src4, src6: src6, srcAddr: srcA,
			defaults: defaults, capped: capped,
		}),
		Provenance:  prov,
		Sensitivity: trustfreeze.SensitivityInternal,
	})

	res.Status, res.Reason = routesStatus([]routeSource{src4, src6, srcA}, s.warnings)
	switch res.Status {
	case trustfreeze.StatusPermissionDenied:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassPermissionDenied, Message: res.Reason}
	case trustfreeze.StatusTimeout:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTimeout, Message: res.Reason}
	case trustfreeze.StatusUnavailable:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassToolMissing, Message: res.Reason}
	case trustfreeze.StatusFailed:
		res.Error = &trustfreeze.ProbeError{Class: probe.ClassTerminated, Message: res.Reason}
	}
	return s.finish(res, arts, start)
}

// routes runs one of the two route calls and parses its document.
func (p *RoutesProbe) routes(s *netProbeState, family string, args []string, evidence string) ([]Route, routeSource) {
	what := family + " routes"
	cmd := s.run(RoutesTool, args)
	if cmd.Status != trustfreeze.StatusCaptured {
		s.evidenceIfAny(evidence+".stderr", "stderr:"+RoutesTool, cmd.Res.Stderr, cmd.Res.StderrTruncated)
		s.warn(netDiagCode(cmd.Status), "route", what+": "+cmd.Detail)
		return nil, routeSource{what: what, status: cmd.Status, detail: cmd.Detail}
	}
	s.evidence(evidence, "stdout:"+RoutesTool, cmd.Res.Stdout, cmd.Res.StdoutTruncated)
	// The cut has to be read before the rows are counted: a count over a cut
	// document is a claim about the host that nobody measured, and a cut JSON
	// document does not parse at all, which would otherwise be reported as a
	// broken tool instead of as a reached limit.
	if reason := s.truncationCheck(cmd, "route_list",
		"the routes beyond the cut are not in this bundle, and the recorded counts count only what was read"); reason != "" {
		return nil, routeSource{what: what, status: trustfreeze.StatusPartial, detail: reason}
	}
	routes, diags := ParseIPRoutes(family, cmd.Res.Stdout.Bytes())
	s.warnings = append(s.warnings, diags...)
	src := routeSource{what: what, status: trustfreeze.StatusCaptured, read: true}
	for _, d := range diags {
		if d.Code == routeDiagJSONUnreadable {
			src.read = false
			src.status = trustfreeze.StatusFailed
			src.detail = d.Message
			return nil, src
		}
	}
	if len(diags) > 0 {
		src.status = trustfreeze.StatusPartial
		src.detail = fmt.Sprintf("%d %s could not be read", len(diags), what)
	}
	return routes, src
}

// addresses runs the address call and parses its document.
func (p *RoutesProbe) addresses(s *netProbeState) ([]Address, routeSource) {
	const what = "interface addresses"
	cmd := s.run(RoutesTool, []string{"-j", "addr", "show"})
	if cmd.Status != trustfreeze.StatusCaptured {
		s.evidenceIfAny("ip-addr-show.json.stderr", "stderr:"+RoutesTool, cmd.Res.Stderr, cmd.Res.StderrTruncated)
		s.warn(netDiagCode(cmd.Status), "address", what+": "+cmd.Detail)
		return nil, routeSource{what: what, status: cmd.Status, detail: cmd.Detail}
	}
	s.evidence("ip-addr-show.json", "stdout:"+RoutesTool, cmd.Res.Stdout, cmd.Res.StdoutTruncated)
	if reason := s.truncationCheck(cmd, "address_list",
		"the addresses beyond the cut are not in this bundle, and the recorded counts count only what was read"); reason != "" {
		return nil, routeSource{what: what, status: trustfreeze.StatusPartial, detail: reason}
	}
	addrs, diags := ParseIPAddresses(cmd.Res.Stdout.Bytes())
	s.warnings = append(s.warnings, diags...)
	src := routeSource{what: what, status: trustfreeze.StatusCaptured, read: true}
	for _, d := range diags {
		if d.Code == routeDiagJSONUnreadable {
			src.read = false
			src.status = trustfreeze.StatusFailed
			src.detail = d.Message
			return nil, src
		}
	}
	if len(diags) > 0 {
		src.status = trustfreeze.StatusPartial
		src.detail = fmt.Sprintf("%d address records could not be read", len(diags))
	}
	return addrs, src
}

// routeAttributes builds the attributes of one route artifact. The metric
// lives under its own key so that the versioned normalization rule set can
// drop it without touching a metric of some other artifact family (B5).
func routeAttributes(r Route) map[string]string {
	attrs := map[string]string{
		"address_family": r.Family,
		"destination":    r.Destination,
		"device":         r.Device,
		"table":          r.Table,
		"default_route":  privBool(r.IsDefault()),
	}
	for k, v := range map[string]string{
		"gateway":          r.Gateway,
		"route_metric":     r.Metric,
		"protocol":         r.Protocol,
		"scope":            r.Scope,
		"preferred_source": r.PreferredSource,
		"route_preference": r.Preference,
	} {
		if v != "" {
			attrs[k] = v
		}
	}
	if len(r.Flags) > 0 {
		flags, cut := privCapList(r.Flags, routesMaxValueBytes)
		attrs["route_flags"] = flags
		if cut {
			attrs["route_flags_truncated"] = privBool(true)
		}
	}
	return attrs
}

// addressAttributes builds the attributes of one address artifact.
func addressAttributes(a Address) map[string]string {
	attrs := map[string]string{
		"address_family": a.Family,
		"device":         a.Device,
		"local_address":  a.Local,
		"prefix_length":  a.PrefixLength,
		"dynamic":        privBool(a.Dynamic),
		"permanent":      privBool(a.Permanent),
	}
	for k, v := range map[string]string{
		"scope":         a.Scope,
		"label":         a.Label,
		"device_state":  a.DeviceState,
		"address_class": routeAddressClass(a.Local),
	} {
		if v != "" {
			attrs[k] = v
		}
	}
	if len(a.DeviceFlags) > 0 {
		flags, cut := privCapList(a.DeviceFlags, routesMaxValueBytes)
		attrs["device_flags"] = flags
		if cut {
			attrs["device_flags_truncated"] = privBool(true)
		}
	}
	return attrs
}

// routeAddressClass classifies an address the way the listener probe
// classifies a bind address, so that the exposure vocabulary of the two
// network probes is the same one. An address the parser cannot read is
// unknown, never silently absent.
func routeAddressClass(local string) string {
	ip, err := netip.ParseAddr(local)
	if err != nil {
		return ExposureUnknown
	}
	switch {
	case ip.IsLoopback():
		return ExposureLoopback
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return ExposureLinkLocal
	case ip.IsUnspecified():
		return ExposureAnyAddress
	}
	return ExposureSpecificAddress
}

// routeDefault is the default route of one address family and how many
// default routes that family has.
type routeDefault struct {
	route Route
	count int
}

// routeDefaults returns, per family, the default route the kernel prefers and
// how many default routes that family carries. Preferred means the lowest
// metric, because that is the route a packet to an unknown destination takes;
// a route without a metric is metric 0, which is what the kernel means when it
// prints none. A tie is broken by the base id, so the choice is deterministic
// (playbook L8) even where two default routes agree on everything comparable.
func routeDefaults(routes []Route) map[string]routeDefault {
	out := map[string]routeDefault{}
	for _, r := range routes {
		if !r.IsDefault() {
			continue
		}
		cur, seen := out[r.Family]
		switch {
		case !seen:
			out[r.Family] = routeDefault{route: r, count: 1}
		case routeMetricValue(r) < routeMetricValue(cur.route),
			routeMetricValue(r) == routeMetricValue(cur.route) && r.BaseArtifactID() < cur.route.BaseArtifactID():
			out[r.Family] = routeDefault{route: r, count: cur.count + 1}
		default:
			out[r.Family] = routeDefault{route: cur.route, count: cur.count + 1}
		}
	}
	return out
}

// routeMetricValue returns the metric as a number. An absent or unreadable
// metric is 0, the value the kernel uses when a route names none.
func routeMetricValue(r Route) int64 {
	if r.Metric == "" {
		return 0
	}
	v, err := strconv.ParseInt(r.Metric, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// routeSetInput is what the set artifact is built from.
type routeSetInput struct {
	v4, v6   []Route
	addrs    []Address
	src4     routeSource
	src6     routeSource
	srcAddr  routeSource
	defaults map[string]routeDefault
	capped   bool
}

// routeSetAttributes builds the set artifact. It states the result even where
// a family has no route at all: zero IPv6 routes is a fact about the host and
// is recorded as one, but only when the IPv6 call actually answered. Where it
// did not, the count is absent and a flag says the family was not read, so a
// missing answer can never be mistaken for an empty table (playbook L1).
func routeSetAttributes(in routeSetInput) map[string]string {
	attrs := map[string]string{
		"tool":              RoutesTool,
		"tables_queried":    routeTableMain,
		"route_list_capped": privBool(in.capped),
	}
	for _, f := range []struct {
		family string
		routes []Route
		src    routeSource
	}{{routeFamilyIPv4, in.v4, in.src4}, {routeFamilyIPv6, in.v6, in.src6}} {
		attrs[f.family+"_routes_read"] = privBool(f.src.read)
		if f.src.read {
			attrs[f.family+"_route_count"] = strconv.Itoa(len(f.routes))
		}
		d, ok := in.defaults[f.family]
		switch {
		case ok:
			attrs[f.family+"_default_route"] = d.route.BaseArtifactID()
			attrs[f.family+"_default_device"] = d.route.Device
			attrs[f.family+"_default_route_count"] = strconv.Itoa(d.count)
			if d.route.Gateway != "" {
				attrs[f.family+"_default_gateway"] = d.route.Gateway
			}
		case f.src.read:
			// A host with no default route for a family reaches nothing
			// beyond its directly attached networks there, which is a finding
			// a reader looks for first and therefore is written down.
			attrs[f.family+"_default_route"] = "none"
			attrs[f.family+"_default_route_count"] = "0"
		}
	}
	attrs["address_list_read"] = privBool(in.srcAddr.read)
	if in.srcAddr.read {
		attrs["address_count"] = strconv.Itoa(len(in.addrs))
		devices := map[string]bool{}
		for _, a := range in.addrs {
			devices[a.Device] = true
		}
		attrs["device_count"] = strconv.Itoa(len(devices))
	}
	return attrs
}

// routesStatus folds the three calls into the probe status. The routing table
// is the answer this probe exists for, so a host whose IPv4 and IPv6 tables
// were both read is at worst partial; a run that read neither reports the
// strongest cause it saw, and never captured.
func routesStatus(sources []routeSource, warnings []trustfreeze.Diagnostic) (trustfreeze.ProbeStatus, string) {
	var reasons []string
	read := 0
	for _, src := range sources {
		if src.read {
			read++
		}
		if src.detail != "" {
			reasons = append(reasons, src.what+": "+src.detail)
		}
	}
	reason := strings.Join(reasons, "; ")
	if read == 0 {
		// The precedence: a privilege block outranks a timeout, a timeout
		// outranks a missing tool, and a partial outranks a plain failure.
		// The last one matters for the case where an output cap cut every
		// document: the tool answered and the limit cut it, which is not the
		// same as a tool that failed.
		for _, want := range []trustfreeze.ProbeStatus{
			trustfreeze.StatusPermissionDenied, trustfreeze.StatusTimeout,
			trustfreeze.StatusUnavailable, trustfreeze.StatusPartial,
		} {
			for _, src := range sources {
				if src.status == want {
					return want, reason
				}
			}
		}
		if reason == "" {
			reason = "no route or address document was read"
		}
		return trustfreeze.StatusFailed, reason
	}
	if len(reasons) > 0 || routeHasVolumeWarning(warnings) {
		if reason == "" {
			reason = "the recorded routes and addresses stop at the volume cap of this probe"
		}
		return trustfreeze.StatusPartial, reason
	}
	return trustfreeze.StatusCaptured, ""
}

// routeHasVolumeWarning reports whether a volume cap dropped records.
func routeHasVolumeWarning(warnings []trustfreeze.Diagnostic) bool {
	for _, w := range warnings {
		if w.Code == netDiagVolumeCapped {
			return true
		}
	}
	return false
}
