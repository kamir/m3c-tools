// Package linux holds the Trust Freeze probes of a Linux host (SPEC-0471
// TF06-R3) and the capability resolver that turns their artifacts into
// privilege statements (SPEC-0466 section 4.6).
//
// The probes, by id: linux.packages and linux.users (inventory),
// linux.sudo and linux.ssh (privilege), linux.systemd and linux.mounts
// (services and file systems), linux.network.listeners,
// linux.network.routes, linux.dns, linux.firewall and linux.containers
// (network and runtimes), and linux.executables (the programs the services
// and listeners name, with a hash).
//
// Platform guard: every descriptor of this package names linux as its only
// platform, so a build for another operating system still registers the
// probes and the capture engine records them as unsupported with the platform
// as the reason, instead of leaving them out and claiming they are not
// implemented. Each probe is a thin reader plus pure parsers over the bytes a
// tool printed, so the fixture tests of this package run on any host.
//
// Nothing here elevates: no probe calls sudo, pkexec or doas, not even when
// it would work (T-03 playbook L2). An answer that needs privileges the
// capture does not have is permission_denied, never a silent empty list.
package linux

import (
	"slices"
	"sort"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// Register adds every probe of this package to reg. It is called on every
// platform: the descriptors carry the platform guard (see the package
// documentation).
func Register(reg *probe.Registry) error {
	for _, p := range Probes() {
		if err := reg.Register(p); err != nil {
			return err
		}
	}
	return nil
}

// Probes returns one instance of every probe of this package, in probe id
// order.
func Probes() []probe.Probe {
	return []probe.Probe{
		NewContainersProbe(),
		NewDNSProbe(),
		NewExecutablesProbe(),
		NewFirewallProbe(),
		NewMountsProbe(),
		NewListenersProbe(),
		NewRoutesProbe(),
		NewPackagesProbe(),
		NewSSHProbe(),
		NewSudoProbe(),
		NewSystemdProbe(),
		NewUsersProbe(),
	}
}

// AllowedRoots returns the file roots the probes of this package read on
// goos, sorted and without duplicates. The capture engine passes them to the
// restricted file reader, so a probe whose path is not under one of these
// roots reads nothing: linux.sudo, linux.ssh and linux.dns are the probes
// that open files through that reader. linux.executables is not among them.
// It hashes program files through its own ProgramReader, which carries its
// own root list (ExecutableRoots) and its own refusals, because a hash needs
// the resolved path and the size of the file rather than a text read.
func AllowedRoots(goos string) []string {
	if goos != string(probe.PlatformLinux) {
		return nil
	}
	roots := append(SudoAllowedRoots(), SSHAllowedRoots()...)
	roots = append(roots, DNSAllowedRoots()...)
	sort.Strings(roots)
	return slices.Compact(roots)
}
