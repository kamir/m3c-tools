package capture

import (
	"context"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/linux"
)

// SPEC-0466 section 5.7: a capture on a platform with a capability resolver
// carries state/capabilities.json, the resolver names itself, and the
// document is part of the manifest.
func TestCaptureWritesCapabilities(t *testing.T) {
	p := profile(t, []string{"common.identity"}, nil)
	res := mustRun(t, baseOptions(t, p, registry(t), identityRunner()))
	b := verifyBundle(t, res)
	if !b.Has(trustfreeze.StateCapabilitiesFile) || b.Capabilities == nil {
		t.Fatalf("no %s in a linux capture", trustfreeze.StateCapabilitiesFile)
	}
	if b.Capabilities.Resolver != LinuxCapabilityResolverID {
		t.Fatalf("resolver %q", b.Capabilities.Resolver)
	}
	// The identity probe produces no privilege artifact, so the resolver says
	// so instead of leaving an empty list unexplained.
	if len(b.Capabilities.Capabilities) != 0 {
		t.Fatalf("capabilities %+v", b.Capabilities.Capabilities)
	}
	if len(b.Capabilities.Diagnostics) == 0 {
		t.Fatal("an empty capability list without a diagnostic")
	}
	if res.Capabilities == nil || res.Capabilities.Resolver != b.Capabilities.Resolver {
		t.Fatalf("result capabilities %+v", res.Capabilities)
	}
}

// A platform without a resolver writes no capability document at all: the
// absence says that nobody looked, not that the host grants nothing.
func TestCaptureWithoutResolverWritesNoCapabilities(t *testing.T) {
	p := profile(t, []string{"common.identity"}, nil)
	opts := baseOptions(t, p, registry(t), identityRunner())
	opts.Capabilities = &CapabilityResolver{}
	res := mustRun(t, opts)
	b := verifyBundle(t, res)
	if b.Has(trustfreeze.StateCapabilitiesFile) || b.Capabilities != nil || res.Capabilities != nil {
		t.Fatal("a capture without a resolver wrote a capability document")
	}
	if DefaultCapabilityResolver("darwin") != nil || DefaultCapabilityResolver("windows") != nil {
		t.Fatal("this build claims a capability resolver outside linux")
	}
	if r := DefaultCapabilityResolver("linux"); r == nil || r.Resolve == nil || r.ID != LinuxCapabilityResolverID {
		t.Fatalf("linux resolver %+v", r)
	}
}

// The engine drops a capability without an id or with a duplicate id and says
// so, so a resolver cannot write an ambiguous document.
func TestCaptureDropsAmbiguousCapabilities(t *testing.T) {
	cap1 := trustfreeze.Capability{
		ID: "capability/execute/host/user/alice", SubjectID: "user/alice", Action: "execute",
		Resource: "host", Effect: "allowed", State: trustfreeze.StateDeclared, Scope: "host",
		Privilege: linux.CapPrivilegeRootViaSudo, Sources: []string{"device/os"},
		Confidence: trustfreeze.ConfidenceCorroborated,
	}
	second, nameless := cap1, cap1
	second.Privilege = linux.CapPrivilegeUser
	nameless.ID = ""
	p := profile(t, []string{"common.identity"}, nil)
	opts := baseOptions(t, p, registry(t), identityRunner())
	opts.Capabilities = &CapabilityResolver{
		ID: "test.resolver/v1",
		Resolve: func(context.Context, []trustfreeze.Artifact) ([]trustfreeze.Capability, []trustfreeze.Diagnostic, error) {
			return []trustfreeze.Capability{cap1, second, nameless}, nil, nil
		},
	}
	b := verifyBundle(t, mustRun(t, opts))
	if b.Capabilities == nil || len(b.Capabilities.Capabilities) != 1 || b.Capabilities.Capabilities[0].Privilege != linux.CapPrivilegeRootViaSudo {
		t.Fatalf("capabilities %+v", b.Capabilities)
	}
	dropped := 0
	for _, d := range b.Capabilities.Diagnostics {
		if d.Code == DiagCapabilityDropped {
			dropped++
		}
	}
	if dropped != 2 {
		t.Fatalf("%d capability_dropped diagnostics, want 2", dropped)
	}
}
