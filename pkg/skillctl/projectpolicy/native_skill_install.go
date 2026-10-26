package projectpolicy

import (
	"context"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// BeginER1SkillInstall acquires the selected enrolled native journal before
// credential lookup or artifact acquisition. It does not grant generic native
// mutations, enrollment, dependency provisioning or skill execution.
func (p *NativePolicy) BeginER1SkillInstall(ctx context.Context, digest string) (*registry.NativeLiveSkillSession, error) {
	if p == nil || p.liveSkill == nil {
		return nil, ErrUnsupported
	}
	selected, err := p.OfflineInstallSelection()
	if err != nil {
		return nil, err
	}
	journal, err := registry.OpenNativeJournal(selected)
	if err != nil {
		return nil, err
	}
	return registry.NewNativeLiveSkillSession(ctx, journal, p.liveSkill, digest)
}
