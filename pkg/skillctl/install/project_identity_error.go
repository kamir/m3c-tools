package install

import (
	"context"
	"errors"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// Keep verifier classifications while not rendering registry-controlled identity
// fields in a managed online error. Unwrap preserves errors.Is/As for callers.
type projectIdentityError struct{ cause error }

func (e projectIdentityError) Error() string { return "install: project identity verification refused" }
func (e projectIdentityError) Unwrap() error { return e.cause }

// The initial identity verified the retained root signature. A final observation
// must still authorize that same key, without relabeling a changed identity.
type projectIdentityProof struct {
	reader *registry.BoundIdentityReader
	author registry.Identity
}

func (p projectIdentityProof) recheck(ctx context.Context, source *installedSkillSource) error {
	current, err := source.GetIdentity(ctx, p.author.ID)
	if err != nil {
		return projectIdentityError{cause: errors.Join(verify.ErrAuthorSigInvalid, err)}
	}
	if current.IsRevoked() {
		return projectIdentityError{cause: verify.ErrIdentityRevoked}
	}
	if current.PubkeyB64 != p.author.PubkeyB64 {
		return projectIdentityError{cause: verify.ErrAuthorSigInvalid}
	}
	return nil
}

type managedInstallError struct {
	cause     error
	uncertain bool
}

func (e managedInstallError) Error() string {
	if e.uncertain {
		return "install: managed operation failed; installation may already have completed"
	}
	return "install: managed registry operation refused"
}
func (e managedInstallError) Unwrap() error { return e.cause }
func redactManagedInstallError(err error, token string) error {
	if err == nil || token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return managedInstallError{cause: err, uncertain: strings.Contains(err.Error(), "may already have completed") || strings.Contains(err.Error(), "inspect installation status")}
}
