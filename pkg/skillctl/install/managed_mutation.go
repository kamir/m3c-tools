package install

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// prepareManagedInstall selects retained trust history in the library, including
// calls with no CLI policy callback. Fresh retained signed evidence is sufficient;
// an optional newer list is adopted without creating missing enrollment.
func prepareManagedInstall(ctx context.Context, root *verify.TrustRoot, home string, evidence []byte) (*mutationstate.Store, error) {
	if !root.IsManaged() {
		if len(evidence) != 0 {
			return nil, fmt.Errorf("explicit mutation evidence requires a managed trust root: %w", verify.ErrRegistryNotTrusted)
		}
		return nil, nil
	}
	store, err := mutationstate.New(filepath.Join(home, ".claude", "mutation-state"), root)
	if err == nil && len(evidence) != 0 {
		_, err = store.Adopt(ctx, evidence)
	}
	if err != nil {
		return nil, managedInstallStateError(err)
	}
	return store, nil
}

func beginManagedInstall(ctx context.Context, store *mutationstate.Store, digest string) (*mutationstate.Session, error) {
	if store == nil {
		return nil, nil
	}
	session, err := store.Begin(ctx, verify.MutationInstall, digest)
	if err != nil {
		return nil, managedInstallStateError(err)
	}
	return session, nil
}

func managedInstallStateError(err error) error {
	if !errors.Is(err, verify.ErrRegistryNotTrusted) && (errors.Is(err, mutationstate.ErrNotEnrolled) || errors.Is(err, mutationstate.ErrInvalidState)) {
		err = errors.Join(verify.ErrRevocationStale, err)
	}
	return fmt.Errorf("managed install state: %w", err)
}

// closeManagedInstall reports uncertain completion when releasing the held lock
// fails. State and installation may already have committed; neither is rolled back.
func closeManagedInstall(session *mutationstate.Session, resultErr *error) {
	if session == nil {
		return
	}
	if err := session.Close(); err != nil {
		*resultErr = errors.Join(*resultErr, fmt.Errorf("managed install lock close failed; inspect installation status: %w", err))
	}
}

// validateMutationEvidenceSize must run before copying caller-owned bytes.
func validateMutationEvidenceSize(raw []byte) error {
	if len(raw) > mutationstate.MaxEvidenceBytes {
		return fmt.Errorf("managed install evidence exceeds size limit: %w", verify.ErrRegistryNotTrusted)
	}
	return nil
}
