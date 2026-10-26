package artifact

import (
	"encoding/hex"
	"errors"
	"strings"
)

// ErrNativeMutationUnavailable marks selected native Enterprise work that needs
// the future durable native history path. It never authorizes legacy fallback.
var ErrNativeMutationUnavailable = errors.New("native Enterprise mutation requires durable verified revocation history; this version denies the operation")

// NativeEnterpriseIntent records explicit selection, not verified authority.
// Every nonnil instance is denied by native mutation consumers in this version.
type NativeEnterpriseIntent struct{ profileDigest, selectionID string }

// NewNativeEnterpriseIntent bounds immutable selection identifiers before copying.
func NewNativeEnterpriseIntent(profileDigest, selectionID string) (*NativeEnterpriseIntent, error) {
	for _, s := range []string{profileDigest, selectionID} {
		if len(s) != 64 || strings.ToLower(s) != s {
			return nil, ErrNativeMutationUnavailable
		}
		if _, err := hex.DecodeString(s); err != nil {
			return nil, ErrNativeMutationUnavailable
		}
	}
	return &NativeEnterpriseIntent{profileDigest: profileDigest, selectionID: selectionID}, nil
}

// RejectNativeEnterpriseMutation denies even a zero allocated intent. Nil only
// retains the unselected legacy contract; it is not a native Enterprise grant.
func RejectNativeEnterpriseMutation(intent *NativeEnterpriseIntent) error {
	if intent != nil {
		return ErrNativeMutationUnavailable
	}
	return nil
}
