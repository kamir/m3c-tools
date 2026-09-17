// register.go: the ONE place a backend name resolves to an implementation
// (SPEC-0455 REQ-4.1/REQ-4.2, unit T-01).
//
// A backend name is an interface in the claims sense: it appears in
// configuration, help text and documentation, and renaming one is an API
// break that changes both sides in the same commit. Names() feeds every
// surface that lists the known names, so the list has one carrier.
//
// T-01 registers exactly one name. The selector surface
// (SKILLCTL_AUDIT_BACKEND, decision D8) arrives with T-02; the git and
// kafka entries are blocked on decisions D2 and D4+EC respectively.
package auditexport

import (
	"fmt"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
)

// Names lists the registered backend names, the population every "known
// backends" claim quotes (acceptance A4).
func Names() []string { return []string{"er1"} }

// New resolves a backend name. The er1 backend needs the caller's
// configured IngestClient; future backends will grow a richer config
// surface with T-02 and are refused by name until they exist.
func New(name string, client *outbox.IngestClient) (Backend, error) {
	switch name {
	case "er1":
		if client == nil {
			return nil, fmt.Errorf("audit export backend %q needs a configured ingest client", name)
		}
		return &ER1{Client: client}, nil
	default:
		return nil, fmt.Errorf("unknown audit export backend %q (known: %s)", name, strings.Join(Names(), ", "))
	}
}
