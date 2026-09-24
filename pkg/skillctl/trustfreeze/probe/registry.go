package probe

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrDuplicateProbe is returned when a probe id is registered twice.
var ErrDuplicateProbe = errors.New("probe: duplicate probe id")

// Registry holds probes by id. Iteration order is sorted by id, so every
// consumer runs and lists probes deterministically.
type Registry struct {
	mu     sync.RWMutex
	probes map[string]Probe
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{probes: map[string]Probe{}} }

// Register adds p after validating its descriptor. A second probe with the
// same id is an error; nothing is replaced.
func (r *Registry) Register(p Probe) error {
	if p == nil {
		return fmt.Errorf("%w: nil probe", ErrInvalidDescriptor)
	}
	d := p.Descriptor()
	if err := d.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.probes[d.ID]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateProbe, d.ID)
	}
	r.probes[d.ID] = p
	return nil
}

// Get returns the probe with id.
func (r *Registry) Get(id string) (Probe, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.probes[id]
	return p, ok
}

// IDs returns the registered ids, sorted.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.probes))
	for id := range r.probes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Probes returns the registered probes, sorted by id.
func (r *Registry) Probes() []Probe {
	ids := r.IDs()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Probe, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.probes[id])
	}
	return out
}
