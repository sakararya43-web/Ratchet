package graph

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type generation struct {
	snapshot *Snapshot
	ready    bool
}
type tenantGraph struct {
	current atomic.Pointer[generation]
	changed chan struct{}
}
type Registry struct {
	mu      sync.Mutex
	tenants map[string]*tenantGraph
	maxWait time.Duration
}

func NewRegistry(maxWait time.Duration) (*Registry, error) {
	if maxWait <= 0 || maxWait > 30*time.Second {
		return nil, ErrInvalid
	}
	return &Registry{tenants: map[string]*tenantGraph{}, maxWait: maxWait}, nil
}
func (r *Registry) tenant(id string) *tenantGraph {
	t := r.tenants[id]
	if t == nil {
		t = &tenantGraph{changed: make(chan struct{})}
		r.tenants[id] = t
	}
	return t
}
func (r *Registry) Publish(tenant string, s *Snapshot) error {
	if tenant == "" || s == nil || s.version < 1 {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tenant(tenant)
	if old := t.current.Load(); old != nil && old.snapshot.version >= s.version {
		return fmt.Errorf("%w: graph version regression", ErrInvalid)
	}
	t.current.Store(&generation{snapshot: s, ready: true})
	close(t.changed)
	t.changed = make(chan struct{})
	return nil
}
func (r *Registry) Invalidate(tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tenant(tenant)
	if old := t.current.Load(); old != nil {
		t.current.Store(&generation{snapshot: old.snapshot, ready: false})
	}
	close(t.changed)
	t.changed = make(chan struct{})
}
func (r *Registry) Get(ctx context.Context, tenant string, minVersion int64) (*Snapshot, error) {
	if tenant == "" || minVersion < 0 {
		return nil, ErrInvalid
	}
	wait, cancel := context.WithTimeout(ctx, r.maxWait)
	defer cancel()
	for {
		r.mu.Lock()
		t := r.tenant(tenant)
		state := t.current.Load()
		changed := t.changed
		r.mu.Unlock()
		if state != nil && state.ready && state.snapshot.version >= minVersion {
			return state.snapshot, nil
		}
		select {
		case <-wait.Done():
			return nil, fmt.Errorf("%w: minimum version %d", ErrUnavailable, minVersion)
		case <-changed:
		}
	}
}
