package policy

import (
	"context"
	"os"

	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// FileSource loads fresh peer stores so an external Authority process can
// publish changes without sharing mutable registry pointers with core workers.
type FileSource struct {
	Manager       Manager
	AuthorityFile string
	BundleFile    string
}

func (s FileSource) Refresh(ctx context.Context) error {
	info, err := os.Stat(s.AuthorityFile)
	if err != nil {
		return ErrUnavailable
	}
	if info.Size() > 16<<20 {
		return ErrInvalid
	}
	authority, err := trust.NewStore(s.AuthorityFile)
	if err != nil {
		return ErrInvalid
	}
	m := s.Manager
	m.Authority = authority
	if err := m.RefreshRegistry(ctx); err != nil {
		return err
	}
	if s.BundleFile != "" {
		info, err := os.Stat(s.BundleFile)
		if err != nil {
			return ErrUnavailable
		}
		if info.Size() > 1<<20 {
			return ErrInvalid
		}
		raw, err := os.ReadFile(s.BundleFile)
		if err != nil {
			return ErrUnavailable
		}
		return m.Activate(ctx, raw)
	}
	_, err = m.Engine.Current(m.Tenant)
	return err
}
