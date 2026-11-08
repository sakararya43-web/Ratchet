package authority

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// ExportFiles publishes public verified inputs for the core's existing pinned
// trust loader. The database is authoritative; a failed export is retried from
// its committed state, never reported as a successful core policy activation.
func (s *Service) ExportFiles(ctx context.Context, directory string) error {
	state, err := s.State(ctx)
	if err != nil {
		return err
	}
	store, err := trust.Import(state.Authority)
	if err != nil {
		return err
	}
	if _, err = store.GetGenesis(); err != nil {
		return nil
	}
	if err = writeAtomic(filepath.Join(directory, "authority.json"), state.Authority); err != nil {
		return err
	}
	bundle, err := store.GetActiveBundle()
	if err != nil {
		return nil
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, "bundle.json"), raw)
}
func writeAtomic(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".public-artifact-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return parent.Sync()
}
