package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// WritePrivateJSON replaces a local receipt/cursor only after flushing its bytes.
func WritePrivateJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".ratchet-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	// Linux runtime receipts must survive a power loss after the rename as well.
	// Windows does not support fsync of directory handles.
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return err
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}
