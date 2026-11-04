package diagnostics

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile stores a report at an absolute path with owner-only permissions.
// An empty path disables output.
func WriteFile(path string, report Report) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return errors.New("diagnostic report path must be absolute")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open diagnostic report: %w", err)
	}
	if err = f.Chmod(0600); err != nil {
		return errors.Join(fmt.Errorf("restrict diagnostic report permissions: %w", err), f.Close())
	}
	writeErr := WriteJSON(f, report)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}
