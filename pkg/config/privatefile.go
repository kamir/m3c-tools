package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WritePrivateFile atomically replaces a regular file with owner-only content.
// Existing symlinks and other non-regular files are refused. On Windows, the
// temporary file is created with a protected owner-only DACL.
// A failed write leaves the previous target intact; temporary files are removed.
func WritePrivateFile(path string, data []byte) error {
	return writePrivateFile(path, data, os.Rename)
}

func writePrivateFile(path string, data []byte, rename func(string, string) error) (resultErr error) {
	// #nosec G703 -- path is the caller-selected local config/profile destination; this helper is not a sandbox or an archive extractor.
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("private file target is not a regular file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect private file: %w", err)
	}
	file, err := createPrivateTemp(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("create private file: %w", err)
	}
	tempPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
		// #nosec G703 -- tempPath comes only from the private temporary file created above, never from file content.
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary private file: %w", err))
		}
	}()
	written, err := file.Write(data)
	if err != nil {
		return fmt.Errorf("write private file: %w", err)
	}
	if written != len(data) {
		return fmt.Errorf("write private file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync private file: %w", err)
	}
	err = file.Close()
	closed = true
	if err != nil {
		return fmt.Errorf("close private file: %w", err)
	}
	if err := rename(tempPath, path); err != nil {
		return fmt.Errorf("replace private file: %w", err)
	}
	return nil
}
