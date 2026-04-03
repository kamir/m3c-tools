package pocket

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// StageRecording copies a recording from the Pocket device to the local raw archive.
// The raw file is preserved permanently — the device copy is never modified.
func StageRecording(rec *Recording, cfg *Config) error {
	destDir := filepath.Join(cfg.RawDir, rec.Date)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("creating raw dir %s: %w", destDir, err)
	}

	destPath := filepath.Join(destDir, filepath.Base(rec.FilePath))

	// Skip if already staged
	if _, err := os.Stat(destPath); err == nil {
		rec.Status = "staged"
		log.Printf("[pocket] already staged: %s", rec.DedupeKey())
		return nil
	}

	if err := copyFile(rec.FilePath, destPath); err != nil {
		return fmt.Errorf("staging %s: %w", rec.DedupeKey(), err)
	}

	rec.Status = "staged"
	log.Printf("[pocket] staged: %s → %s", rec.DedupeKey(), destPath)
	return nil
}

// StageAll copies all recordings to the local raw archive.
// Returns the number of newly staged files.
func StageAll(recordings []Recording, cfg *Config) (int, error) {
	if err := cfg.EnsureDirs(); err != nil {
		return 0, err
	}

	staged := 0
	for i := range recordings {
		if recordings[i].Status == "synced" {
			continue
		}
		if err := StageRecording(&recordings[i], cfg); err != nil {
			log.Printf("[pocket] staging error: %v", err)
			continue
		}
		staged++
	}
	return staged, nil
}

// ListStaged returns recordings that exist in the local raw archive.
func ListStaged(cfg *Config) ([]Recording, error) {
	return Scan(cfg.RawDir)
}

// StagedPath returns the local path for a staged recording.
func StagedPath(rec Recording, cfg *Config) string {
	return filepath.Join(cfg.RawDir, rec.Date, filepath.Base(rec.FilePath))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
