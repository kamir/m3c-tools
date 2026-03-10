// Package importer provides batch audio file discovery and import.
package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Supported audio file extensions (lowercase, with leading dot).
var SupportedExtensions = map[string]bool{
	".wav":  true,
	".mp3":  true,
	".m4a":  true,
	".flac": true,
	".ogg":  true,
	".opus": true,
	".aac":  true,
	".wma":  true,
	".aiff": true,
	".webm": true,
}

// AudioFile represents a discovered audio file with metadata.
type AudioFile struct {
	Path string // Absolute path to the file.
	Name string // Base filename without directory.
	Ext  string // Lowercase extension including dot (e.g. ".wav").
	Size int64  // File size in bytes.
}

// ScanResult holds the outcome of a directory scan.
type ScanResult struct {
	Files      []AudioFile // Discovered audio files, sorted by path.
	ScannedDir string      // Root directory that was scanned.
	TotalFound int         // Number of audio files found.
}

// ScanDir recursively walks root and returns all files matching supported
// audio extensions. Symlinks are followed. Hidden directories (starting
// with '.') are skipped. The returned files are sorted by path.
func ScanDir(root string) (*ScanResult, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("scan dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan dir: %s is not a directory", root)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("scan dir: %w", err)
	}

	var files []AudioFile

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}

		// Skip hidden directories (but not the root itself).
		if info.IsDir() && path != absRoot && strings.HasPrefix(info.Name(), ".") {
			return filepath.SkipDir
		}

		if info.IsDir() {
			return nil
		}

		if IsAudioFile(path) {
			files = append(files, AudioFile{
				Path: path,
				Name: info.Name(),
				Ext:  strings.ToLower(filepath.Ext(path)),
				Size: info.Size(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan dir: %w", err)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	return &ScanResult{
		Files:      files,
		ScannedDir: absRoot,
		TotalFound: len(files),
	}, nil
}

// IsAudioFile reports whether the given filename has a supported audio extension.
func IsAudioFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return SupportedExtensions[ext]
}

// ExtensionList returns the sorted list of supported extensions.
func ExtensionList() []string {
	exts := make([]string, 0, len(SupportedExtensions))
	for ext := range SupportedExtensions {
		exts = append(exts, ext)
	}
	sort.Strings(exts)
	return exts
}
