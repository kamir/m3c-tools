// Package importer — audio import logic: scan, deduplicate, copy, and track.
//
// ImportAudio uses the configured ImportConfig properties (source, dest,
// content-type) and integrates with the tracking.FilesDB to skip
// already-imported files. New files are copied into per-file MEMORY folders
// under the destination directory and recorded in the tracking DB.
package importer

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

// ImportResult holds the outcome of a batch audio import operation.
type ImportResult struct {
	// Imported lists files that were newly copied and tracked.
	Imported []ImportedFile
	// Skipped lists files that were already tracked (imported, uploaded, or duplicate).
	Skipped []SkippedFile
	// Failed lists files where the import attempt encountered an error.
	Failed []FailedFile
	// TotalScanned is the number of audio files found in the source directory.
	TotalScanned int
}

// ImportedFile represents a successfully imported audio file.
type ImportedFile struct {
	Source   string // Original path in the source directory.
	Dest     string // Path in the MEMORY folder under dest directory.
	MemoryID string // MEMORY folder name (e.g., "MEMORY-20260309-120000").
	Hash     string // SHA-256 hash of the file content.
	Size     int64  // File size in bytes.
	Tags     string // Comma-separated tags derived from filename.
}

// SkippedFile represents a file that was skipped because it is already tracked.
type SkippedFile struct {
	Path   string     // File path in the source directory.
	Status FileStatus // Reason it was skipped (imported, uploaded, duplicate).
}

// FailedFile represents a file where the import attempt failed.
type FailedFile struct {
	Path  string // File path in the source directory.
	Error error  // The error that occurred.
}

// Summary returns a human-readable summary of the import result.
func (r *ImportResult) Summary() string {
	return fmt.Sprintf("scanned=%d imported=%d skipped=%d failed=%d",
		r.TotalScanned, len(r.Imported), len(r.Skipped), len(r.Failed))
}

// ImportAudio scans the configured source directory for audio files,
// checks each against the tracking DB to skip already-imported files,
// copies new files into MEMORY folders under the destination directory,
// and records them in the tracking DB.
//
// The cfg must have AudioSource, AudioDest, and ContentType set.
// If db is nil, all files are treated as new (no deduplication).
// If filterExts is non-empty, only files with those extensions are imported.
func ImportAudio(cfg *ImportConfig, db *tracking.FilesDB, filterExts []string) (*ImportResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("import config is nil")
	}

	srcDir, err := cfg.SourceDir()
	if err != nil {
		return nil, fmt.Errorf("resolve source: %w", err)
	}
	destDir, err := cfg.DestDir()
	if err != nil {
		return nil, fmt.Errorf("resolve dest: %w", err)
	}

	log.Printf("[import] START src=%s dest=%s content-type=%q", srcDir, destDir, cfg.ContentType)

	// Scan source directory.
	scanResult, err := ScanDir(srcDir)
	if err != nil {
		return nil, fmt.Errorf("scan source: %w", err)
	}

	// Apply extension filter if specified.
	files := scanResult.Files
	if len(filterExts) > 0 {
		filterSet := make(map[string]bool, len(filterExts))
		for _, ext := range filterExts {
			ext = normalizeExt(ext)
			filterSet[ext] = true
		}
		var filtered []AudioFile
		for _, f := range files {
			if filterSet[f.Ext] {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	result := &ImportResult{
		TotalScanned: len(files),
	}

	if len(files) == 0 {
		log.Printf("[import] DONE no audio files found in %s", srcDir)
		return result, nil
	}

	// Create the destination base directory if it doesn't exist.
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("create dest dir %s: %w", destDir, err)
	}

	// Build a status checker from the tracking DB.
	checker := StatusCheckerFromDB(db, "audio")

	for _, af := range files {
		status, checkErr := checker(af.Path)
		if checkErr != nil {
			log.Printf("[import] WARN status check failed for %s: %v", af.Name, checkErr)
			// Treat check failures as new to avoid skipping erroneously.
			status = StatusNew
		}

		// Skip files that are already tracked.
		if status != StatusNew {
			result.Skipped = append(result.Skipped, SkippedFile{
				Path:   af.Path,
				Status: status,
			})
			log.Printf("[import] SKIP %s status=%s", af.Name, status)
			continue
		}

		// Import this file: hash, copy to MEMORY folder, record in DB.
		imported, importErr := importSingleFile(af, destDir, cfg.ContentType, db)
		if importErr != nil {
			result.Failed = append(result.Failed, FailedFile{
				Path:  af.Path,
				Error: importErr,
			})
			log.Printf("[import] FAIL %s error=%v", af.Name, importErr)
			continue
		}

		result.Imported = append(result.Imported, *imported)
		log.Printf("[import] OK %s → %s hash=%s", af.Name, imported.MemoryID, imported.Hash[:12])
	}

	log.Printf("[import] DONE %s", result.Summary())
	return result, nil
}

// ImportAudioFiltered works like ImportAudio but when onlySourcePath is
// non-empty, only the file matching that path is imported. All other files
// are skipped. When onlySourcePath is empty, it behaves identically to
// ImportAudio (imports all new files).
func ImportAudioFiltered(cfg *ImportConfig, db *tracking.FilesDB, filterExts []string, onlySourcePath string) (*ImportResult, error) {
	onlySourcePath = strings.TrimSpace(onlySourcePath)
	if onlySourcePath == "" {
		return ImportAudio(cfg, db, filterExts)
	}

	if cfg == nil {
		return nil, fmt.Errorf("import config is nil")
	}

	srcDir, err := cfg.SourceDir()
	if err != nil {
		return nil, fmt.Errorf("resolve source: %w", err)
	}
	destDir, err := cfg.DestDir()
	if err != nil {
		return nil, fmt.Errorf("resolve dest: %w", err)
	}

	// Resolve the target path.
	absOnly, _ := filepath.Abs(onlySourcePath)
	info, statErr := os.Stat(absOnly)
	if statErr != nil {
		return nil, fmt.Errorf("file not found: %s", onlySourcePath)
	}

	af := AudioFile{
		Path: absOnly,
		Name: info.Name(),
		Size: info.Size(),
		Ext:  normalizeExt(filepath.Ext(info.Name())),
	}

	log.Printf("[import] START single-file src=%s dest=%s", af.Path, destDir)

	result := &ImportResult{TotalScanned: 1}

	// Check DB status.
	checker := StatusCheckerFromDB(db, "audio")
	status, checkErr := checker(af.Path)
	if checkErr != nil {
		log.Printf("[import] WARN status check failed for %s: %v", af.Name, checkErr)
		status = StatusNew
	}
	if status != StatusNew {
		result.Skipped = append(result.Skipped, SkippedFile{Path: af.Path, Status: status})
		log.Printf("[import] SKIP %s status=%s (already tracked)", af.Name, status)
		return result, nil
	}

	_ = srcDir // validated above
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("create dest dir %s: %w", destDir, err)
	}

	imported, importErr := importSingleFile(af, destDir, cfg.ContentType, db)
	if importErr != nil {
		result.Failed = append(result.Failed, FailedFile{Path: af.Path, Error: importErr})
		log.Printf("[import] FAIL %s error=%v", af.Name, importErr)
		return result, nil
	}

	result.Imported = append(result.Imported, *imported)
	log.Printf("[import] OK %s → %s hash=%s", af.Name, imported.MemoryID, imported.Hash[:12])
	return result, nil
}

// importSingleFile handles the import of one audio file:
//  1. Compute SHA-256 hash
//  2. Check for content-duplicate via hash (if DB available)
//  3. Create a MEMORY folder in destDir
//  4. Copy the audio file into the MEMORY folder
//  5. Write a tag.txt file with filename-derived tags
//  6. Record the file in the tracking DB
func importSingleFile(af AudioFile, destDir, contentType string, db *tracking.FilesDB) (*ImportedFile, error) {
	// Step 1: Hash the source file.
	hash, err := tracking.HashFile(af.Path)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}

	// Step 2: Content-duplicate check via hash (if DB available).
	if db != nil {
		processed, err := db.IsFileProcessed(hash, "audio")
		if err != nil {
			return nil, fmt.Errorf("duplicate check: %w", err)
		}
		if processed {
			return nil, fmt.Errorf("content duplicate (hash=%s)", hash[:12])
		}
	}

	// Step 3: Create a MEMORY folder with current timestamp.
	now := time.Now()
	memoryID := fmt.Sprintf("MEMORY-%s", now.Format("20060102-150405"))
	memoryPath := filepath.Join(destDir, memoryID)

	// Ensure unique folder name if one already exists at the same second.
	for i := 1; ; i++ {
		if _, err := os.Stat(memoryPath); os.IsNotExist(err) {
			break
		}
		memoryID = fmt.Sprintf("MEMORY-%s-%d", now.Format("20060102-150405"), i)
		memoryPath = filepath.Join(destDir, memoryID)
		if i > 100 {
			return nil, fmt.Errorf("could not create unique MEMORY folder after %d attempts", i)
		}
	}

	if err := os.MkdirAll(memoryPath, 0755); err != nil {
		return nil, fmt.Errorf("create memory folder: %w", err)
	}

	// Step 4: Copy the audio file into the MEMORY folder.
	destFile := filepath.Join(memoryPath, af.Name)
	if err := copyFile(af.Path, destFile); err != nil {
		return nil, fmt.Errorf("copy audio: %w", err)
	}

	// Step 5: Parse filename for tags and write tag.txt.
	info := impression.ParseFilename(af.Name)
	tags := impression.BuildImportTags(info.Tags)

	tagFilePath := filepath.Join(memoryPath, "tag.txt")
	tagContent := tags + "\n"
	if contentType != "" {
		tagContent += "content-type:" + contentType + "\n"
	}
	if err := os.WriteFile(tagFilePath, []byte(tagContent), 0644); err != nil {
		return nil, fmt.Errorf("write tags: %w", err)
	}

	// Step 6: Record in tracking DB (if available).
	if db != nil {
		if _, err := db.RecordFile(af.Path, hash, af.Size, "audio", memoryID); err != nil {
			// Non-fatal: file is copied but tracking record failed.
			log.Printf("[import] WARN tracking record failed for %s: %v", af.Name, err)
		}
	}

	return &ImportedFile{
		Source:   af.Path,
		Dest:     destFile,
		MemoryID: memoryID,
		Hash:     hash,
		Size:     af.Size,
		Tags:     tags,
	}, nil
}

// copyFile copies src to dst, creating dst if it doesn't exist.
// It preserves the file permissions of the source.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("create dest: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	return dstFile.Close()
}

// normalizeExt ensures an extension has a leading dot and is lowercase.
func normalizeExt(ext string) string {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return ext
}
