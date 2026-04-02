package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/importer"
)

func TestImporterScanDir(t *testing.T) {
	// Create a temp directory tree with mixed files
	root := t.TempDir()

	// Subdirectories
	sub1 := filepath.Join(root, "session1")
	sub2 := filepath.Join(root, "session1", "nested")
	hidden := filepath.Join(root, ".hidden")
	if err := os.MkdirAll(sub2, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create test files: audio and non-audio
	testFiles := map[string]string{
		filepath.Join(root, "intro.wav"):      "wav",
		filepath.Join(root, "notes.txt"):      "txt",
		filepath.Join(sub1, "track1.mp3"):     "mp3",
		filepath.Join(sub1, "track2.M4A"):     "m4a-upper",
		filepath.Join(sub2, "deep.flac"):      "flac",
		filepath.Join(sub2, "image.png"):      "png",
		filepath.Join(root, "podcast.ogg"):    "ogg",
		filepath.Join(root, "voice.opus"):     "opus",
		filepath.Join(hidden, "secret.wav"):   "hidden-wav",
		filepath.Join(root, "README.md"):      "md",
		filepath.Join(root, "interview.aac"):  "aac",
		filepath.Join(root, "classical.aiff"): "aiff",
		filepath.Join(root, "recording.webm"): "webm",
	}
	for path, content := range testFiles {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir error: %v", err)
	}

	// Expect: intro.wav, track1.mp3, track2.M4A, deep.flac, podcast.ogg,
	//         voice.opus, interview.aac, classical.aiff, recording.webm = 9
	// Excluded: notes.txt, image.png, README.md (non-audio),
	//           secret.wav (hidden dir)
	expectedCount := 9
	if result.TotalFound != expectedCount {
		t.Errorf("Expected %d audio files, got %d", expectedCount, result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s", f.Path)
		}
	}

	// Verify files are sorted by path
	for i := 1; i < len(result.Files); i++ {
		if result.Files[i].Path < result.Files[i-1].Path {
			t.Error("Files not sorted by path")
			break
		}
	}

	// Verify each file has correct metadata
	for _, f := range result.Files {
		if f.Name == "" {
			t.Error("AudioFile.Name is empty")
		}
		if f.Ext == "" {
			t.Error("AudioFile.Ext is empty")
		}
		if f.Size == 0 {
			t.Error("AudioFile.Size is 0")
		}
		t.Logf("  %s (ext=%s, size=%d)", f.Name, f.Ext, f.Size)
	}
}

func TestImporterScanDirEmpty(t *testing.T) {
	root := t.TempDir()
	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir error: %v", err)
	}
	if result.TotalFound != 0 {
		t.Errorf("Expected 0 files in empty dir, got %d", result.TotalFound)
	}
}

func TestImporterScanDirNotExist(t *testing.T) {
	_, err := importer.ScanDir("/nonexistent/path/12345")
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}
}

func TestImporterScanDirNotDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := importer.ScanDir(f)
	if err == nil {
		t.Error("Expected error for non-directory path")
	}
}

func TestImporterIsAudioFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"song.wav", true},
		{"song.WAV", true},
		{"song.mp3", true},
		{"song.m4a", true},
		{"song.flac", true},
		{"song.ogg", true},
		{"song.opus", true},
		{"song.aac", true},
		{"song.wma", true},
		{"song.aiff", true},
		{"song.webm", true},
		{"image.png", false},
		{"doc.pdf", false},
		{"noext", false},
		{"", false},
	}
	for _, tc := range cases {
		got := importer.IsAudioFile(tc.path)
		if got != tc.want {
			t.Errorf("IsAudioFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestImporterExtensionList(t *testing.T) {
	exts := importer.ExtensionList()
	if len(exts) == 0 {
		t.Error("ExtensionList returned empty")
	}
	// Verify sorted
	for i := 1; i < len(exts); i++ {
		if exts[i] < exts[i-1] {
			t.Error("ExtensionList not sorted")
			break
		}
	}
	t.Logf("Supported extensions: %v", exts)
}

func TestImporterScanDirHiddenSkip(t *testing.T) {
	root := t.TempDir()
	hidden := filepath.Join(root, ".dotdir")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Audio file in hidden dir should be excluded
	if err := os.WriteFile(filepath.Join(hidden, "secret.wav"), []byte("wav"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Audio file in visible dir should be included
	if err := os.WriteFile(filepath.Join(root, "visible.wav"), []byte("wav"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir error: %v", err)
	}
	if result.TotalFound != 1 {
		t.Errorf("Expected 1 file (hidden excluded), got %d", result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s", f.Path)
		}
	}
}

func TestImporterScanDirCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	files := []string{"lower.wav", "UPPER.WAV", "Mixed.Mp3", "camel.FlaC"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(root, f), []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir error: %v", err)
	}
	if result.TotalFound != 4 {
		t.Errorf("Expected 4 audio files (case insensitive), got %d", result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s (ext=%s)", f.Name, f.Ext)
		}
	}

	// All extensions should be normalized to lowercase
	for _, f := range result.Files {
		if f.Ext != strings.ToLower(f.Ext) {
			t.Errorf("Extension not normalized: %s", f.Ext)
		}
	}
}

func TestImporterScanDirAbsPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "test.wav"), []byte("wav"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir error: %v", err)
	}

	// ScannedDir should be absolute
	if !filepath.IsAbs(result.ScannedDir) {
		t.Errorf("ScannedDir should be absolute, got %s", result.ScannedDir)
	}

	// Each file path should be absolute
	for _, f := range result.Files {
		if !filepath.IsAbs(f.Path) {
			t.Errorf("File path should be absolute, got %s", f.Path)
		}
	}
}

func TestImporterScanDirDeepNesting(t *testing.T) {
	root := t.TempDir()
	deepDir := filepath.Join(root, "a", "b", "c", "d")
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "deep.mp3"), []byte("mp3"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.wav"), []byte("wav"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir error: %v", err)
	}
	if result.TotalFound != 2 {
		t.Errorf("Expected 2 files (across nested dirs), got %d", result.TotalFound)
	}
}

func TestImporterExtensionCoverage(t *testing.T) {
	// Ensure the supported extensions map covers common audio formats
	required := []string{".wav", ".mp3", ".m4a", ".flac", ".ogg", ".opus", ".aac", ".aiff", ".webm"}
	exts := importer.ExtensionList()
	extSet := make(map[string]bool)
	for _, e := range exts {
		extSet[e] = true
	}

	for _, r := range required {
		if !extSet[r] {
			t.Errorf("Missing required audio extension: %s", r)
		}
	}
}

func TestImporterCLIExtensions(t *testing.T) {
	binPath, _ := filepath.Abs(filepath.Join("..", "build", "m3c-tools"))
	if _, err := os.Stat(binPath); err != nil {
		repoRoot, _ := filepath.Abs("..")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = repoRoot
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	out, err := exec.Command(binPath, "import-audio", "--extensions").CombinedOutput()
	if err != nil {
		t.Fatalf("import-audio --extensions failed: %v\nOutput: %s", err, out)
	}
	output := string(out)
	if !strings.Contains(output, ".wav") {
		t.Error("expected .wav in extensions output")
	}
	if !strings.Contains(output, ".mp3") {
		t.Error("expected .mp3 in extensions output")
	}
	if !strings.Contains(output, "Supported audio extensions") {
		t.Error("expected header in extensions output")
	}
	t.Logf("CLI extensions output:\n%s", output)
}

func TestImporterCLIScanDir(t *testing.T) {
	root := t.TempDir()
	// Create test audio files
	for _, name := range []string{"track1.wav", "track2.mp3", "track3.flac"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("audio-data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	// Create non-audio file
	if err := os.WriteFile(filepath.Join(root, "readme.txt"), []byte("text"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	binPath, _ := filepath.Abs(filepath.Join("..", "build", "m3c-tools"))
	if _, err := os.Stat(binPath); err != nil {
		repoRoot, _ := filepath.Abs("..")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = repoRoot
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	out, err := exec.Command(binPath, "import-audio", root).CombinedOutput()
	if err != nil {
		t.Fatalf("import-audio scan failed: %v\nOutput: %s", err, out)
	}
	output := string(out)

	// Verify output mentions found files
	if !strings.Contains(output, "Found 3 audio file") {
		t.Errorf("expected 'Found 3 audio file(s)', got:\n%s", output)
	}
	if !strings.Contains(output, "track1.wav") {
		t.Error("expected track1.wav in output")
	}
	if !strings.Contains(output, "track2.mp3") {
		t.Error("expected track2.mp3 in output")
	}
	if !strings.Contains(output, "track3.flac") {
		t.Error("expected track3.flac in output")
	}
	// readme.txt should NOT appear
	if strings.Contains(output, "readme.txt") {
		t.Error("non-audio file readme.txt should not appear in output")
	}
	t.Logf("CLI scan output:\n%s", output)
}

func TestImporterCLIEmptyDir(t *testing.T) {
	root := t.TempDir()

	binPath, _ := filepath.Abs(filepath.Join("..", "build", "m3c-tools"))
	if _, err := os.Stat(binPath); err != nil {
		repoRoot, _ := filepath.Abs("..")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = repoRoot
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	out, err := exec.Command(binPath, "import-audio", root).CombinedOutput()
	if err != nil {
		t.Fatalf("import-audio scan failed: %v\nOutput: %s", err, out)
	}
	output := string(out)
	if !strings.Contains(output, "No audio files found") {
		t.Errorf("expected 'No audio files found', got:\n%s", output)
	}
}

func TestImporterCLINonexistentDir(t *testing.T) {
	binPath, _ := filepath.Abs(filepath.Join("..", "build", "m3c-tools"))
	if _, err := os.Stat(binPath); err != nil {
		repoRoot, _ := filepath.Abs("..")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = repoRoot
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	out, err := exec.Command(binPath, "import-audio", "/nonexistent/dir/12345").CombinedOutput()
	if err == nil {
		t.Error("expected non-zero exit for nonexistent directory")
	}
	output := string(out)
	if !strings.Contains(output, "Scan error") {
		t.Errorf("expected 'Scan error' message, got:\n%s", output)
	}
}

func TestImporterCLINoArgs(t *testing.T) {
	binPath, _ := filepath.Abs(filepath.Join("..", "build", "m3c-tools"))
	if _, err := os.Stat(binPath); err != nil {
		repoRoot, _ := filepath.Abs("..")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = repoRoot
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}

	cmd := exec.Command(binPath, "import-audio")
	// Run outside repo root so .env isn't loaded into the subprocess.
	cmd.Dir = t.TempDir()
	// Explicitly remove IMPORT_AUDIO_SOURCE in child env.
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "IMPORT_AUDIO_SOURCE=") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected non-zero exit for no arguments")
	}
	output := string(out)
	if output != "" && !strings.Contains(output, "Usage") {
		t.Errorf("expected usage message, got:\n%s", output)
	}
}

func TestImporterScanFromEnvNotSet(t *testing.T) {
	t.Setenv("IMPORT_AUDIO_SOURCE", "")
	_, err := importer.ScanFromEnv(nil)
	if err == nil {
		t.Error("expected error when IMPORT_AUDIO_SOURCE is not set")
	}
	if !strings.Contains(err.Error(), "IMPORT_AUDIO_SOURCE") {
		t.Errorf("expected error to mention IMPORT_AUDIO_SOURCE, got: %v", err)
	}
}

func TestImporterScanFromEnvAllFormats(t *testing.T) {
	root := t.TempDir()
	t.Setenv("IMPORT_AUDIO_SOURCE", root)

	// Create files of various types
	for _, name := range []string{"a.mp3", "b.wav", "c.flac", "d.ogg", "e.txt", "f.png"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanFromEnv(nil)
	if err != nil {
		t.Fatalf("ScanFromEnv error: %v", err)
	}

	// Should find 4 audio files (mp3, wav, flac, ogg) but not txt or png
	if result.TotalFound != 4 {
		t.Errorf("expected 4 audio files, got %d", result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s", f.Name)
		}
	}
}

func TestImporterScanFromEnvFiltered(t *testing.T) {
	root := t.TempDir()
	t.Setenv("IMPORT_AUDIO_SOURCE", root)

	// Create files of various audio types
	for _, name := range []string{"a.mp3", "b.wav", "c.flac", "d.ogg"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanFromEnv([]string{".mp3", ".wav"})
	if err != nil {
		t.Fatalf("ScanFromEnv error: %v", err)
	}

	// Should find only mp3 and wav
	if result.TotalFound != 2 {
		t.Errorf("expected 2 filtered files, got %d", result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s (ext=%s)", f.Name, f.Ext)
		}
	}

	for _, f := range result.Files {
		if f.Ext != ".mp3" && f.Ext != ".wav" {
			t.Errorf("unexpected extension in filtered result: %s", f.Ext)
		}
	}
}

func TestImporterScanFromEnvFilterNoDot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("IMPORT_AUDIO_SOURCE", root)

	for _, name := range []string{"a.mp3", "b.wav", "c.flac"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	// Filter with extensions without leading dot — should still work
	result, err := importer.ScanFromEnv([]string{"mp3", "wav"})
	if err != nil {
		t.Fatalf("ScanFromEnv error: %v", err)
	}
	if result.TotalFound != 2 {
		t.Errorf("expected 2 files with dot-less filter, got %d", result.TotalFound)
	}
}

func TestImporterScanMP3WAV(t *testing.T) {
	root := t.TempDir()
	t.Setenv("IMPORT_AUDIO_SOURCE", root)

	// Create mixed audio files
	for _, name := range []string{"a.mp3", "b.wav", "c.flac", "d.ogg", "e.mp3"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanMP3WAV()
	if err != nil {
		t.Fatalf("ScanMP3WAV error: %v", err)
	}

	// Should find only mp3 and wav: a.mp3, b.wav, e.mp3
	if result.TotalFound != 3 {
		t.Errorf("expected 3 mp3/wav files, got %d", result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s (ext=%s)", f.Name, f.Ext)
		}
	}

	for _, f := range result.Files {
		if f.Ext != ".mp3" && f.Ext != ".wav" {
			t.Errorf("ScanMP3WAV returned non mp3/wav file: %s (ext=%s)", f.Name, f.Ext)
		}
	}
}

func TestImporterScanMP3WAVRecursive(t *testing.T) {
	root := t.TempDir()
	t.Setenv("IMPORT_AUDIO_SOURCE", root)

	// Create nested directory structure
	sub := filepath.Join(root, "subdir", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	for _, name := range []string{
		filepath.Join(root, "top.mp3"),
		filepath.Join(root, "subdir", "mid.wav"),
		filepath.Join(sub, "deep.mp3"),
		filepath.Join(sub, "deep.flac"), // should be excluded by mp3/wav filter
	} {
		if err := os.WriteFile(name, []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanMP3WAV()
	if err != nil {
		t.Fatalf("ScanMP3WAV error: %v", err)
	}

	if result.TotalFound != 3 {
		t.Errorf("expected 3 mp3/wav files recursively, got %d", result.TotalFound)
		for _, f := range result.Files {
			t.Logf("  found: %s", f.Path)
		}
	}
}

func TestImporterScanFromEnvNonexistent(t *testing.T) {
	t.Setenv("IMPORT_AUDIO_SOURCE", "/nonexistent/path/12345")
	_, err := importer.ScanFromEnv(nil)
	if err == nil {
		t.Error("expected error for nonexistent IMPORT_AUDIO_SOURCE directory")
	}
}
