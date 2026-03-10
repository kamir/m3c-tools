package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadImportConfig_Defaults(t *testing.T) {
	// Clear all IMPORT_ env vars to test defaults.
	for _, key := range []string{
		"IMPORT_AUDIO_SOURCE",
		"IMPORT_AUDIO_DEST",
		"IMPORT_CONTENT_TYPE",
		"IMPORT_TRACKER_FILE",
	} {
		t.Setenv(key, "")
	}

	cfg, err := LoadImportConfig()
	if err != nil {
		t.Fatalf("LoadImportConfig() error: %v", err)
	}

	if cfg.AudioSource != "" {
		t.Errorf("AudioSource = %q, want empty", cfg.AudioSource)
	}
	if cfg.ContentType != "Audio-Track vom Diktiergerät" {
		t.Errorf("ContentType = %q, want default", cfg.ContentType)
	}

	// AudioDest and TrackerFile should be tilde-expanded.
	home, _ := os.UserHomeDir()
	wantDest := filepath.Join(home, "ER1")
	if cfg.AudioDest != wantDest {
		t.Errorf("AudioDest = %q, want %q", cfg.AudioDest, wantDest)
	}
	wantTracker := filepath.Join(home, ".m3c-tools", "transcript_tracker.md")
	if cfg.TrackerFile != wantTracker {
		t.Errorf("TrackerFile = %q, want %q", cfg.TrackerFile, wantTracker)
	}
}

func TestLoadImportConfig_EnvOverrides(t *testing.T) {
	t.Setenv("IMPORT_AUDIO_SOURCE", "/tmp/audio-src")
	t.Setenv("IMPORT_AUDIO_DEST", "/tmp/audio-dest")
	t.Setenv("IMPORT_CONTENT_TYPE", "Custom-Type")
	t.Setenv("IMPORT_TRACKER_FILE", "/tmp/tracker.md")

	cfg, err := LoadImportConfig()
	if err != nil {
		t.Fatalf("LoadImportConfig() error: %v", err)
	}

	if cfg.AudioSource != "/tmp/audio-src" {
		t.Errorf("AudioSource = %q, want /tmp/audio-src", cfg.AudioSource)
	}
	if cfg.AudioDest != "/tmp/audio-dest" {
		t.Errorf("AudioDest = %q, want /tmp/audio-dest", cfg.AudioDest)
	}
	if cfg.ContentType != "Custom-Type" {
		t.Errorf("ContentType = %q, want Custom-Type", cfg.ContentType)
	}
	if cfg.TrackerFile != "/tmp/tracker.md" {
		t.Errorf("TrackerFile = %q, want /tmp/tracker.md", cfg.TrackerFile)
	}
}

func TestLoadImportConfig_TildeExpansion(t *testing.T) {
	t.Setenv("IMPORT_AUDIO_SOURCE", "~/my-audio")
	t.Setenv("IMPORT_AUDIO_DEST", "~/my-dest")
	t.Setenv("IMPORT_CONTENT_TYPE", "")
	t.Setenv("IMPORT_TRACKER_FILE", "~/my-tracker.md")

	cfg, err := LoadImportConfig()
	if err != nil {
		t.Fatalf("LoadImportConfig() error: %v", err)
	}

	home, _ := os.UserHomeDir()

	if !strings.HasPrefix(cfg.AudioSource, home) {
		t.Errorf("AudioSource %q should start with %q", cfg.AudioSource, home)
	}
	if !strings.HasPrefix(cfg.AudioDest, home) {
		t.Errorf("AudioDest %q should start with %q", cfg.AudioDest, home)
	}
	if !strings.HasPrefix(cfg.TrackerFile, home) {
		t.Errorf("TrackerFile %q should start with %q", cfg.TrackerFile, home)
	}
}

func TestImportConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ImportConfig
		wantErr string
	}{
		{
			name:    "missing source",
			cfg:     ImportConfig{AudioDest: "/d", ContentType: "t", TrackerFile: "/f"},
			wantErr: "IMPORT_AUDIO_SOURCE",
		},
		{
			name:    "missing dest",
			cfg:     ImportConfig{AudioSource: "/s", ContentType: "t", TrackerFile: "/f"},
			wantErr: "IMPORT_AUDIO_DEST",
		},
		{
			name:    "missing content type",
			cfg:     ImportConfig{AudioSource: "/s", AudioDest: "/d", TrackerFile: "/f"},
			wantErr: "IMPORT_CONTENT_TYPE",
		},
		{
			name:    "missing tracker",
			cfg:     ImportConfig{AudioSource: "/s", AudioDest: "/d", ContentType: "t"},
			wantErr: "IMPORT_TRACKER_FILE",
		},
		{
			name: "valid",
			cfg:  ImportConfig{AudioSource: "/s", AudioDest: "/d", ContentType: "t", TrackerFile: "/f"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestImportConfig_Summary(t *testing.T) {
	cfg := ImportConfig{
		AudioSource: "/src",
		AudioDest:   "/dest",
		ContentType: "Audio-Type",
		TrackerFile: "/tracker.md",
	}
	s := cfg.Summary()
	if !strings.Contains(s, "/src") {
		t.Errorf("Summary() = %q, want containing /src", s)
	}
	if !strings.Contains(s, "Audio-Type") {
		t.Errorf("Summary() = %q, want containing Audio-Type", s)
	}
}

func TestExpandTilde(t *testing.T) {
	// Empty string stays empty.
	out, err := expandTilde("")
	if err != nil || out != "" {
		t.Errorf("expandTilde(\"\") = %q, %v", out, err)
	}

	// Absolute path unchanged.
	out, err = expandTilde("/absolute/path")
	if err != nil || out != "/absolute/path" {
		t.Errorf("expandTilde(/absolute/path) = %q, %v", out, err)
	}

	// Tilde expanded.
	out, err = expandTilde("~/test")
	if err != nil {
		t.Fatalf("expandTilde(~/test) error: %v", err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, "test")
	if out != want {
		t.Errorf("expandTilde(~/test) = %q, want %q", out, want)
	}
}
