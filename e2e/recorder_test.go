package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/recorder"
)

func TestRecorderListDevices(t *testing.T) {
	devices, err := recorder.ListInputDevices()
	if err != nil {
		t.Fatalf("ListInputDevices error: %v", err)
	}
	if len(devices) == 0 {
		t.Error("No input devices found")
	}
	for _, d := range devices {
		marker := "  "
		if d.IsDefault {
			marker = "* "
		}
		t.Logf("%s%s (max %d ch, %.0f Hz)", marker, d.Name, d.MaxInputChannels, d.DefaultSampleRate)
	}
}

func TestRecorderEncodeWAV(t *testing.T) {
	samples := make([]int16, 16000) // 1 second of silence
	wav := recorder.EncodeWAV(samples)

	// Check WAV header
	if string(wav[:4]) != "RIFF" {
		t.Error("Missing RIFF header")
	}
	if string(wav[8:12]) != "WAVE" {
		t.Error("Missing WAVE marker")
	}
	expectedSize := 44 + 16000*2 // header + data
	if len(wav) != expectedSize {
		t.Errorf("Expected %d bytes, got %d", expectedSize, len(wav))
	}
	t.Logf("WAV: %d bytes", len(wav))
}

func TestRecorderStats(t *testing.T) {
	samples := []int16{0, 100, -200, 300, -400, 500}
	stats := recorder.Stats(samples)
	if stats.PeakAmplitude != 500 {
		t.Errorf("Expected peak 500, got %d", stats.PeakAmplitude)
	}
	if stats.Samples != 6 {
		t.Errorf("Expected 6 samples, got %d", stats.Samples)
	}
}

func TestRecorderWriteWAV(t *testing.T) {
	// Generate synthetic audio: 1 second of a simple tone pattern
	samples := make([]int16, recorder.SampleRate) // 1 second
	for i := range samples {
		// Simple triangle wave so we have non-zero data
		samples[i] = int16((i % 400) - 200)
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "test_record.wav")
	if err := recorder.WriteWAV(tmpFile, samples); err != nil {
		t.Fatalf("WriteWAV error: %v", err)
	}

	// Verify file exists and has correct size
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	expectedSize := int64(44 + recorder.SampleRate*2) // WAV header + PCM data
	if info.Size() != expectedSize {
		t.Errorf("Expected file size %d, got %d", expectedSize, info.Size())
	}

	// Read back and verify WAV header
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if string(data[:4]) != "RIFF" {
		t.Error("Missing RIFF header in written file")
	}
	if string(data[8:12]) != "WAVE" {
		t.Error("Missing WAVE marker in written file")
	}
	if string(data[36:40]) != "data" {
		t.Error("Missing data chunk marker in written file")
	}

	// Verify stats on the samples
	stats := recorder.Stats(samples)
	if stats.PeakAmplitude == 0 {
		t.Error("Expected non-zero peak amplitude")
	}
	if stats.Duration < 0.9 || stats.Duration > 1.1 {
		t.Errorf("Expected ~1.0s duration, got %.2f", stats.Duration)
	}

	t.Logf("WriteWAV: %s (%d bytes), peak=%d, duration=%.2fs",
		tmpFile, info.Size(), stats.PeakAmplitude, stats.Duration)
}

func TestRecorderRecord2Seconds(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping recording in short mode")
	}
	samples, err := recorder.Record(2)
	if err != nil {
		t.Fatalf("Record error: %v", err)
	}
	if len(samples) < 30000 { // ~2 seconds at 16kHz
		t.Errorf("Expected ~32000 samples, got %d", len(samples))
	}
	stats := recorder.Stats(samples)
	t.Logf("Recorded %d samples (%.1fs), peak=%d, avg=%.0f",
		stats.Samples, stats.Duration, stats.PeakAmplitude, stats.AverageAmplitude)
}
