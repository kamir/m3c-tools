package e2e

import (
	"os"
	"testing"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/whisper"
)

func TestWhisperBinaryFound(t *testing.T) {
	path, err := whisper.FindBinary()
	if err != nil {
		t.Skip("Whisper binary not found — install with: pip install openai-whisper")
	}
	t.Logf("Whisper binary: %s", path)
}

func TestWhisperTranscribe(t *testing.T) {
	if _, err := whisper.FindBinary(); err != nil {
		t.Skip("Whisper binary not found")
	}

	// Create a test WAV with silence (whisper will return empty/noise)
	wavData := er1.SilentWAV(2)
	tmpFile := "/tmp/m3c-tools-e2e-whisper-test.wav"
	os.WriteFile(tmpFile, wavData, 0644)
	defer os.Remove(tmpFile)

	result, err := whisper.Transcribe(tmpFile, "base", "en")
	if err != nil {
		t.Fatalf("Transcribe error: %v", err)
	}
	t.Logf("Whisper result: %d segments, text=%q", len(result.Segments), result.Text)
	// Silence may produce 0 or 1 segments — just check it didn't crash
}
