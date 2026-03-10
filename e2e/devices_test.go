package e2e

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/recorder"
)

// TestDevicesCLI builds and runs "m3c-tools devices" to verify the command
// lists PortAudio input devices. Requires PortAudio + a sound card.
func TestDevicesCLI(t *testing.T) {
	// Build the binary
	build := exec.Command("go", "build", "-o", "../build/m3c-tools-test", "../cmd/m3c-tools")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run "devices" subcommand
	cmd := exec.Command("../build/m3c-tools-test", "devices")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devices command failed: %v\n%s", err, out)
	}

	output := string(out)
	t.Logf("Output:\n%s", output)

	// Verify output contains expected markers
	if !strings.Contains(output, "Audio input devices") {
		t.Error("Expected 'Audio input devices' header in output")
	}
	if !strings.Contains(output, "Hz") {
		t.Error("Expected device sample rate (Hz) in output")
	}
	if !strings.Contains(output, "default input device") {
		t.Error("Expected default device legend in output")
	}
}

// TestDevicesPackage verifies recorder.ListInputDevices returns device info
// with the expected fields populated.
func TestDevicesPackage(t *testing.T) {
	devices, err := recorder.ListInputDevices()
	if err != nil {
		t.Fatalf("ListInputDevices: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("No input devices found")
	}

	hasDefault := false
	for _, d := range devices {
		if d.Name == "" {
			t.Error("Device with empty name")
		}
		if d.MaxInputChannels <= 0 {
			t.Errorf("Device %q: expected >0 input channels, got %d", d.Name, d.MaxInputChannels)
		}
		if d.DefaultSampleRate <= 0 {
			t.Errorf("Device %q: expected >0 sample rate, got %.0f", d.Name, d.DefaultSampleRate)
		}
		if d.IsDefault {
			hasDefault = true
		}
		t.Logf("Device: %s (%d ch, %.0f Hz, default=%v)", d.Name, d.MaxInputChannels, d.DefaultSampleRate, d.IsDefault)
	}
	if !hasDefault {
		t.Log("Warning: no device marked as default (may be expected on some systems)")
	}
}
