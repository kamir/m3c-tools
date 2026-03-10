// POC 4: Audio Recording with PortAudio
//
// Validates:
//   - PortAudio Go bindings + cgo linking
//   - Default input device detection
//   - Microphone capture to buffer
//   - WAV file writing (16-bit PCM, 16kHz mono — whisper-compatible)
//   - Timed recording with clean shutdown
//
// Prerequisites:
//   - brew install portaudio
//
// Run: go run ./cmd/poc-recorder [output.wav] [duration_seconds]
// Default: recording.wav, 5 seconds
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gordonklaus/portaudio"
)

const (
	sampleRate = 16000 // 16kHz — whisper's native sample rate
	channels   = 1     // mono
	bitsPerSample = 16
)

func main() {
	output := "recording.wav"
	duration := 5

	if len(os.Args) > 1 {
		output = os.Args[1]
	}
	if len(os.Args) > 2 {
		d, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid duration: %s\n", os.Args[2])
			os.Exit(1)
		}
		duration = d
	}

	fmt.Println("POC Audio Recording (PortAudio)")
	fmt.Printf("  Output: %s\n", output)
	fmt.Printf("  Duration: %d seconds\n", duration)
	fmt.Printf("  Format: %d Hz, %d-bit, mono (whisper-compatible)\n\n", sampleRate, bitsPerSample)

	// Step 1: Initialize PortAudio
	fmt.Println("=== Initializing PortAudio ===")
	if err := portaudio.Initialize(); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing PortAudio: %v\n", err)
		os.Exit(1)
	}
	defer portaudio.Terminate()

	// Step 2: Show default input device
	defaultInput, err := portaudio.DefaultInputDevice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting default input device: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Default input: %s\n", defaultInput.Name)
	fmt.Printf("  Max input channels: %d\n", defaultInput.MaxInputChannels)
	fmt.Printf("  Default sample rate: %.0f Hz\n", defaultInput.DefaultSampleRate)

	// Step 3: List all input devices
	fmt.Println("\n=== Available Input Devices ===")
	devices, err := portaudio.Devices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing devices: %v\n", err)
		os.Exit(1)
	}
	inputCount := 0
	for _, d := range devices {
		if d.MaxInputChannels > 0 {
			inputCount++
			marker := "  "
			if d.Name == defaultInput.Name {
				marker = "* "
			}
			fmt.Printf("  %s%s (max %d ch, %.0f Hz)\n", marker, d.Name, d.MaxInputChannels, d.DefaultSampleRate)
		}
	}
	fmt.Printf("  Total: %d input devices\n", inputCount)

	// Step 4: Record audio
	fmt.Printf("\n=== Recording %d seconds ===\n", duration)
	totalSamples := sampleRate * duration
	buffer := make([]int16, totalSamples)

	// Use a small frame buffer for the callback
	framesPerBuffer := 1024
	frameBuffer := make([]int16, framesPerBuffer)

	stream, err := portaudio.OpenDefaultStream(channels, 0, float64(sampleRate), framesPerBuffer, frameBuffer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening stream: %v\n", err)
		os.Exit(1)
	}
	defer stream.Close()

	if err := stream.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting stream: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("  Recording")
	samplesRead := 0
	startTime := time.Now()

	for samplesRead < totalSamples {
		if err := stream.Read(); err != nil {
			fmt.Fprintf(os.Stderr, "\nError reading from stream: %v\n", err)
			break
		}

		// Copy frame buffer into main buffer
		remaining := totalSamples - samplesRead
		copyLen := len(frameBuffer)
		if copyLen > remaining {
			copyLen = remaining
		}
		copy(buffer[samplesRead:samplesRead+copyLen], frameBuffer[:copyLen])
		samplesRead += copyLen

		// Print progress dots
		elapsed := time.Since(startTime)
		if int(elapsed.Seconds())%1 == 0 && elapsed.Milliseconds()%1000 < 100 {
			fmt.Print(".")
		}
	}

	if err := stream.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "\nError stopping stream: %v\n", err)
	}

	actualDuration := time.Since(startTime)
	fmt.Printf("\n  Captured %d samples in %.1fs\n", samplesRead, actualDuration.Seconds())

	// Step 5: Check audio levels (basic sanity)
	var maxAmp int16
	var sumAbs int64
	for _, s := range buffer[:samplesRead] {
		if s < 0 {
			s = -s
		}
		if s > maxAmp {
			maxAmp = s
		}
		sumAbs += int64(s)
	}
	avgAmp := float64(sumAbs) / float64(samplesRead)
	fmt.Printf("  Peak amplitude: %d (%.1f%%)\n", maxAmp, float64(maxAmp)/32768.0*100)
	fmt.Printf("  Average amplitude: %.0f (%.1f%%)\n", avgAmp, avgAmp/32768.0*100)

	if maxAmp < 100 {
		fmt.Println("  WARNING: Very low audio levels — check microphone permissions")
	}

	// Step 6: Write WAV file
	fmt.Printf("\n=== Writing WAV: %s ===\n", output)
	if err := writeWAV(output, buffer[:samplesRead]); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing WAV: %v\n", err)
		os.Exit(1)
	}

	info, _ := os.Stat(output)
	fmt.Printf("  File size: %d bytes\n", info.Size())
	fmt.Printf("  Duration: %.1f seconds\n", float64(samplesRead)/float64(sampleRate))

	fmt.Println("\nPOC audio recording: SUCCESS")
}

// writeWAV writes 16-bit PCM mono audio data as a WAV file.
func writeWAV(path string, samples []int16) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dataSize := uint32(len(samples) * 2) // 2 bytes per int16
	fileSize := 36 + dataSize

	// RIFF header
	f.Write([]byte("RIFF"))
	binary.Write(f, binary.LittleEndian, fileSize)
	f.Write([]byte("WAVE"))

	// fmt subchunk
	f.Write([]byte("fmt "))
	binary.Write(f, binary.LittleEndian, uint32(16))      // subchunk size
	binary.Write(f, binary.LittleEndian, uint16(1))        // PCM format
	binary.Write(f, binary.LittleEndian, uint16(channels)) // channels
	binary.Write(f, binary.LittleEndian, uint32(sampleRate))
	byteRate := uint32(sampleRate * channels * bitsPerSample / 8)
	binary.Write(f, binary.LittleEndian, byteRate)
	blockAlign := uint16(channels * bitsPerSample / 8)
	binary.Write(f, binary.LittleEndian, blockAlign)
	binary.Write(f, binary.LittleEndian, uint16(bitsPerSample))

	// data subchunk
	f.Write([]byte("data"))
	binary.Write(f, binary.LittleEndian, dataSize)
	binary.Write(f, binary.LittleEndian, samples)

	return nil
}
