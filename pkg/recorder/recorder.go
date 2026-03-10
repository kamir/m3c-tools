// Package recorder handles microphone audio capture via PortAudio
// and WAV file output in whisper-compatible format (16kHz, 16-bit, mono).
package recorder

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/gordonklaus/portaudio"
)

const (
	SampleRate    = 16000 // 16kHz — whisper's native sample rate
	Channels      = 1     // mono
	BitsPerSample = 16
)

// DeviceInfo holds information about an audio input device.
type DeviceInfo struct {
	Name            string
	MaxInputChannels int
	DefaultSampleRate float64
	IsDefault       bool
}

// ListInputDevices returns all available audio input devices.
func ListInputDevices() ([]DeviceInfo, error) {
	if err := portaudio.Initialize(); err != nil {
		return nil, fmt.Errorf("portaudio init: %w", err)
	}
	defer func() { _ = portaudio.Terminate() }()

	defaultDev, _ := portaudio.DefaultInputDevice()
	defaultName := ""
	if defaultDev != nil {
		defaultName = defaultDev.Name
	}

	devices, err := portaudio.Devices()
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}

	var result []DeviceInfo
	for _, d := range devices {
		if d.MaxInputChannels > 0 {
			result = append(result, DeviceInfo{
				Name:            d.Name,
				MaxInputChannels: d.MaxInputChannels,
				DefaultSampleRate: d.DefaultSampleRate,
				IsDefault:       d.Name == defaultName,
			})
		}
	}
	return result, nil
}

// Record captures audio from the default microphone for the given duration.
func Record(seconds int) ([]int16, error) {
	if err := portaudio.Initialize(); err != nil {
		return nil, fmt.Errorf("portaudio init: %w", err)
	}
	defer func() { _ = portaudio.Terminate() }()

	totalSamples := SampleRate * seconds
	buffer := make([]int16, totalSamples)
	framesPerBuffer := 1024
	frameBuffer := make([]int16, framesPerBuffer)

	stream, err := portaudio.OpenDefaultStream(Channels, 0, float64(SampleRate), framesPerBuffer, frameBuffer)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if err := stream.Start(); err != nil {
		return nil, fmt.Errorf("start stream: %w", err)
	}

	samplesRead := 0
	for samplesRead < totalSamples {
		if err := stream.Read(); err != nil {
			break
		}
		remaining := totalSamples - samplesRead
		copyLen := len(frameBuffer)
		if copyLen > remaining {
			copyLen = remaining
		}
		copy(buffer[samplesRead:samplesRead+copyLen], frameBuffer[:copyLen])
		samplesRead += copyLen
	}

	_ = stream.Stop()
	return buffer[:samplesRead], nil
}

// RecordTimed records for the specified duration and returns the WAV data.
func RecordTimed(duration time.Duration) ([]byte, error) {
	samples, err := Record(int(duration.Seconds()))
	if err != nil {
		return nil, err
	}
	return EncodeWAV(samples), nil
}

// RecordUntilStop captures audio until the stop channel is closed or
// maxSeconds is reached (whichever comes first). This allows the caller
// to let the user control when recording ends.
func RecordUntilStop(stop <-chan struct{}, maxSeconds int) ([]int16, error) {
	if err := portaudio.Initialize(); err != nil {
		return nil, fmt.Errorf("portaudio init: %w", err)
	}
	defer func() { _ = portaudio.Terminate() }()

	maxSamples := SampleRate * maxSeconds
	buffer := make([]int16, 0, SampleRate*10) // pre-alloc ~10s
	framesPerBuffer := 1024
	frameBuffer := make([]int16, framesPerBuffer)

	stream, err := portaudio.OpenDefaultStream(Channels, 0, float64(SampleRate), framesPerBuffer, frameBuffer)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if err := stream.Start(); err != nil {
		return nil, fmt.Errorf("start stream: %w", err)
	}

	for len(buffer) < maxSamples {
		// Check if stop was signaled
		select {
		case <-stop:
			_ = stream.Stop()
			return buffer, nil
		default:
		}

		if err := stream.Read(); err != nil {
			break
		}
		remaining := maxSamples - len(buffer)
		copyLen := len(frameBuffer)
		if copyLen > remaining {
			copyLen = remaining
		}
		buffer = append(buffer, frameBuffer[:copyLen]...)
	}

	_ = stream.Stop()
	return buffer, nil
}

// RecordTimedWithStop records until the stop channel is closed or maxSeconds
// is reached. Returns WAV-encoded data.
func RecordTimedWithStop(stop <-chan struct{}, maxSeconds int) ([]byte, error) {
	samples, err := RecordUntilStop(stop, maxSeconds)
	if err != nil {
		return nil, err
	}
	return EncodeWAV(samples), nil
}

// WriteWAV writes 16-bit PCM mono audio data as a WAV file.
func WriteWAV(path string, samples []int16) error {
	return os.WriteFile(path, EncodeWAV(samples), 0644)
}

// EncodeWAV encodes samples to WAV format bytes.
func EncodeWAV(samples []int16) []byte {
	dataSize := uint32(len(samples) * 2)
	fileSize := 36 + dataSize

	buf := make([]byte, 0, int(fileSize)+8)

	// RIFF header
	buf = append(buf, []byte("RIFF")...)
	buf = appendLE32(buf, fileSize)
	buf = append(buf, []byte("WAVE")...)

	// fmt subchunk
	buf = append(buf, []byte("fmt ")...)
	buf = appendLE32(buf, 16)
	buf = appendLE16(buf, 1)            // PCM
	buf = appendLE16(buf, Channels)
	buf = appendLE32(buf, SampleRate)
	buf = appendLE32(buf, SampleRate*Channels*BitsPerSample/8)
	buf = appendLE16(buf, Channels*BitsPerSample/8)
	buf = appendLE16(buf, BitsPerSample)

	// data subchunk
	buf = append(buf, []byte("data")...)
	buf = appendLE32(buf, dataSize)
	for _, s := range samples {
		buf = appendLE16(buf, uint16(s))
	}

	return buf
}

// AudioLevel represents real-time audio input levels for a single frame.
type AudioLevel struct {
	RMS     float64 // Root mean square amplitude (0.0–1.0 normalized)
	Peak    float64 // Peak amplitude in the frame (0.0–1.0 normalized)
	RMSdB   float64 // RMS level in decibels (−∞ to 0)
	PeakdB  float64 // Peak level in decibels (−∞ to 0)
	Clipped bool    // True if any sample hit ±32767
}

// LevelCallback is invoked with real-time audio levels during recording.
// It is called approximately SampleRate/framesPerBuffer times per second
// (e.g., ~15 Hz with 1024-sample frames at 16 kHz).
type LevelCallback func(level AudioLevel)

// CalcRMS computes the root-mean-square of int16 samples, normalized to 0.0–1.0.
func CalcRMS(samples []int16) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sumSq float64
	for _, s := range samples {
		v := float64(s) / 32768.0
		sumSq += v * v
	}
	return math.Sqrt(sumSq / float64(len(samples)))
}

// CalcPeak returns the peak absolute amplitude of int16 samples, normalized to 0.0–1.0.
func CalcPeak(samples []int16) float64 {
	var maxAbs int16
	for _, s := range samples {
		if s < 0 {
			s = -s
		}
		if s > maxAbs {
			maxAbs = s
		}
	}
	return float64(maxAbs) / 32768.0
}

// AmplitudeToDb converts a linear amplitude (0.0–1.0) to decibels.
// Returns -96 for zero or negative input (silence floor).
func AmplitudeToDb(amplitude float64) float64 {
	if amplitude <= 0 {
		return -96.0
	}
	db := 20 * math.Log10(amplitude)
	if db < -96.0 {
		return -96.0
	}
	return db
}

// computeLevel calculates an AudioLevel from a frame of samples.
func computeLevel(frame []int16) AudioLevel {
	rms := CalcRMS(frame)
	peak := CalcPeak(frame)
	clipped := false
	for _, s := range frame {
		if s == 32767 || s == -32768 {
			clipped = true
			break
		}
	}
	return AudioLevel{
		RMS:     rms,
		Peak:    peak,
		RMSdB:   AmplitudeToDb(rms),
		PeakdB:  AmplitudeToDb(peak),
		Clipped: clipped,
	}
}

// RecordWithLevels captures audio until the stop channel is closed or
// maxSeconds is reached, calling onLevel after each frame with real-time
// RMS and peak levels. The callback is invoked from the recording goroutine.
func RecordWithLevels(stop <-chan struct{}, maxSeconds int, onLevel LevelCallback) ([]int16, error) {
	if err := portaudio.Initialize(); err != nil {
		return nil, fmt.Errorf("portaudio init: %w", err)
	}
	defer func() { _ = portaudio.Terminate() }()

	maxSamples := SampleRate * maxSeconds
	buffer := make([]int16, 0, SampleRate*10)
	framesPerBuffer := 1024
	frameBuffer := make([]int16, framesPerBuffer)

	stream, err := portaudio.OpenDefaultStream(Channels, 0, float64(SampleRate), framesPerBuffer, frameBuffer)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	if err := stream.Start(); err != nil {
		return nil, fmt.Errorf("start stream: %w", err)
	}

	for len(buffer) < maxSamples {
		select {
		case <-stop:
			_ = stream.Stop()
			return buffer, nil
		default:
		}

		if err := stream.Read(); err != nil {
			break
		}

		remaining := maxSamples - len(buffer)
		copyLen := len(frameBuffer)
		if copyLen > remaining {
			copyLen = remaining
		}
		buffer = append(buffer, frameBuffer[:copyLen]...)

		if onLevel != nil {
			onLevel(computeLevel(frameBuffer[:copyLen]))
		}
	}

	_ = stream.Stop()
	return buffer, nil
}

// AudioStats returns basic statistics about audio samples.
type AudioStats struct {
	PeakAmplitude    int16
	AverageAmplitude float64
	Samples          int
	Duration         float64 // seconds
}

// Stats calculates basic audio statistics from samples.
func Stats(samples []int16) AudioStats {
	var maxAmp int16
	var sumAbs int64
	for _, s := range samples {
		if s < 0 {
			s = -s
		}
		if s > maxAmp {
			maxAmp = s
		}
		sumAbs += int64(s)
	}
	return AudioStats{
		PeakAmplitude:    maxAmp,
		AverageAmplitude: float64(sumAbs) / float64(len(samples)),
		Samples:          len(samples),
		Duration:         float64(len(samples)) / float64(SampleRate),
	}
}

// DecodePCM16 converts raw little-endian 16-bit PCM bytes to int16 samples.
func DecodePCM16(data []byte) []int16 {
	n := len(data) / 2
	samples := make([]int16, n)
	for i := 0; i < n; i++ {
		samples[i] = int16(binary.LittleEndian.Uint16(data[i*2 : i*2+2]))
	}
	return samples
}

func appendLE16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return append(buf, b...)
}

func appendLE32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}
