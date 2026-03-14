// wav.go — Pure Go WAV encoding and audio utilities.
// No cgo, no platform dependencies. Used by all platforms.
package recorder

import (
	"encoding/binary"
	"math"
	"os"
)

const (
	SampleRate    = 16000 // 16kHz — whisper's native sample rate
	Channels      = 1     // mono
	BitsPerSample = 16
)

// DeviceInfo holds information about an audio input device.
type DeviceInfo struct {
	Name             string
	MaxInputChannels int
	DefaultSampleRate float64
	IsDefault        bool
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
type LevelCallback func(level AudioLevel)

// AudioStats returns basic statistics about audio samples.
type AudioStats struct {
	PeakAmplitude    int16
	AverageAmplitude float64
	Samples          int
	Duration         float64 // seconds
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
	buf = appendLE16(buf, 1) // PCM
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

// WriteWAV writes 16-bit PCM mono audio data as a WAV file.
func WriteWAV(path string, samples []int16) error {
	return writeFile(path, EncodeWAV(samples))
}

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

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
