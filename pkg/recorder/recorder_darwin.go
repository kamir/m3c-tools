// recorder_darwin.go — PortAudio-based audio recording (macOS only, requires cgo).
//
//go:build darwin

package recorder

import (
	"fmt"
	"time"

	"github.com/gordonklaus/portaudio"
)

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
				Name:              d.Name,
				MaxInputChannels:  d.MaxInputChannels,
				DefaultSampleRate: d.DefaultSampleRate,
				IsDefault:         d.Name == defaultName,
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
// maxSeconds is reached (whichever comes first).
func RecordUntilStop(stop <-chan struct{}, maxSeconds int) ([]int16, error) {
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

// RecordWithLevels captures audio until the stop channel is closed or
// maxSeconds is reached, calling onLevel after each frame with real-time levels.
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
