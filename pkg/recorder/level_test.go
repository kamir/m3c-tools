package recorder

import (
	"math"
	"testing"
)

func TestCalcRMS_Silence(t *testing.T) {
	samples := make([]int16, 1024)
	rms := CalcRMS(samples)
	if rms != 0 {
		t.Errorf("Expected RMS 0 for silence, got %f", rms)
	}
}

func TestCalcRMS_Empty(t *testing.T) {
	rms := CalcRMS(nil)
	if rms != 0 {
		t.Errorf("Expected RMS 0 for empty slice, got %f", rms)
	}
}

func TestCalcRMS_FullScale(t *testing.T) {
	// All samples at max positive amplitude
	samples := make([]int16, 100)
	for i := range samples {
		samples[i] = 32767
	}
	rms := CalcRMS(samples)
	// Should be very close to 1.0 (32767/32768)
	if rms < 0.99 || rms > 1.0 {
		t.Errorf("Expected RMS ~1.0 for full-scale, got %f", rms)
	}
}

func TestCalcRMS_KnownValue(t *testing.T) {
	// RMS of a constant value k is |k|
	// Samples all at 16384 (half scale) → RMS ≈ 0.5
	samples := make([]int16, 1000)
	for i := range samples {
		samples[i] = 16384
	}
	rms := CalcRMS(samples)
	expected := 16384.0 / 32768.0 // 0.5
	if math.Abs(rms-expected) > 0.001 {
		t.Errorf("Expected RMS %.4f, got %.4f", expected, rms)
	}
}

func TestCalcPeak_Silence(t *testing.T) {
	samples := make([]int16, 100)
	peak := CalcPeak(samples)
	if peak != 0 {
		t.Errorf("Expected peak 0 for silence, got %f", peak)
	}
}

func TestCalcPeak_Positive(t *testing.T) {
	samples := []int16{0, 100, 200, 50}
	peak := CalcPeak(samples)
	expected := 200.0 / 32768.0
	if math.Abs(peak-expected) > 1e-6 {
		t.Errorf("Expected peak %f, got %f", expected, peak)
	}
}

func TestCalcPeak_Negative(t *testing.T) {
	samples := []int16{0, -500, 100, -200}
	peak := CalcPeak(samples)
	expected := 500.0 / 32768.0
	if math.Abs(peak-expected) > 1e-6 {
		t.Errorf("Expected peak %f, got %f", expected, peak)
	}
}

func TestAmplitudeToDb_FullScale(t *testing.T) {
	db := AmplitudeToDb(1.0)
	if math.Abs(db) > 0.001 {
		t.Errorf("Expected 0 dB for amplitude 1.0, got %f", db)
	}
}

func TestAmplitudeToDb_HalfScale(t *testing.T) {
	db := AmplitudeToDb(0.5)
	expected := 20 * math.Log10(0.5) // ≈ -6.02
	if math.Abs(db-expected) > 0.01 {
		t.Errorf("Expected %.2f dB, got %.2f", expected, db)
	}
}

func TestAmplitudeToDb_Silence(t *testing.T) {
	db := AmplitudeToDb(0)
	if db != -96.0 {
		t.Errorf("Expected -96 dB for silence, got %f", db)
	}
}

func TestAmplitudeToDb_Negative(t *testing.T) {
	db := AmplitudeToDb(-1.0)
	if db != -96.0 {
		t.Errorf("Expected -96 dB for negative input, got %f", db)
	}
}

func TestAmplitudeToDb_VeryQuiet(t *testing.T) {
	// Very small amplitude should clamp to -96
	db := AmplitudeToDb(0.00001)
	if db != -96.0 {
		t.Errorf("Expected -96 dB for very quiet signal, got %f", db)
	}
}

func TestComputeLevel_Silence(t *testing.T) {
	frame := make([]int16, 1024)
	level := computeLevel(frame)
	if level.RMS != 0 {
		t.Errorf("Expected RMS 0, got %f", level.RMS)
	}
	if level.Peak != 0 {
		t.Errorf("Expected Peak 0, got %f", level.Peak)
	}
	if level.RMSdB != -96.0 {
		t.Errorf("Expected RMSdB -96, got %f", level.RMSdB)
	}
	if level.Clipped {
		t.Error("Silence should not be clipped")
	}
}

func TestComputeLevel_Clipping(t *testing.T) {
	frame := []int16{0, 100, 32767, -100}
	level := computeLevel(frame)
	if !level.Clipped {
		t.Error("Expected clipping detection for sample at 32767")
	}

	frame2 := []int16{0, 100, -32768, -100}
	level2 := computeLevel(frame2)
	if !level2.Clipped {
		t.Error("Expected clipping detection for sample at -32768")
	}
}

func TestComputeLevel_NoClipping(t *testing.T) {
	frame := []int16{0, 100, 32766, -32767}
	level := computeLevel(frame)
	if level.Clipped {
		t.Error("Should not detect clipping for non-extreme values")
	}
}

func TestComputeLevel_Consistency(t *testing.T) {
	frame := []int16{1000, -2000, 3000, -4000, 5000}
	level := computeLevel(frame)

	// Peak should be >= RMS
	if level.Peak < level.RMS {
		t.Errorf("Peak (%f) should be >= RMS (%f)", level.Peak, level.RMS)
	}

	// PeakdB should be >= RMSdB (less negative = louder)
	if level.PeakdB < level.RMSdB {
		t.Errorf("PeakdB (%f) should be >= RMSdB (%f)", level.PeakdB, level.RMSdB)
	}

	// Values should be in valid range
	if level.RMS < 0 || level.RMS > 1 {
		t.Errorf("RMS %f out of range [0, 1]", level.RMS)
	}
	if level.Peak < 0 || level.Peak > 1 {
		t.Errorf("Peak %f out of range [0, 1]", level.Peak)
	}
}

func TestAudioLevel_FieldsDocumented(t *testing.T) {
	// Verify the struct has all expected fields by constructing one
	level := AudioLevel{
		RMS:     0.5,
		Peak:    0.8,
		RMSdB:   -6.0,
		PeakdB:  -1.9,
		Clipped: false,
	}
	if level.RMS != 0.5 {
		t.Error("RMS field not set correctly")
	}
}
