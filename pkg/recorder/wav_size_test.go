package recorder

import (
	"math"
	"testing"
)

func TestWAVSizesRejectOverflowWithoutAllocatingAudio(t *testing.T) {
	maxSamples := uint64((math.MaxUint32 - 36) / 2)
	if nativeMax := (uint64(^uint(0)>>1) - 44) / 2; nativeMax < maxSamples {
		maxSamples = nativeMax
	}
	data, size, err := wavSizes(int(maxSamples))
	if err != nil || uint64(data) != maxSamples*2 || uint64(size) != 36+maxSamples*2 {
		t.Fatalf("maximum valid size: data=%d size=%d err=%v", data, size, err)
	}
	for _, n := range []int{-1, int(maxSamples) + 1, int(^uint(0) >> 1)} {
		if _, _, err := wavSizes(n); err == nil {
			t.Fatalf("accepted invalid sample count %d", n)
		}
	}
}

func TestWAVSignedPCMBitPatternsRoundTrip(t *testing.T) {
	samples := []int16{math.MinInt16, -1, 0, 1, math.MaxInt16}
	wav := EncodeWAV(samples)
	decoded := DecodePCM16(wav[44:])
	for i := range samples {
		if decoded[i] != samples[i] {
			t.Fatalf("sample %d: got %d want %d", i, decoded[i], samples[i])
		}
	}
}
