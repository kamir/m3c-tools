package plaud

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestCDPFrameLengthBoundaries(t *testing.T) {
	for _, size := range []int{0, 125, 126, 65535, 65536} {
		payload := strings.Repeat("x", size)
		frame := cdpFrame(payload)
		length, offset := uint64(frame[1]&127), 2
		switch length {
		case 126:
			length, offset = uint64(binary.BigEndian.Uint16(frame[2:4])), 4
		case 127:
			length, offset = binary.BigEndian.Uint64(frame[2:10]), 10
		}
		if frame[1]&128 == 0 || length != uint64(size) || len(frame) != offset+4+size {
			t.Fatalf("size=%d: encoded=%d frame bytes=%d", size, length, len(frame))
		}
		for i := 0; i < size; i++ {
			if frame[offset+4+i]^frame[offset+i%4] != payload[i] {
				t.Fatalf("size=%d: incorrect masked byte %d", size, i)
			}
		}
	}
}
