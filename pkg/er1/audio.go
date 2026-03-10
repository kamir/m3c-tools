package er1

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SilentWAV creates a WAV file with silence (16kHz, 16-bit, mono).
func SilentWAV(seconds int) []byte {
	samples := 16000 * seconds
	dataSize := samples * 2

	var buf bytes.Buffer
	buf.WriteString("RIFF")
	writeLE32(&buf, uint32(36+dataSize))
	buf.WriteString("WAVE")
	buf.WriteString("fmt ")
	writeLE32(&buf, 16)
	writeLE16(&buf, 1)     // PCM
	writeLE16(&buf, 1)     // mono
	writeLE32(&buf, 16000) // sample rate
	writeLE32(&buf, 32000) // byte rate
	writeLE16(&buf, 2)     // block align
	writeLE16(&buf, 16)    // bits per sample
	buf.WriteString("data")
	writeLE32(&buf, uint32(dataSize))
	buf.Write(make([]byte, dataSize))
	return buf.Bytes()
}

// PlaceholderPNG returns a minimal 1x1 red PNG image.
func PlaceholderPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41,
		0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
		0x00, 0x00, 0x03, 0x00, 0x01, 0x36, 0x28, 0x19,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
		0x44, 0xae, 0x42, 0x60, 0x82,
	}
}

var (
	logoOnce sync.Once
	logoData []byte
)

// PlaceholderLogoPNG returns the app logo image bytes when available.
// It falls back to nil if no suitable logo file is found.
func PlaceholderLogoPNG() []byte {
	logoOnce.Do(func() {
		candidates := make([]string, 0, 6)
		if p := strings.TrimSpace(os.Getenv("M3C_APP_LOGO_PATH")); p != "" {
			candidates = append(candidates, p)
		}
		candidates = append(candidates, "maindset_icon.png")

		if exe, err := os.Executable(); err == nil && exe != "" {
			exeDir := filepath.Dir(exe)
			candidates = append(candidates,
				filepath.Join(exeDir, "maindset_icon.png"),
				filepath.Join(exeDir, "..", "Resources", "icon.png"),
			)
		}

		for _, p := range candidates {
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil || len(data) == 0 {
				continue
			}
			logoData = data
			return
		}
	})
	return logoData
}

func writeLE16(buf *bytes.Buffer, v uint16) {
	buf.WriteByte(byte(v))
	buf.WriteByte(byte(v >> 8))
}

func writeLE32(buf *bytes.Buffer, v uint32) {
	buf.WriteByte(byte(v))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 24))
}
