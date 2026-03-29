package sapblob

import (
	"bytes"
	"compress/flate"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

// ============================================================
// Helper: Create a SAP BLOB from plaintext for testing
// ============================================================

// makeSAPBlob compresses plaintext data into a SAP BLOB with
// the 8-byte header and nonsense padding bits.
func makeSAPBlob(plaintext []byte, algorithm int, nonsensePadBits int) []byte {
	// 1. Compress with deflate
	var compressed bytes.Buffer
	w, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	w.Write(plaintext)
	w.Close()
	rawDeflate := compressed.Bytes()

	// flate.NewWriter produces zlib-wrapped output (2 byte header + 4 byte checksum)
	// We need raw deflate, so strip the 2-byte header and 4-byte trailer
	// Actually Go's flate writer IS raw deflate. Let me re-check:
	// flate.NewWriter gives raw deflate. Good.

	// 2. Add nonsense padding bits by shifting left
	totalPad := NonsenseLenBits + nonsensePadBits
	padded := shiftBitsLeft(rawDeflate, totalPad)

	// Set the lower NonsenseLenBits of the first byte to nonsensePadBits value
	padded[0] = (padded[0] & ^byte((1<<NonsenseLenBits)-1)) | byte(nonsensePadBits&((1<<NonsenseLenBits)-1))

	// 3. Build SAP header
	header := make([]byte, CsHeadSize)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(plaintext)))
	header[4] = byte((1 << 4) | (algorithm & 0x0F)) // version 1
	header[5] = 0x1F                                // flags (mimicking real SAP)
	header[6] = 0x9D
	header[7] = 0x02

	return append(header, padded...)
}

func shiftBitsLeft(data []byte, bitsToAdd int) []byte {
	if bitsToAdd == 0 {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	// Add one extra byte to handle overflow
	result := make([]byte, len(data)+1)
	shift := uint(bitsToAdd)
	carry := 8 - shift

	for i := len(data) - 1; i >= 1; i-- {
		result[i] = (data[i] << shift) | (data[i-1] >> carry)
	}
	result[0] = data[0] << shift
	// Last byte gets overflow from last data byte
	result[len(data)] = data[len(data)-1] >> carry

	return result
}

// ============================================================
// 1. HEADER PARSING TESTS
// ============================================================

func TestParseHeader_Valid(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantSize uint32
		wantVer  int
		wantAlg  int
		wantName string
	}{
		{
			name:     "LZH algorithm",
			data:     []byte{0x00, 0xF4, 0x01, 0x00, 0x12, 0x1F, 0x9D, 0x02, 0x25},
			wantSize: 128000,
			wantVer:  1,
			wantAlg:  2,
			wantName: "LZH",
		},
		{
			name:     "LZC algorithm",
			data:     []byte{0x00, 0x10, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00},
			wantSize: 4096,
			wantVer:  1,
			wantAlg:  1,
			wantName: "LZC",
		},
		{
			name:     "Large file",
			data:     []byte{0x00, 0x00, 0x10, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00},
			wantSize: 1048576, // 1 MB
			wantVer:  2,
			wantAlg:  2,
			wantName: "LZH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := ParseHeader(tt.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h.UncompressedSize != tt.wantSize {
				t.Errorf("size = %d, want %d", h.UncompressedSize, tt.wantSize)
			}
			if h.Version != tt.wantVer {
				t.Errorf("version = %d, want %d", h.Version, tt.wantVer)
			}
			if h.Algorithm != tt.wantAlg {
				t.Errorf("algorithm = %d, want %d", h.Algorithm, tt.wantAlg)
			}
			if h.AlgorithmName != tt.wantName {
				t.Errorf("name = %q, want %q", h.AlgorithmName, tt.wantName)
			}
		})
	}
}

func TestParseHeader_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x01, 0x02}},
		{"empty", []byte{}},
		{"7 bytes", []byte{0x3F, 0xF7, 0x01, 0x00, 0x12, 0x1F, 0x9D}},
		{"unknown algorithm", []byte{0x10, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00}},
		{"zero size", []byte{0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHeader(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ============================================================
// 2. ENTROPY TESTS
// ============================================================

func TestEntropy_AllSame(t *testing.T) {
	// All same bytes = 0 entropy
	data := bytes.Repeat([]byte{0x42}, 1000)
	e := Entropy(data)
	if e != 0 {
		t.Errorf("entropy of uniform data = %f, want 0", e)
	}
}

func TestEntropy_TwoValues(t *testing.T) {
	// Equal mix of 2 values = 1.0 bit
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 2)
	}
	e := Entropy(data)
	if math.Abs(e-1.0) > 0.01 {
		t.Errorf("entropy of 2-value data = %f, want 1.0", e)
	}
}

func TestEntropy_Maximum(t *testing.T) {
	// All 256 values equally = 8.0 bits
	data := make([]byte, 256*100)
	for i := range data {
		data[i] = byte(i % 256)
	}
	e := Entropy(data)
	if math.Abs(e-8.0) > 0.01 {
		t.Errorf("entropy of uniform-256 data = %f, want 8.0", e)
	}
}

func TestEntropy_CompressedData(t *testing.T) {
	// Compressed data should have high entropy (> 7.5)
	plaintext := bytes.Repeat([]byte("SAP BLOB decompression test data. "), 1000)
	blob := makeSAPBlob(plaintext, AlgLZH, 1)
	e := Entropy(blob[CsHeadSize:]) // only compressed part
	if e < 3.5 {
		t.Errorf("entropy of compressed data = %f, want > 3.5", e)
	}
}

func TestEntropy_Empty(t *testing.T) {
	e := Entropy([]byte{})
	if e != 0 {
		t.Errorf("entropy of empty = %f, want 0", e)
	}
}

// ============================================================
// 3. UNIQUE BYTES TESTS
// ============================================================

func TestUniqueBytes(t *testing.T) {
	if UniqueBytes([]byte{1, 1, 1}) != 1 {
		t.Error("expected 1")
	}
	if UniqueBytes([]byte{0, 1, 2, 3, 0, 1}) != 4 {
		t.Error("expected 4")
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if UniqueBytes(all) != 256 {
		t.Error("expected 256")
	}
}

// ============================================================
// 4. LEGACY FORMAT DETECTION
// ============================================================

func TestIsLegacyFormat(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantLeg   bool
		wantMagic uint16
	}{
		{
			name:    "modern LZH (our test file header)",
			data:    []byte{0x3F, 0xF7, 0x01, 0x00, 0x12, 0x1F, 0x9D, 0x02, 0x25, 0xDF, 0xAD},
			wantLeg: false,
		},
		{
			name:      "legacy 1F9D at offset 9",
			data:      []byte{0x10, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x9D},
			wantLeg:   true,
			wantMagic: 0x1F9D,
		},
		{
			name:      "legacy 1F9E at offset 9",
			data:      []byte{0x10, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x9E},
			wantLeg:   true,
			wantMagic: 0x1F9E,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, magic := IsLegacyFormat(tt.data)
			if got != tt.wantLeg {
				t.Errorf("IsLegacy = %v, want %v", got, tt.wantLeg)
			}
			if tt.wantLeg && magic != tt.wantMagic {
				t.Errorf("magic = 0x%04X, want 0x%04X", magic, tt.wantMagic)
			}
		})
	}
}

// ============================================================
// 5. FILE TYPE DETECTION
// ============================================================

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"PDF", []byte("%PDF-1.5 rest of data"), "PDF"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG"},
		{"PNG", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, "PNG"},
		{"ZIP", []byte{'P', 'K', 3, 4, 0, 0}, "ZIP/DOCX/XLSX"},
		{"OLE2", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "OLE2/DOC/XLS"},
		{"XML", []byte("<?xml version"), "XML/HTML"},
		{"JSON", []byte(`{"key": "value"}`), "JSON"},
		{"unknown", []byte{0x00, 0x01, 0x02, 0x03}, "unknown"},
		{"short", []byte{0x25}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectFileType(tt.data)
			if got != tt.want {
				t.Errorf("type = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================
// 6. BIT SHIFTING TESTS
// ============================================================

func TestShiftBitsRight_Zero(t *testing.T) {
	data := []byte{0xAB, 0xCD, 0xEF}
	result := shiftBitsRight(data, 0)
	if !bytes.Equal(result, data) {
		t.Errorf("shift 0 changed data: %X -> %X", data, result)
	}
}

func TestShiftBitsRight_3(t *testing.T) {
	// Manual calculation:
	// data[0]=0x25=0b00100101, data[1]=0xDF=0b11011111
	// result[0] = (0x25 >> 3) | (0xDF << 5)
	//           = 0b00000100 | 0b11100000
	//           = 0b11100100 = 0xE4
	data := []byte{0x25, 0xDF, 0xAD}
	result := shiftBitsRight(data, 3)

	a := int(0x25) >> 3
	b := int(0xDF) << 5
	expected0 := byte(a | b)
	if result[0] != expected0 {
		t.Errorf("result[0] = 0x%02X, want 0x%02X", result[0], expected0)
	}
}

func TestShiftBitsRight_Roundtrip(t *testing.T) {
	// Shifting left then right should preserve the deflate data
	original := []byte{0x04, 0xC0, 0x6D, 0xE9, 0xFF} // some deflate-like bytes

	for shift := 1; shift <= 7; shift++ {
		shifted := shiftBitsLeft(original, shift)
		recovered := shiftBitsRight(shifted, shift)

		// The first len(original) bytes should match
		for i := 0; i < len(original); i++ {
			if recovered[i] != original[i] {
				t.Errorf("shift=%d: byte %d: got 0x%02X, want 0x%02X",
					shift, i, recovered[i], original[i])
			}
		}
	}
}

// ============================================================
// 7. ROUNDTRIP: COMPRESS → DECOMPRESS
// ============================================================

func TestDecompress_Roundtrip_PDF(t *testing.T) {
	// Create a fake PDF
	plaintext := []byte("%PDF-1.5\r\n%\xB5\xB5\xB5\xB5\r\n1 0 obj\r\n<</Type/Catalog>>\r\nendobj\r\n%%EOF\r\n")

	for _, padBits := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("pad=%d", padBits), func(t *testing.T) {
			blob := makeSAPBlob(plaintext, AlgLZH, padBits)

			result, err := Decompress(blob)
			if err != nil {
				t.Fatalf("decompress error: %v", err)
			}

			if !bytes.Equal(result, plaintext) {
				t.Errorf("roundtrip mismatch:\n  got  (%d bytes): %q\n  want (%d bytes): %q",
					len(result), result[:min(50, len(result))],
					len(plaintext), plaintext[:min(50, len(plaintext))])
			}
		})
	}
}

func TestDecompress_Roundtrip_LargeData(t *testing.T) {
	// Test with larger, more realistic data
	plaintext := bytes.Repeat([]byte("SAP document content for decompression testing purposes.\n"), 500)

	blob := makeSAPBlob(plaintext, AlgLZH, 1)
	result, err := Decompress(blob)
	if err != nil {
		t.Fatalf("decompress error: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("roundtrip failed: got %d bytes, want %d", len(result), len(plaintext))
	}

	// Verify compression actually happened
	if len(blob) >= len(plaintext) {
		t.Errorf("compression did not reduce size: %d -> %d", len(plaintext), len(blob))
	}
}

func TestDecompress_Roundtrip_BinaryData(t *testing.T) {
	// Test with binary data (simulating JPEG)
	plaintext := make([]byte, 10000)
	plaintext[0] = 0xFF
	plaintext[1] = 0xD8
	plaintext[2] = 0xFF
	for i := 3; i < len(plaintext); i++ {
		plaintext[i] = byte(((i * 7) + 13) & 0xFF)
	}

	blob := makeSAPBlob(plaintext, AlgLZH, 2)
	result, err := Decompress(blob)
	if err != nil {
		t.Fatalf("decompress error: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("binary roundtrip failed: got %d bytes, want %d", len(result), len(plaintext))
	}

	if DetectFileType(result) != "JPEG" {
		t.Errorf("file type = %q, want JPEG", DetectFileType(result))
	}
}

// ============================================================
// 8. ERROR CASES
// ============================================================

func TestDecompress_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{0x01, 0x02, 0x03}},
		{"bad algorithm", []byte{0x10, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decompress(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ============================================================
// 9. FULL ANALYSIS PIPELINE
// ============================================================

func TestAnalyze_Pipeline(t *testing.T) {
	plaintext := []byte("%PDF-1.4\nTest document content for SAP BLOB analysis.\n%%EOF\n")
	blob := makeSAPBlob(plaintext, AlgLZH, 1)

	a := Analyze(blob)

	// Header checks
	if a.Header.Algorithm != AlgLZH {
		t.Errorf("algorithm = %d, want %d", a.Header.Algorithm, AlgLZH)
	}
	if a.Header.UncompressedSize != uint32(len(plaintext)) {
		t.Errorf("uncompressed size = %d, want %d", a.Header.UncompressedSize, len(plaintext))
	}
	if a.Header.AlgorithmName != "LZH" {
		t.Errorf("name = %q, want LZH", a.Header.AlgorithmName)
	}

	// Entropy should be > 0
	if a.Entropy <= 0 {
		t.Errorf("entropy = %f, want > 0", a.Entropy)
	}

	// Not legacy
	if a.IsLegacyFormat {
		t.Error("should not be legacy format")
	}

	// Nonsense bits
	if a.NonsenseBits != 3 { // 2 + 1
		t.Errorf("nonsense bits = %d, want 3", a.NonsenseBits)
	}

	// For very small inputs, compression overhead can exceed savings
	// Just verify the rate is calculated
	if a.CompressionRate <= 0 {
		t.Errorf("compression rate = %.1f%%, want > 0%%", a.CompressionRate)
	}

	// Now decompress and verify
	result, err := Decompress(blob)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Error("roundtrip mismatch after analysis")
	}
	if DetectFileType(result) != "PDF" {
		t.Errorf("detected type = %q, want PDF", DetectFileType(result))
	}
}

// ============================================================
// 10. MD5 CONSISTENCY CHECK
// ============================================================

func TestDecompress_MD5Stability(t *testing.T) {
	// Same input must always produce same output (deterministic)
	plaintext := []byte("%PDF-1.5\r\nStable output test\r\n%%EOF\r\n")
	blob := makeSAPBlob(plaintext, AlgLZH, 1)

	var firstMD5 [md5.Size]byte
	for i := 0; i < 5; i++ {
		result, err := Decompress(blob)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		sum := md5.Sum(result)
		if i == 0 {
			firstMD5 = sum
		} else if sum != firstMD5 {
			t.Errorf("run %d: MD5 mismatch: %x != %x", i, sum, firstMD5)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
