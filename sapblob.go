// Package sapblob decompresses SAP database BLOBs that use SAP's
// proprietary LZC/LZH compression format.
//
// # Background
//
// SAP systems store documents (PDFs, images, office files) in database
// tables like SOFFCONT1, REPOSRC, and STXL using a proprietary compression
// format. When these BLOBs are extracted directly from the database (e.g.
// via SQL dump, RFC export, or pg_dump), they cannot be opened because
// they're wrapped in SAP's custom compression envelope.
//
// # The Key Discovery
//
// Through reverse-engineering the open-source MaxDB decompression code
// (vpa108csulzh.cpp), we discovered that SAP's "proprietary" LZH algorithm
// is actually standard RFC 1951 DEFLATE with two minor additions:
//
//  1. An 8-byte header containing the uncompressed size and algorithm ID
//  2. A few "nonsense" padding bits before the DEFLATE stream
//
// This means decompression can be done with any language's built-in
// DEFLATE/Inflate implementation — no proprietary C++ code needed.
//
// # SAP BLOB Format
//
//	Offset  Size  Field
//	------  ----  ----------------------------------------
//	0       4     Uncompressed size (uint32 little-endian)
//	4       1     (version << 4) | algorithm
//	              algorithm 1 = LZC (Lempel-Ziv-Thomas)
//	              algorithm 2 = LZH (Lempel-Ziv-Huffman)
//	5       3     Algorithm-specific flags
//	8       ...   Compressed data (DEFLATE with bit padding)
//
// # Credits
//
// This work builds on research by:
//   - Martin Gallo (pysap / SecureAuth) — CVE-2015-2282, CVE-2015-2278
//   - Daniel Berlin — SAP REPOSRC decompressor
//   - Hans-Christian Esperer — hascar (Haskell reimplementation)
//   - SAP AG — MaxDB 7.5/7.6 open-source release (GPL v2)
package sapblob

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// =========================================================================
// Constants
// =========================================================================

const (
	// CsHeadSize is the size of the SAP compression header in bytes.
	// This header precedes the compressed data in every SAP BLOB.
	//
	// Layout:
	//   [0:4] uint32 LE — uncompressed size
	//   [4]   byte      — (version << 4) | algorithm
	//   [5:8] bytes     — algorithm-specific flags
	CsHeadSize = 8

	// AlgLZC identifies the LZC (Lempel-Ziv-Thomas) algorithm.
	// This is algorithm ID 1 in the SAP header byte.
	AlgLZC = 1

	// AlgLZH identifies the LZH (Lempel-Ziv-Huffman) algorithm.
	// This is algorithm ID 2 in the SAP header byte.
	// Despite the name, SAP LZH is actually standard DEFLATE (RFC 1951).
	AlgLZH = 2

	// NonsenseLenBits is the number of bits used to encode the length
	// of the "nonsense" padding. SAP writes this many bits at the start
	// of the compressed stream, containing a value N. Then N additional
	// random bits follow. The total padding is (NonsenseLenBits + N).
	//
	// This padding was likely added to prevent standard tools from
	// accidentally recognizing the DEFLATE stream. The SAP source code
	// literally calls this "NONSENSE" — see vpa107cslzh.cpp line 1289:
	//
	//   x = rand () & ((1 << NONSENSE_LENBITS) - 1);
	//   SendBits (x, NONSENSE_LENBITS);
	//
	// In practice, N ranges from 0 to 3, so total padding is 2–5 bits.
	NonsenseLenBits = 2

	// maxUncompressedSize is a safety limit to prevent allocating
	// absurd amounts of memory from a corrupted header.
	maxUncompressedSize = 500 * 1024 * 1024 // 500 MB
)

// =========================================================================
// Types
// =========================================================================

// Header represents the parsed 8-byte SAP compression header.
type Header struct {
	UncompressedSize uint32  // Original file size in bytes
	Version          int     // Compression version (usually 1)
	Algorithm        int     // 1 = LZC, 2 = LZH
	AlgorithmName    string  // Human-readable: "LZC", "LZH", or "unknown"
	Flags            [3]byte // Algorithm-specific flags (bytes 5-7)
}

// Analysis holds diagnostic information about a BLOB.
// Use [Analyze] to populate this struct.
type Analysis struct {
	Header          Header
	FileSize        int     // Total BLOB size in bytes
	Entropy         float64 // Shannon entropy (0.0–8.0 bits/byte)
	IsLegacyFormat  bool    // True if legacy SAP magic detected
	LegacyMagic     uint16  // The legacy magic value, if detected
	NonsenseBits    int     // Total nonsense padding bits (2 + N)
	DetectedType    string  // File type of decompressed content
	CompressionRate float64 // Compressed/uncompressed ratio in percent
}

// =========================================================================
// Header Parsing
// =========================================================================

// ParseHeader reads and validates the 8-byte SAP compression header.
//
// The header format was documented by studying SAP's CsSetHead function
// in vpa105CsObjInt.cpp (MaxDB open-source release):
//
//	outbuf[0] = (SAP_BYTE) (l & 0xff);          // size byte 0 (LSB)
//	outbuf[1] = (SAP_BYTE) ((l & 0xff00) >> 8); // size byte 1
//	outbuf[2] = (SAP_BYTE) ((l & 0xff0000L) >> 16);   // size byte 2
//	outbuf[3] = (SAP_BYTE) ((l & 0xff000000L) >> 24);  // size byte 3 (MSB)
//
// Byte 4 encodes both version and algorithm:
//
//	CsSetHead(outbuf, sumlen,
//	    (BYTE_TYP) ((CS_VERSION << 4) | CS_ALGORITHM),  // byte 4
//	    (BYTE_TYP) (maxbits | block_compress));          // byte 7
func ParseHeader(data []byte) (Header, error) {
	if len(data) < CsHeadSize {
		return Header{}, fmt.Errorf("input too small (%d bytes), need at least %d", len(data), CsHeadSize)
	}

	h := Header{
		UncompressedSize: binary.LittleEndian.Uint32(data[0:4]),
		Version:          int((data[4] >> 4) & 0x0F),
		Algorithm:        int(data[4] & 0x0F),
	}
	copy(h.Flags[:], data[5:8])

	switch h.Algorithm {
	case AlgLZC:
		h.AlgorithmName = "LZC"
	case AlgLZH:
		h.AlgorithmName = "LZH"
	default:
		h.AlgorithmName = "unknown"
		return h, fmt.Errorf("unknown algorithm: %d (expected 1=LZC or 2=LZH)", h.Algorithm)
	}

	if h.UncompressedSize == 0 || h.UncompressedSize > maxUncompressedSize {
		return h, fmt.Errorf("implausible uncompressed size: %d", h.UncompressedSize)
	}

	return h, nil
}

// =========================================================================
// Analysis Utilities
// =========================================================================

// Entropy calculates the Shannon entropy of data in bits per byte.
//
// Returns a value between 0.0 and 8.0:
//   - 0.0 = all bytes identical (no information)
//   - 1.0 = two equally frequent values
//   - 8.0 = all 256 byte values equally frequent (maximum entropy)
//
// Compressed or encrypted data typically has entropy > 7.5.
// Uncompressed text files are usually between 4.0 and 6.5.
// This is the first diagnostic check when analyzing an unknown BLOB.
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// UniqueBytes counts distinct byte values present in the data.
// Compressed data typically uses all 256 possible values.
func UniqueBytes(data []byte) int {
	var seen [256]bool
	for _, b := range data {
		seen[b] = true
	}
	count := 0
	for _, s := range seen {
		if s {
			count++
		}
	}
	return count
}

// IsLegacyFormat checks whether the BLOB uses an older SAP compression
// format that is NOT standard DEFLATE. These legacy formats require
// the proprietary MaxDB C++ decompressor (vpa106cslzc.cpp / vpa108csulzh.cpp).
//
// Legacy formats are identified by magic bytes 0x1F9D (LZC) or 0x1F9E (LZH)
// appearing at bytes 9-10 of the BLOB (offset 1-2 within the compressed data).
//
// Modern SAP systems (NetWeaver 7.x+) typically use the DEFLATE-based format.
func IsLegacyFormat(data []byte) (bool, uint16) {
	if len(data) > CsHeadSize+2 {
		magic := binary.BigEndian.Uint16(data[CsHeadSize+1 : CsHeadSize+3])
		if magic == 0x1f9d || magic == 0x1f9e {
			return true, magic
		}
	}
	return false, 0
}

// DetectFileType identifies common file types by their magic bytes.
// This is used after decompression to verify the output makes sense.
func DetectFileType(data []byte) string {
	if len(data) < 4 {
		return "unknown"
	}
	switch {
	case string(data[:4]) == "%PDF":
		return "PDF"
	case data[0] == 0xFF && data[1] == 0xD8:
		return "JPEG"
	case bytes.Equal(data[:4], []byte{0x89, 'P', 'N', 'G'}):
		return "PNG"
	case bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}):
		return "ZIP/DOCX/XLSX"
	case bytes.Equal(data[:4], []byte{0xD0, 0xCF, 0x11, 0xE0}):
		return "OLE2/DOC/XLS"
	case len(data) >= 5 && (string(data[:5]) == "<?xml" || string(data[:5]) == "<html"):
		return "XML/HTML"
	case data[0] == '{' || data[0] == '[':
		return "JSON"
	default:
		return "unknown"
	}
}

// Analyze performs a full diagnostic analysis of a SAP BLOB without
// actually decompressing it. Useful for understanding what a BLOB
// contains before attempting decompression.
func Analyze(data []byte) Analysis {
	a := Analysis{
		FileSize: len(data),
		Entropy:  Entropy(data),
	}

	h, _ := ParseHeader(data)
	a.Header = h

	legacy, magic := IsLegacyFormat(data)
	a.IsLegacyFormat = legacy
	a.LegacyMagic = magic

	if !legacy && len(data) > CsHeadSize {
		nonsenseLen := int(data[CsHeadSize] & ((1 << NonsenseLenBits) - 1))
		a.NonsenseBits = NonsenseLenBits + nonsenseLen
	}

	if h.UncompressedSize > 0 {
		a.CompressionRate = float64(len(data)) / float64(h.UncompressedSize) * 100
	}

	return a
}

// =========================================================================
// Bit Shifting
// =========================================================================

// shiftBitsRight removes n bits from the LSB end of each byte in the data,
// effectively shifting the entire bitstream right by n positions.
//
// This is the core operation that makes SAP decompression possible with
// standard DEFLATE libraries. After the 8-byte SAP header, the compressed
// data starts with "nonsense" padding bits that misalign the DEFLATE stream.
// By shifting these bits out, we get a standard DEFLATE stream.
//
// Example with n=3 and data = [0x25, 0xDF, ...]:
//
//	Byte 0: 0x25 = 0b|00100101|
//	Byte 1: 0xDF = 0b|11011111|
//
//	result[0] = (0x25 >> 3) | (0xDF << 5)
//	          = 0b00000100  | 0b11100000
//	          = 0b11100100
//	          = 0xE4
//
// The resulting 0xE4 starts a valid DEFLATE block:
//   - bit 0 = 0 → not the last block
//   - bits 1-2 = 10 → dynamic Huffman (block type 2)
func shiftBitsRight(data []byte, bitsToSkip int) []byte {
	if bitsToSkip == 0 {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	length := len(data)
	result := make([]byte, length)
	shift := uint(bitsToSkip)
	carry := 8 - shift

	for i := 0; i < length-1; i++ {
		result[i] = (data[i] >> shift) | (data[i+1] << carry)
	}
	if length > 0 {
		result[length-1] = data[length-1] >> shift
	}
	return result
}

// =========================================================================
// Decompression
// =========================================================================

// Decompress takes a raw SAP BLOB (including the 8-byte header) and
// returns the original uncompressed data.
//
// The process:
//  1. Parse the 8-byte SAP header to get the uncompressed size and algorithm
//  2. Check for legacy format (returns error if detected)
//  3. Read the "nonsense" padding length from the first 2 bits after the header
//  4. Bit-shift the stream to remove the padding
//  5. Feed the aligned stream to Go's compress/flate (raw DEFLATE mode)
//
// Returns the decompressed data, or an error if decompression fails.
// On success, the output should match the uncompressed size from the header.
func Decompress(input []byte) ([]byte, error) {
	if len(input) <= CsHeadSize {
		return nil, fmt.Errorf("input too small: need header plus compressed payload")
	}

	// Step 1: Parse SAP header
	header, err := ParseHeader(input)
	if err != nil {
		return nil, fmt.Errorf("header error: %w", err)
	}

	if header.Algorithm != AlgLZH && header.Algorithm != AlgLZC {
		return nil, fmt.Errorf("unsupported algorithm: %d (%s)", header.Algorithm, header.AlgorithmName)
	}

	// Step 2: Check for legacy format
	// Older SAP systems used a different (non-DEFLATE) compression that
	// we can't handle with standard libraries. Detect and report clearly.
	if legacy, magic := IsLegacyFormat(input); legacy {
		return nil, fmt.Errorf(
			"legacy SAP format detected (magic 0x%04X) — "+
				"this format requires the proprietary MaxDB C++ decompressor. "+
				"See https://github.com/OWASP/pysap for the C++ implementation",
			magic,
		)
	}

	// Step 3: Calculate nonsense bits to skip
	//
	// The SAP compressor writes random padding bits before the DEFLATE
	// stream. The first NonsenseLenBits (2) bits encode a value N,
	// then N more random bits follow. Total padding = 2 + N bits.
	//
	// From vpa108csulzh.cpp, NoBits():
	//   NEEDBITS(NONSENSE_LENBITS)
	//   x = (unsigned) (bb & ((1 << NONSENSE_LENBITS) - 1));
	//   DUMPBITS(NONSENSE_LENBITS)
	//   if (x) { NEEDBITS(x); DUMPBITS(x); }
	firstByte := input[CsHeadSize]
	nonsenseLen := int(firstByte & ((1 << NonsenseLenBits) - 1))
	totalSkipBits := NonsenseLenBits + nonsenseLen

	// Step 4: Shift bitstream to remove padding
	deflateStream := shiftBitsRight(input[CsHeadSize:], totalSkipBits)

	// Step 5: Decompress using standard DEFLATE.
	// flate.NewReader expects raw DEFLATE (no zlib/gzip wrapper),
	// which is exactly what SAP's LZH produces after removing the padding.
	fr := flate.NewReader(bytes.NewReader(deflateStream))
	defer fr.Close()

	output, err := io.ReadAll(fr)
	if err != nil {
		return nil, fmt.Errorf("deflate error: %w", err)
	}

	if len(output) != int(header.UncompressedSize) {
		return nil, fmt.Errorf(
			"decompressed size mismatch: got %d bytes, expected %d",
			len(output),
			header.UncompressedSize,
		)
	}

	return output, nil
}
