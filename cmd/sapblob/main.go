package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sapblob "github.com/umsername/sap-blob-decompress"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type options struct {
	Analyze      bool
	IdentifyType bool
	JSON         bool
	Output       string
	Force        bool
	ShowVer      bool
}

type jsonAnalysis struct {
	FileSize         int     `json:"file_size"`
	UncompressedSize uint32  `json:"uncompressed_size"`
	Version          int     `json:"version"`
	Algorithm        int     `json:"algorithm"`
	AlgorithmName    string  `json:"algorithm_name"`
	Flags            [3]byte `json:"flags"`
	CompressionRate  float64 `json:"compression_rate_percent"`
	Entropy          float64 `json:"entropy"`
	UniqueByteValues int     `json:"unique_byte_values"`
	NonsenseBits     int     `json:"nonsense_bits"`
	LegacyFormat     bool    `json:"legacy_format"`
	LegacyMagic      uint16  `json:"legacy_magic,omitempty"`
}

type jsonResult struct {
	InputFile         string       `json:"input_file"`
	OutputFile        string       `json:"output_file,omitempty"`
	DetectedType      string       `json:"detected_type,omitempty"`
	OutputSize        int          `json:"output_size,omitempty"`
	MD5               string       `json:"md5,omitempty"`
	Analysis          jsonAnalysis `json:"analysis"`
	DecompressionOkay bool         `json:"decompression_ok"`
}

func main() {
	opts, args, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usageText())
			return
		}
		fatalf("%v\n\n%s", err, usageText())
	}

	if opts.ShowVer {
		fmt.Printf("sapblob %s\ncommit: %s\nbuilt:  %s\n", version, commit, date)
		return
	}

	if len(args) == 0 {
		fmt.Print(usageText())
		os.Exit(2)
	}
	if len(args) > 1 {
		fatalf("too many positional arguments\n\n%s", usageText())
	}

	inputPath := args[0]
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fatalf("failed to read %q: %v", inputPath, err)
	}

	analysis := sapblob.Analyze(data)

	if opts.Analyze {
		emitAnalysis(inputPath, analysis, data, opts.JSON)
		return
	}

	if analysis.IsLegacyFormat {
		fatalf("legacy SAP format detected (magic 0x%04X). This repository handles the modern header + bit-padded DEFLATE variant, not the older MaxDB-specific legacy stream.", analysis.LegacyMagic)
	}

	result, err := sapblob.Decompress(data)
	if err != nil {
		fatalf("decompression failed: %v", err)
	}

	detectedType := sapblob.DetectFileType(result)

	if opts.IdentifyType {
		emitDetectedType(inputPath, detectedType, analysis, opts.JSON)
		return
	}

	outputPath := opts.Output
	if outputPath == "" {
		outputPath = defaultOutputPath(inputPath, detectedType)
	}

	if err := ensureWritablePath(outputPath, opts.Force); err != nil {
		fatalf("cannot write output %q: %v", outputPath, err)
	}
	if err := os.WriteFile(outputPath, result, 0o644); err != nil {
		fatalf("failed to write %q: %v", outputPath, err)
	}

	checksum := fmt.Sprintf("%x", md5.Sum(result))

	if opts.JSON {
		payload := jsonResult{
			InputFile:         inputPath,
			OutputFile:        outputPath,
			DetectedType:      detectedType,
			OutputSize:        len(result),
			MD5:               checksum,
			Analysis:          makeJSONAnalysis(analysis, data),
			DecompressionOkay: true,
		}
		writeJSON(payload)
		return
	}

	printSummary(inputPath, outputPath, analysis, detectedType, len(result), checksum)
}

func parseFlags(args []string) (options, []string, error) {
	var opts options
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-h", "--help":
			return opts, nil, flag.ErrHelp
		case "-a", "--analyze":
			opts.Analyze = true
		case "-t", "--identify-type":
			opts.IdentifyType = true
		case "-j", "--json":
			opts.JSON = true
		case "-f", "--force":
			opts.Force = true
		case "-V", "--version":
			opts.ShowVer = true
		case "-o", "--output":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("%s requires a value", arg)
			}
			opts.Output = args[i]
		default:
			if strings.HasPrefix(arg, "--output=") {
				opts.Output = strings.TrimPrefix(arg, "--output=")
				continue
			}
			if strings.HasPrefix(arg, "-o=") {
				opts.Output = strings.TrimPrefix(arg, "-o=")
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return opts, nil, fmt.Errorf("unknown option: %s", arg)
			}
			positional = append(positional, arg)
		}
	}

	if opts.Analyze && opts.Output != "" {
		return opts, nil, errors.New("--output cannot be used together with --analyze")
	}
	if opts.Analyze && opts.IdentifyType {
		return opts, nil, errors.New("--analyze cannot be used together with --identify-type")
	}

	return opts, positional, nil
}

func detectedExtension(detectedType string) string {
	switch detectedType {
	case "PDF":
		return ".pdf"
	case "JPEG":
		return ".jpg"
	case "PNG":
		return ".png"
	case "ZIP/DOCX/XLSX":
		return ".zip"
	case "OLE2/DOC/XLS":
		return ".bin"
	case "XML/HTML":
		return ".xml"
	case "JSON":
		return ".json"
	default:
		return ".bin"
	}
}

func emitAnalysis(inputPath string, analysis sapblob.Analysis, raw []byte, asJSON bool) {
	if asJSON {
		writeJSON(jsonResult{InputFile: inputPath, Analysis: makeJSONAnalysis(analysis, raw), DecompressionOkay: false})
		return
	}

	fmt.Println("sapblob analysis")
	fmt.Printf("input              : %s\n", inputPath)
	fmt.Printf("file size          : %d bytes\n", analysis.FileSize)
	fmt.Printf("uncompressed size  : %d bytes\n", analysis.Header.UncompressedSize)
	fmt.Printf("version            : %d\n", analysis.Header.Version)
	fmt.Printf("algorithm          : %d (%s)\n", analysis.Header.Algorithm, analysis.Header.AlgorithmName)
	fmt.Printf("flags              : %02x %02x %02x\n", analysis.Header.Flags[0], analysis.Header.Flags[1], analysis.Header.Flags[2])
	fmt.Printf("compression ratio  : %.1f%%\n", analysis.CompressionRate)
	fmt.Printf("entropy            : %.4f bits/byte\n", analysis.Entropy)
	fmt.Printf("unique byte values : %d / 256\n", sapblob.UniqueBytes(raw))
	fmt.Printf("nonsense bits      : %d\n", analysis.NonsenseBits)
	fmt.Printf("legacy format      : %v\n", analysis.IsLegacyFormat)
	if analysis.IsLegacyFormat {
		fmt.Printf("legacy magic       : 0x%04X\n", analysis.LegacyMagic)
	}
}

func emitDetectedType(inputPath, detectedType string, analysis sapblob.Analysis, asJSON bool) {
	if asJSON {
		writeJSON(jsonResult{InputFile: inputPath, DetectedType: detectedType, Analysis: makeJSONAnalysis(analysis, nil), DecompressionOkay: true})
		return
	}

	fmt.Printf("Input         : %s\n", inputPath)
	fmt.Printf("Detected type : %s\n", detectedType)
	fmt.Printf("Header        : %s v%d\n", analysis.Header.AlgorithmName, analysis.Header.Version)
}

func printSummary(inputPath, outputPath string, analysis sapblob.Analysis, detectedType string, outputSize int, checksum string) {
	fmt.Printf("Input   : %s (%d bytes)\n", inputPath, analysis.FileSize)
	fmt.Printf("Header  : %s v%d, expected original size %d bytes\n", analysis.Header.AlgorithmName, analysis.Header.Version, analysis.Header.UncompressedSize)
	fmt.Printf("Stats   : entropy %.2f bits/byte, nonsense padding %d bits, ratio %.1f%%\n", analysis.Entropy, analysis.NonsenseBits, analysis.CompressionRate)
	fmt.Printf("Output  : %s (%d bytes, detected type: %s)\n", outputPath, outputSize, detectedType)
	fmt.Printf("MD5     : %s\n", checksum)
}

func makeJSONAnalysis(analysis sapblob.Analysis, raw []byte) jsonAnalysis {
	uniqueBytes := 0
	if raw != nil {
		uniqueBytes = sapblob.UniqueBytes(raw)
	}

	return jsonAnalysis{
		FileSize:         analysis.FileSize,
		UncompressedSize: analysis.Header.UncompressedSize,
		Version:          analysis.Header.Version,
		Algorithm:        analysis.Header.Algorithm,
		AlgorithmName:    analysis.Header.AlgorithmName,
		Flags:            analysis.Header.Flags,
		CompressionRate:  analysis.CompressionRate,
		Entropy:          analysis.Entropy,
		UniqueByteValues: uniqueBytes,
		NonsenseBits:     analysis.NonsenseBits,
		LegacyFormat:     analysis.IsLegacyFormat,
		LegacyMagic:      analysis.LegacyMagic,
	}
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatalf("failed to encode JSON: %v", err)
	}
}

func defaultOutputPath(inputPath, detectedType string) string {
	base := strings.TrimSuffix(inputPath, filepath.Ext(inputPath))
	if base == "" {
		base = inputPath
	}
	return base + detectedExtension(detectedType)
}

func ensureWritablePath(path string, force bool) error {
	if path == "" {
		return errors.New("empty output path")
	}

	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("file already exists (use --force to overwrite)")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}

	return os.MkdirAll(dir, 0o755)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func usageText() string {
	return `sapblob - SAP BLOB analyzer and decompressor

Usage:
  sapblob [options] <input-file>

Examples:
  sapblob example.blob
  sapblob example.blob --output recovered.pdf
  sapblob --output recovered.pdf example.blob
  sapblob --analyze example.blob
  sapblob --identify-type example.blob
  sapblob --json --identify-type example.blob
  sapblob example.blob --force --output out/result.bin

Batch examples:
  for f in samples/*.blob; do sapblob "$f"; done
  Get-ChildItem .\samples\*.blob | ForEach-Object { sapblob $_.FullName }

Options:
  -o, --output <path>        Write decompressed payload to this file.
                             Default: best-effort detected extension,
                             with .bin as the fallback.
  -a, --analyze              Inspect the SAP wrapper without writing output.
  -t, --identify-type        Decompress in memory and identify the recovered
                             payload type from magic bytes.
  -j, --json                 Print machine-readable JSON output.
  -f, --force                Overwrite an existing output file.
  -V, --version              Show version information.
  -h, --help                 Show this help text.

Notes:
  - The recovered payload is not necessarily a PDF. It may be any file type.
  - By default, output is written next to the input file.
  - The CLI uses best-effort type detection for the default extension.
  - Unknown payload types fall back to .bin.
  - Legacy SAP formats are detected early and reported explicitly.
`
}
