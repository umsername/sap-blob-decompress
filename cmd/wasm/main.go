//go:build js && wasm

package main

import (
	"crypto/md5"
	"fmt"
	"syscall/js"

	"github.com/umsername/sap-blob-decompress"
)

func main() {
	js.Global().Set("sapAnalyze", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		data := getBytes(args[0])
		a := sapblob.Analyze(data)
		return map[string]interface{}{"uncompressedSize": a.Header.UncompressedSize, "algorithmName": a.Header.AlgorithmName, "compressionRate": a.CompressionRate, "entropy": a.Entropy, "nonsenseBits": a.NonsenseBits, "legacyFormat": a.IsLegacyFormat}
	}))
	js.Global().Set("sapDecompress", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		data := getBytes(args[0])
		res, err := sapblob.Decompress(data)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		uint8Array := js.Global().Get("Uint8Array").New(len(res))
		js.CopyBytesToJS(uint8Array, res)
		return map[string]interface{}{"data": uint8Array, "md5": fmt.Sprintf("%x", md5.Sum(res))}
	}))
	js.Global().Set("sapDetectType", js.FuncOf(func(this js.Value, args []js.Value) interface{} { return sapblob.DetectFileType(getBytes(args[0])) }))
	select {}
}

func getBytes(v js.Value) []byte { b := make([]byte, v.Length()); js.CopyBytesToGo(b, v); return b }
