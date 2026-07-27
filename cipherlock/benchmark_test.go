package cipherlock

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"golang.org/x/crypto/argon2"
)

// fastBenchConfig returns a low-cost Argon2id config so benchmarks measure crypto
// throughput without being dominated by the KDF (which is constant cost per call).
func fastBenchConfig() *Config {
	return &Config{
		SaltLen:   16,
		Time:      1,
		Memory:    8 * 1024,
		Threads:   1,
		KeyLen:    32,
		ChunkSize: 64 * 1024,
	}
}

func benchData(b *testing.B, size int) []byte {
	b.Helper()
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		b.Fatal(err)
	}
	return data
}

func BenchmarkEncryptStreamV05(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := EncryptStream(&buf, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptStreamV05(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
		b.Fatal(err)
	}
	encBytes := enc.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec bytes.Buffer
		if err := DecryptStream(&dec, bytes.NewReader(encBytes), []byte("bench-pwd")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptStreamV2(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := EncryptStreamV2(&buf, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptStreamV2(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
		b.Fatal(err)
	}
	encBytes := enc.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec bytes.Buffer
		if _, err := DecryptStreamV2(&dec, bytes.NewReader(encBytes), []byte("bench-pwd")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptStreamMulti(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	pwds := [][]byte{[]byte("alice"), []byte("bob")}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := EncryptStreamMulti(&buf, bytes.NewReader(data), pwds, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptStreamMulti(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	pwds := [][]byte{[]byte("alice"), []byte("bob")}
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(data), pwds, cfg); err != nil {
		b.Fatal(err)
	}
	encBytes := enc.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec bytes.Buffer
		if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(encBytes), []byte("alice")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReKeyStreamV05(b *testing.B) {
	data := benchData(b, 1024*1024)
	cfg := fastBenchConfig()
	var enc bytes.Buffer
	if err := EncryptStream(&enc, bytes.NewReader(data), []byte("old"), cfg); err != nil {
		b.Fatal(err)
	}
	encBytes := enc.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := ReKey(&out, bytes.NewReader(encBytes), []byte("old"), []byte("new"), nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArgon2idDefault(b *testing.B) {
	// Measures just the KDF cost at default Argon2id parameters so callers can
	// understand the per-call latency they pay before any chunk is encrypted.
	cfg := DefaultConfig
	salt := make([]byte, cfg.SaltLen)
	_, _ = io.ReadFull(rand.Reader, salt)
	pwd := []byte("benchmark-password")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(pwd, salt, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
	}
}

func BenchmarkEncryptStreamV2Compressible(b *testing.B) {
	// Highly compressible data (repeated text pattern)
	data := bytes.Repeat([]byte("Hello, cipherlock compression is working! "), 16384) // ~1MB
	cfg := fastBenchConfig()
	cfg.Compression = true
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := EncryptStreamV2(&buf, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptStreamV2Compressible(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, cipherlock compression is working! "), 16384) // ~1MB
	cfg := fastBenchConfig()
	cfg.Compression = true
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
		b.Fatal(err)
	}
	encBytes := enc.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec bytes.Buffer
		if _, err := DecryptStreamV2(&dec, bytes.NewReader(encBytes), []byte("bench-pwd")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptStreamV2CompressibleSmall(b *testing.B) {
	data := bytes.Repeat([]byte("compressible "), 128) // ~1.5KB
	cfg := fastBenchConfig()
	cfg.Compression = true
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := EncryptStreamV2(&buf, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptStreamV2CompressibleSmall(b *testing.B) {
	data := bytes.Repeat([]byte("compressible "), 128) // ~1.5KB
	cfg := fastBenchConfig()
	cfg.Compression = true
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(data), []byte("bench-pwd"), cfg); err != nil {
		b.Fatal(err)
	}
	encBytes := enc.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dec bytes.Buffer
		if _, err := DecryptStreamV2(&dec, bytes.NewReader(encBytes), []byte("bench-pwd")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArmor(b *testing.B) {
	data := benchData(b, 64*1024)
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(enc, data)

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := Armor(&buf, enc); err != nil {
			b.Fatal(err)
		}
	}
}
