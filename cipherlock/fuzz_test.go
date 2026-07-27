package cipherlock

import (
	"bytes"
	"testing"
)

// fuzzPassword is a fixed password used by all fuzz targets so that any valid
// seed corpus can be decrypted regardless of when it was generated.
var fuzzPassword = []byte("fuzz-test-password")

// FuzzDecryptStream fuzzes the v0x05 (legacy stream) decrypt path.
//
// Seed: a valid encrypted blob generated with fastBenchConfig.
// The fuzzer mutates the ciphertext and verifies the function never panics.
// Expected outcomes: ErrInvalidFormat, ErrAuthFailed, ErrCorrupted, or success.
func FuzzDecryptStream(f *testing.F) {
	plaintext := []byte("hello world fuzz")
	var buf bytes.Buffer
	cfg := fastBenchConfig()
	if err := Encrypt(&buf, bytes.NewReader(plaintext), fuzzPassword, cfg); err != nil {
		f.Fatalf("seeding corpus: %v", err)
	}
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		_ = Decrypt(&out, bytes.NewReader(data), fuzzPassword)
	})
}

// FuzzDecryptStreamV2 fuzzes the v0x06 (stream v2 with meta) decrypt path.
func FuzzDecryptStreamV2(f *testing.F) {
	plaintext := []byte("hello world fuzz v2")
	var buf bytes.Buffer
	cfg := fastBenchConfig()
	if err := EncryptStreamV2(&buf, bytes.NewReader(plaintext), fuzzPassword, cfg); err != nil {
		f.Fatalf("seeding corpus: %v", err)
	}
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		_, _ = DecryptStreamV2(&out, bytes.NewReader(data), fuzzPassword)
	})
}

// FuzzDecryptStreamMulti fuzzes the v0x07 (multi-recipient) decrypt path.
func FuzzDecryptStreamMulti(f *testing.F) {
	plaintext := []byte("hello world fuzz multi")
	var buf bytes.Buffer
	cfg := fastBenchConfig()
	if err := EncryptStreamMulti(&buf, bytes.NewReader(plaintext), [][]byte{fuzzPassword}, cfg); err != nil {
		f.Fatalf("seeding corpus: %v", err)
	}
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		_, _ = DecryptStreamMultiFromReader(&out, bytes.NewReader(data), fuzzPassword)
	})
}

// FuzzDecryptAsymmetric fuzzes the v0x08 (asymmetric X25519) decrypt path.
func FuzzDecryptAsymmetric(f *testing.F) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		f.Fatalf("generating keypair: %v", err)
	}

	plaintext := []byte("hello world fuzz asymmetric")
	var buf bytes.Buffer
	cfg := fastBenchConfig()
	if err := EncryptAsymmetric(&buf, bytes.NewReader(plaintext), []*X25519Recipient{
		{PublicKey: id.PublicKey},
	}, cfg); err != nil {
		f.Fatalf("seeding corpus: %v", err)
	}
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		_ = DecryptAsymmetric(&out, bytes.NewReader(data), id)
	})
}

// FuzzDeserializeIdentity fuzzes the X25519 identity file deserialization.
func FuzzDeserializeIdentity(f *testing.F) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		f.Fatalf("generating keypair: %v", err)
	}

	serialized, err := SerializeX25519Identity(id, fuzzPassword)
	if err != nil {
		f.Fatalf("serializing identity: %v", err)
	}
	f.Add(serialized)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DeserializeX25519Identity(data, fuzzPassword)
	})
}

// FuzzUnarmorBytes fuzzes the base64 armor decoding used for ASCII-armored files.
func FuzzUnarmorBytes(f *testing.F) {
	valid := "-----BEGIN CIPHERLOCK-----\nSGVsbG8=\n-----END CIPHERLOCK-----\n"
	f.Add([]byte(valid))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnarmorBytes(data)
	})
}
