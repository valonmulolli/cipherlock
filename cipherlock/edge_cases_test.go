package cipherlock

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestStreamV2TruncatedHeader(t *testing.T) {
	// Header says version 0x06 but stream is truncated mid-header
	truncated := []byte{'C', 'V', '2', 0, 0x06, 0x01, 0x10}
	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(truncated), []byte("pwd")); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestStreamV2TruncatedBody(t *testing.T) {
	plaintext := []byte("data that gets encrypted")
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), []byte("pwd"), fastConfig()); err != nil {
		t.Fatal(err)
	}
	data := enc.Bytes()
	// Truncate inside the first chunk's ciphertext
	truncated := data[:len(data)-8]
	var dec bytes.Buffer
	_, err := DecryptStreamV2(&dec, bytes.NewReader(truncated), []byte("pwd"))
	if err == nil {
		t.Fatal("expected error for truncated body, got nil")
	}
}

func TestStreamV2RandomBytesDoesNotPanic(t *testing.T) {
	// Feed random bytes prefixed with valid magic+version; the decryptor must
	// return a sentinel error (ErrAuthFailed, ErrCorrupted, or ErrInvalidFormat)
	// rather than panicking. This is a cheap fuzz-style regression test.
	cfg := fastConfig()
	cfg.Checksum = true
	cfg.FileMeta = &FileMeta{Name: "x", Size: 1, ModTime: time.Now()}

	for i := 0; i < 50; i++ {
		buf := make([]byte, 256)
		_, _ = io.ReadFull(rand.Reader, buf)
		// Override first 5 bytes with magic+version
		buf[0], buf[1], buf[2], buf[3], buf[4] = 'C', 'V', '2', 0, 0x06
		_ = cfg // ensures cfg compile-time use even if loop test path changes

		var dec bytes.Buffer
		_, err := DecryptStreamV2(&dec, bytes.NewReader(buf), []byte("pwd"))
		if err == nil {
			t.Fatalf("iteration %d: expected error for random input", i)
		}
	}
}

func TestStreamV2ChunkSizeBoundary(t *testing.T) {
	// Build a plaintext of exactly N*ChunkSize bytes so the chunk loop terminates
	// exactly at the boundary, no partial chunk, no extra chunk.
	cfg := fastConfig()
	cfg.ChunkSize = 16
	plaintext := bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 4) // 64 bytes
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), []byte("pwd"), cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), []byte("pwd")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("boundary round-trip mismatch")
	}
}

func TestStreamV2LongFilename(t *testing.T) {
	// Filename at uint16 max
	cfg := fastConfig()
	name := strings.Repeat("a", 65535)
	cfg.FileMeta = &FileMeta{
		Name:    name,
		Size:    10,
		ModTime: time.Now(),
	}
	plaintext := []byte("data with long name")
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), []byte("pwd"), cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	meta, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), []byte("pwd"))
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil || meta.Name != name {
		t.Fatal("long filename not preserved")
	}
}

func TestStreamMultiTruncatedHeader(t *testing.T) {
	truncated := []byte{'C', 'V', '2', 0, 0x07, 0x01}
	var dec bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(truncated), []byte("pwd")); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestStreamMultiTruncatedBody(t *testing.T) {
	plaintext := []byte("data that gets encrypted with multi")
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), [][]byte{[]byte("pwd")}, fastConfig()); err != nil {
		t.Fatal(err)
	}
	data := enc.Bytes()
	truncated := data[:len(data)-8]
	var dec bytes.Buffer
	_, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(truncated), []byte("pwd"))
	if err == nil {
		t.Fatal("expected error for truncated body, got nil")
	}
}

func TestStreamMultiRandomBytesDoesNotPanic(t *testing.T) {
	for i := 0; i < 50; i++ {
		buf := make([]byte, 256)
		_, _ = io.ReadFull(rand.Reader, buf)
		buf[0], buf[1], buf[2], buf[3], buf[4] = 'C', 'V', '2', 0, 0x07

		var dec bytes.Buffer
		_, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(buf), []byte("pwd"))
		if err == nil {
			t.Fatalf("iteration %d: expected error for random input", i)
		}
	}
}

func TestStreamMultiChunkSizeBoundary(t *testing.T) {
	cfg := fastConfig()
	cfg.ChunkSize = 16
	plaintext := bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 4) // 64 bytes
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), [][]byte{[]byte("pwd")}, cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), []byte("pwd")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("boundary round-trip mismatch")
	}
}

func TestStreamMultiLargeChunkCount(t *testing.T) {
	// Test that many small chunks (more than typical chunk size) round-trip correctly.
	cfg := fastConfig()
	cfg.ChunkSize = 1
	plaintext := make([]byte, 200)
	_, _ = io.ReadFull(rand.Reader, plaintext)
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), [][]byte{[]byte("pwd")}, cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), []byte("pwd")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("many-chunk round-trip mismatch")
	}
}

func TestV06CorruptedMetadataChunk(t *testing.T) {
	// Encrypt with metadata, then corrupt the metadata chunk. The decrypt should
	// fail with ErrAuthFailed before the data chunks are processed.
	cfg := fastConfig()
	cfg.FileMeta = &FileMeta{
		Name:    "secret.bin",
		Size:    50,
		ModTime: time.Now(),
	}
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader([]byte("plaintext-data")), []byte("pwd"), cfg); err != nil {
		t.Fatal(err)
	}
	// Header: magic(4) + version(1) + flags(1) + saltLen(2) + salt(16) + params(17) = 41
	// After that, the metadata chunk starts. Corrupt a byte in the metadata ciphertext.
	data := enc.Bytes()
	if len(data) < 50 {
		t.Fatal("encrypted blob too small")
	}
	data[45] ^= 0xFF

	var dec bytes.Buffer
	_, err := DecryptStreamV2(&dec, bytes.NewReader(data), []byte("pwd"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestV07CorruptedSealedKey(t *testing.T) {
	// Encrypt multi, then corrupt one of the sealed file keys. The decrypt with that
	// password should fail; with the other password should still succeed.
	pwds := [][]byte{[]byte("alice"), []byte("bob")}
	plaintext := []byte("data with multiple recipients")
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), pwds, fastConfig()); err != nil {
		t.Fatal(err)
	}
	data := enc.Bytes()
	// Header layout for v0x07 (offsets, sizes in bytes):
	//   0-3  magic (4)
	//   4    version (1)
	//   5    flags (1)
	//   6-9  numRecipients (4)
	//   10-11 saltLen (2)
	//   12-27 salt (16)
	//   28-31 Time (4)
	//   32-35 Memory (4)
	//   36   Threads (1)
	//   37-40 KeyLen (4)
	//   41-52 KeyNonce (12)
	//   53-54 SealedKey length (2)
	//   55+  SealedKey
	// Corrupt a byte well inside the first recipient's SealedKey so the header
	// parses successfully but the AES-GCM unseal fails.
	const sealedKeyOffset = 55
	data[sealedKeyOffset] ^= 0xFF

	// With "alice" (the corrupted entry's password), should fail
	var dec1 bytes.Buffer
	_, err := DecryptStreamMultiFromReader(&dec1, bytes.NewReader(data), []byte("alice"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed with corrupted alice, got %v", err)
	}

	// With "bob" (untouched entry), should succeed
	var dec2 bytes.Buffer
	_, err = DecryptStreamMultiFromReader(&dec2, bytes.NewReader(data), []byte("bob"))
	if err != nil {
		t.Errorf("expected success with bob, got %v", err)
	}
	if !bytes.Equal(dec2.Bytes(), plaintext) {
		t.Error("bob-decrypted data mismatch")
	}
}

func TestV07RecipientsPreservedOrder(t *testing.T) {
	// All recipients should be able to decrypt, regardless of order.
	pwds := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta")}
	plaintext := []byte("data")
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), pwds, fastConfig()); err != nil {
		t.Fatal(err)
	}
	for _, pwd := range pwds {
		var dec bytes.Buffer
		_, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), pwd)
		if err != nil {
			t.Errorf("decrypt with %q: %v", string(pwd), err)
			continue
		}
		if !bytes.Equal(dec.Bytes(), plaintext) {
			t.Errorf("decrypt with %q: data mismatch", string(pwd))
		}
	}
}
