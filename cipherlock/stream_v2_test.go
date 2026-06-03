package cipherlock

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"
)

// fastConfig returns a Config that uses low Argon2id cost so tests stay fast.
// All variants of streaming encryption share this config in the v06 tests.
func fastConfig() *Config {
	return &Config{
		SaltLen:   16,
		Time:      1,
		Memory:    8 * 1024,
		Threads:   1,
		KeyLen:    32,
		ChunkSize: 4 * 1024,
	}
}

func TestEncryptDecryptStreamV2RoundTrip(t *testing.T) {
	plaintext := []byte("v0x06 streaming round trip")
	password := []byte("v06-pwd")

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, fastConfig()); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	var dec bytes.Buffer
	meta, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStreamV2: %v", err)
	}
	if meta != nil {
		t.Fatalf("expected nil metadata, got %+v", meta)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", dec.Bytes(), plaintext)
	}
}

func TestEncryptDecryptStreamV2WithMeta(t *testing.T) {
	modTime := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	meta := &FileMeta{
		Name:    "secret-document.bin",
		Size:    1024,
		ModTime: modTime,
	}
	plaintext := []byte("v0x06 with metadata")
	password := []byte("v06-meta-pwd")

	cfg := fastConfig()
	cfg.FileMeta = meta

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	// Meta must NOT be visible in cleartext
	encBytes := enc.Bytes()
	if bytes.Contains(encBytes, []byte("secret-document.bin")) {
		t.Fatal("filename leaked in cleartext in v0x06")
	}

	var dec bytes.Buffer
	gotMeta, err := DecryptStreamV2(&dec, bytes.NewReader(encBytes), password)
	if err != nil {
		t.Fatalf("DecryptStreamV2: %v", err)
	}
	if gotMeta == nil {
		t.Fatal("expected metadata, got nil")
	}
	if gotMeta.Name != meta.Name {
		t.Errorf("name: got %q, want %q", gotMeta.Name, meta.Name)
	}
	if gotMeta.Size != meta.Size {
		t.Errorf("size: got %d, want %d", gotMeta.Size, meta.Size)
	}
	if !gotMeta.ModTime.Equal(meta.ModTime) {
		t.Errorf("modtime: got %v, want %v", gotMeta.ModTime, meta.ModTime)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatalf("data mismatch")
	}
}

func TestEncryptDecryptStreamV2WrongPassword(t *testing.T) {
	plaintext := []byte("data")
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), []byte("right"), fastConfig()); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	_, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), []byte("wrong"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestEncryptDecryptStreamV2LargeData(t *testing.T) {
	plaintext := make([]byte, 256*1024+37)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatal(err)
	}
	password := []byte("v06-large")

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, fastConfig()); err != nil {
		t.Fatal(err)
	}

	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), password); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("large round-trip mismatch")
	}
}

func TestEncryptDecryptStreamV2WithChecksum(t *testing.T) {
	plaintext := []byte("checksum content for v0x06")
	password := []byte("v06-sum")

	cfg := fastConfig()
	cfg.Checksum = true

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), password); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("data mismatch")
	}
}

func TestEncryptDecryptStreamV2ChecksumCorrupted(t *testing.T) {
	plaintext := []byte("checksum tampered")
	password := []byte("v06-tamper")

	cfg := fastConfig()
	cfg.Checksum = true

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatal(err)
	}
	data := enc.Bytes()
	data[len(data)-5] ^= 0xFF

	var dec bytes.Buffer
	_, err := DecryptStreamV2(&dec, bytes.NewReader(data), password)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestEncryptDecryptStreamV2EmptyData(t *testing.T) {
	password := []byte("v06-empty")
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(nil), password, fastConfig()); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), password); err != nil {
		t.Fatal(err)
	}
	if len(dec.Bytes()) != 0 {
		t.Fatal("expected empty output")
	}
}

func TestDecryptAutoDetectsV2(t *testing.T) {
	plaintext := []byte("auto-detect v0x06")
	password := []byte("autodetect")

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, fastConfig()); err != nil {
		t.Fatal(err)
	}

	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(enc.Bytes()), password); err != nil {
		t.Fatalf("Decrypt auto-detect: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("data mismatch")
	}
}

func TestReadStreamMetaWithPasswordV2(t *testing.T) {
	modTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	meta := &FileMeta{
		Name:    "with-pwd.bin",
		Size:    99,
		ModTime: modTime,
	}
	cfg := fastConfig()
	cfg.FileMeta = meta

	plaintext := []byte("data")
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), []byte("pwd"), cfg); err != nil {
		t.Fatal(err)
	}

	// ReadStreamMeta without password must return ErrEncryptedMeta
	src1, _ := io.ReadAll(bytes.NewReader(enc.Bytes()))
	if _, err := ReadStreamMeta(bytes.NewReader(src1)); !errors.Is(err, ErrEncryptedMeta) {
		t.Fatalf("expected ErrEncryptedMeta, got %v", err)
	}

	// ReadStreamMetaWithPassword recovers the metadata
	got, err := ReadStreamMetaWithPassword(bytes.NewReader(src1), []byte("pwd"))
	if err != nil {
		t.Fatalf("ReadStreamMetaWithPassword: %v", err)
	}
	if got == nil || got.Name != meta.Name {
		t.Fatalf("expected meta, got %+v", got)
	}
}
