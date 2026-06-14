package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestDecryptFileV1ShortInput(t *testing.T) {
	dir := t.TempDir()

	// 27 bytes: 12 nonce + 15 body (too short for GCM minimum tag of 16).
	short := make([]byte, 27)
	rand.Read(short)
	src := filepath.Join(dir, "short.bin")
	if err := os.WriteFile(src, short, 0644); err != nil {
		t.Fatal(err)
	}

	err := DecryptFileV1(src, "", []byte("pwd"))
	if err == nil {
		t.Fatal("expected ErrInvalidFormat for short input, got nil")
	}
	if err != ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat, got: %v", err)
	}
}

func TestDecryptFileV1EmptyInput(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(src, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	err := DecryptFileV1(src, "", []byte("pwd"))
	if err == nil {
		t.Fatal("expected ErrInvalidFormat for empty input, got nil")
	}
}

func TestDecryptFileV1Exactly28Bytes(t *testing.T) {
	dir := t.TempDir()

	// 28 bytes is the new minimum (12 nonce + 16 tag, plaintext is empty).
	nonce := make([]byte, 12)
	rand.Read(nonce)

	dk := pbkdf2.Key([]byte("pwd"), nonce, 4096, 32, sha1.New)
	block, _ := aes.NewCipher(dk)
	aesgcm, _ := cipher.NewGCM(block)

	// Encrypt empty plaintext: output is just the GCM tag (16 bytes).
	ciphertext := aesgcm.Seal(nil, nonce, nil, nil)
	ciphertext = append(ciphertext, nonce...)

	if len(ciphertext) != 28 {
		t.Fatalf("expected 28 bytes, got %d", len(ciphertext))
	}

	src := filepath.Join(dir, "exactly28.bin")
	if err := os.WriteFile(src, ciphertext, 0644); err != nil {
		t.Fatal(err)
	}

	// Should succeed (empty plaintext).
	dest := filepath.Join(dir, "out")
	if err := DecryptFileV1(src, dest, []byte("pwd")); err != nil {
		t.Fatalf("expected success for 28-byte V1 file, got: %v", err)
	}
	result, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(result))
	}
}

func TestDecryptFileV1NotV1File(t *testing.T) {
	dir := t.TempDir()

	// A non-V1 file that's exactly 28 bytes but not valid V1 ciphertext.
	notV1 := make([]byte, 28)
	rand.Read(notV1)

	src := filepath.Join(dir, "notv1.bin")
	if err := os.WriteFile(src, notV1, 0644); err != nil {
		t.Fatal(err)
	}

	err := DecryptFileV1(src, "", []byte("pwd"))
	if err == nil {
		t.Fatal("expected error for non-V1 28-byte file")
	}
}

func TestDecryptFileV1RoundTrip(t *testing.T) {
	plaintext := []byte("V1 compatibility round-trip")
	password := []byte("v1-password")

	nonce := make([]byte, 12)
	rand.Read(nonce)

	dk := pbkdf2.Key(password, nonce, 4096, 32, sha1.New)
	block, _ := aes.NewCipher(dk)
	aesgcm, _ := cipher.NewGCM(block)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)

	dir := t.TempDir()
	src := filepath.Join(dir, "v1_roundtrip.encrypted")
	if err := os.WriteFile(src, ciphertext, 0644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "v1_roundtrip")
	if err := DecryptFileV1(src, dest, password); err != nil {
		t.Fatalf("DecryptFileV1: %v", err)
	}

	result, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, result) {
		t.Fatalf("round-trip mismatch: got %q, want %q", result, plaintext)
	}
}
