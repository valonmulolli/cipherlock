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

func TestDecryptFileV1(t *testing.T) {
	password := []byte("v1-test-password")
	plaintext := []byte("this was encrypted with the original format")

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	dk := pbkdf2.Key(password, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		t.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)

	dir := t.TempDir()
	src := filepath.Join(dir, "v1_file.encrypted")
	if err := os.WriteFile(src, ciphertext, 0644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "v1_file")
	if err := DecryptFileV1(src, dest, password); err != nil {
		t.Fatalf("DecryptFileV1: %v", err)
	}

	result, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, result) {
		t.Fatalf("V1 compat mismatch: got %q, want %q", result, plaintext)
	}
}

func TestDecryptFileV1WrongPassword(t *testing.T) {
	password := []byte("correct")
	wrongPassword := []byte("wrong")

	nonce := make([]byte, 12)
	rand.Read(nonce)

	dk := pbkdf2.Key(password, nonce, 4096, 32, sha1.New)
	block, _ := aes.NewCipher(dk)
	aesgcm, _ := cipher.NewGCM(block)
	ciphertext := aesgcm.Seal(nil, nonce, []byte("data"), nil)
	ciphertext = append(ciphertext, nonce...)

	dir := t.TempDir()
	src := filepath.Join(dir, "v1_file")
	if err := os.WriteFile(src, ciphertext, 0644); err != nil {
		t.Fatal(err)
	}

	err := DecryptFileV1(src, "", wrongPassword)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}
