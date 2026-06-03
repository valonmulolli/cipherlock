package cipherlock

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"
)

func TestEncryptDecryptStreamMultiRoundTrip(t *testing.T) {
	plaintext := []byte("v0x07 streaming multi-recipient")
	passwords := [][]byte{[]byte("alice"), []byte("bob"), []byte("charlie")}

	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, fastConfig()); err != nil {
		t.Fatalf("EncryptStreamMulti: %v", err)
	}

	for _, pwd := range passwords {
		var dec bytes.Buffer
		meta, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), pwd)
		if err != nil {
			t.Fatalf("decrypt with %q: %v", string(pwd), err)
		}
		if meta != nil {
			t.Errorf("expected nil meta for %q, got %+v", string(pwd), meta)
		}
		if !bytes.Equal(dec.Bytes(), plaintext) {
			t.Errorf("decrypt with %q: data mismatch", string(pwd))
		}
	}
}

func TestEncryptDecryptStreamMultiWithMeta(t *testing.T) {
	plaintext := []byte("v0x07 with metadata")
	passwords := [][]byte{[]byte("a"), []byte("b")}

	meta := &FileMeta{
		Name:    "secret.bin",
		Size:    int64(len(plaintext)),
		ModTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	cfg := fastConfig()
	cfg.FileMeta = meta

	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, cfg); err != nil {
		t.Fatal(err)
	}

	// Filename must not be visible in cleartext
	if bytes.Contains(enc.Bytes(), []byte("secret.bin")) {
		t.Fatal("filename leaked in cleartext in v0x07")
	}

	for _, pwd := range passwords {
		var dec bytes.Buffer
		got, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), pwd)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got == nil || got.Name != meta.Name {
			t.Fatalf("decrypt: expected meta, got %+v", got)
		}
		if !bytes.Equal(dec.Bytes(), plaintext) {
			t.Fatal("data mismatch")
		}
	}
}

func TestEncryptDecryptStreamMultiWrongPassword(t *testing.T) {
	plaintext := []byte("data")
	passwords := [][]byte{[]byte("alice"), []byte("bob")}
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, fastConfig()); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	_, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), []byte("eve"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestEncryptDecryptStreamMultiNoPasswords(t *testing.T) {
	var enc bytes.Buffer
	err := EncryptStreamMulti(&enc, bytes.NewReader([]byte("x")), nil, fastConfig())
	if !errors.Is(err, ErrAtLeastOnePassword) {
		t.Fatalf("expected ErrAtLeastOnePassword, got %v", err)
	}
}

func TestEncryptDecryptStreamMultiLargeData(t *testing.T) {
	plaintext := make([]byte, 512*1024+17)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatal(err)
	}
	passwords := [][]byte{[]byte("p1"), []byte("p2")}

	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, fastConfig()); err != nil {
		t.Fatal(err)
	}

	var dec bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), []byte("p2")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("large v0x07 round-trip mismatch")
	}
}

func TestEncryptDecryptStreamMultiWithChecksum(t *testing.T) {
	plaintext := []byte("v0x07 with checksum")
	passwords := [][]byte{[]byte("a"), []byte("b")}
	cfg := fastConfig()
	cfg.Checksum = true

	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, cfg); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), []byte("a")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("data mismatch")
	}
}

func TestEncryptDecryptStreamMultiChecksumCorrupted(t *testing.T) {
	plaintext := []byte("v0x07 checksum tamper")
	passwords := [][]byte{[]byte("a"), []byte("b")}
	cfg := fastConfig()
	cfg.Checksum = true

	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, cfg); err != nil {
		t.Fatal(err)
	}
	data := enc.Bytes()
	data[len(data)-5] ^= 0xFF

	var dec bytes.Buffer
	_, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(data), []byte("a"))
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestEncryptDecryptStreamMultiEmptyData(t *testing.T) {
	passwords := [][]byte{[]byte("a"), []byte("b")}
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(nil), passwords, fastConfig()); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if _, err := DecryptStreamMultiFromReader(&dec, bytes.NewReader(enc.Bytes()), []byte("a")); err != nil {
		t.Fatal(err)
	}
	if len(dec.Bytes()) != 0 {
		t.Fatal("expected empty output")
	}
}

func TestDecryptAutoDetectsStreamMulti(t *testing.T) {
	plaintext := []byte("auto-detect v0x07")
	passwords := [][]byte{[]byte("a")}

	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, fastConfig()); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(enc.Bytes()), []byte("a")); err != nil {
		t.Fatalf("Decrypt auto-detect: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("data mismatch")
	}
}

func TestReadStreamMetaWithPasswordMulti(t *testing.T) {
	meta := &FileMeta{
		Name:    "multi-meta.bin",
		Size:    42,
		ModTime: time.Date(2026, 5, 5, 5, 5, 5, 0, time.UTC),
	}
	cfg := fastConfig()
	cfg.FileMeta = meta
	passwords := [][]byte{[]byte("a"), []byte("b")}

	plaintext := []byte("data")
	var enc bytes.Buffer
	if err := EncryptStreamMulti(&enc, bytes.NewReader(plaintext), passwords, cfg); err != nil {
		t.Fatal(err)
	}

	// ReadStreamMeta without password must return ErrEncryptedMeta
	if _, err := ReadStreamMeta(bytes.NewReader(enc.Bytes())); !errors.Is(err, ErrEncryptedMeta) {
		t.Fatalf("expected ErrEncryptedMeta, got %v", err)
	}

	// ReadStreamMetaWithPassword with a valid password works
	got, err := ReadStreamMetaWithPassword(bytes.NewReader(enc.Bytes()), []byte("a"))
	if err != nil {
		t.Fatalf("ReadStreamMetaWithPassword: %v", err)
	}
	if got == nil || got.Name != meta.Name {
		t.Fatalf("expected meta, got %+v", got)
	}

	// Wrong password fails
	if _, err := ReadStreamMetaWithPassword(bytes.NewReader(enc.Bytes()), []byte("wrong")); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestReKeyStreamV2(t *testing.T) {
	oldPwd := []byte("old-pwd")
	newPwd := []byte("new-pwd")
	plaintext := []byte("rekey v0x06 test data")

	var encrypted bytes.Buffer
	if err := EncryptStreamV2(&encrypted, bytes.NewReader(plaintext), oldPwd, fastConfig()); err != nil {
		t.Fatal(err)
	}

	var rekeyed bytes.Buffer
	if err := ReKey(&rekeyed, &encrypted, oldPwd, newPwd, nil); err != nil {
		t.Fatalf("ReKey: %v", err)
	}

	var dec bytes.Buffer
	if err := Decrypt(&dec, &rekeyed, newPwd); err != nil {
		t.Fatalf("Decrypt after rekey: %v", err)
	}
	if !bytes.Equal(plaintext, dec.Bytes()) {
		t.Fatal("rekey round-trip mismatch")
	}
}

func TestReKeyStreamMulti(t *testing.T) {
	oldPwd := []byte("old-pwd")
	newPwd := []byte("new-pwd")
	plaintext := []byte("rekey v0x07 test data")

	var encrypted bytes.Buffer
	if err := EncryptStreamMulti(&encrypted, bytes.NewReader(plaintext), [][]byte{oldPwd, []byte("other")}, fastConfig()); err != nil {
		t.Fatal(err)
	}

	var rekeyed bytes.Buffer
	if err := ReKey(&rekeyed, &encrypted, oldPwd, newPwd, nil); err != nil {
		t.Fatalf("ReKey: %v", err)
	}

	var dec bytes.Buffer
	if err := Decrypt(&dec, &rekeyed, newPwd); err != nil {
		t.Fatalf("Decrypt after rekey: %v", err)
	}
	if !bytes.Equal(plaintext, dec.Bytes()) {
		t.Fatal("rekey round-trip mismatch")
	}
}

func TestReKeyStreamV2WrongOldPassword(t *testing.T) {
	plaintext := []byte("data")
	var encrypted bytes.Buffer
	if err := EncryptStreamV2(&encrypted, bytes.NewReader(plaintext), []byte("right"), fastConfig()); err != nil {
		t.Fatal(err)
	}
	err := ReKey(&bytes.Buffer{}, &encrypted, []byte("wrong"), []byte("new"), nil)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}
