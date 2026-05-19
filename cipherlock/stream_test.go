package cipherlock

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecryptStream(t *testing.T) {
	plaintext := []byte("Hello, streaming world!")
	password := []byte("test-password")

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptStreamWrongPassword(t *testing.T) {
	plaintext := []byte("secret data")
	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(plaintext), []byte("correct"), nil)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(&decBuf, bytes.NewReader(buf.Bytes()), []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestEncryptStreamLargeData(t *testing.T) {
	plaintext := make([]byte, 256*1024)
	_, err := io.ReadFull(rand.Reader, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("large-data-test")

	var buf bytes.Buffer
	err = EncryptStream(&buf, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatal("decrypted data does not match original")
	}
}

func TestEncryptStreamSmallChunk(t *testing.T) {
	plaintext := []byte("data for small chunk test")
	password := []byte("small-chunk")

	cfg := &Config{
		SaltLen:   16,
		Time:      1,
		Memory:    64 * 1024,
		Threads:   1,
		KeyLen:    32,
		ChunkSize: 4,
	}

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(plaintext), password, cfg)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptStreamWithChecksum(t *testing.T) {
	plaintext := []byte("data with streaming checksum")
	password := []byte("checksum-pwd")

	cfg := &Config{
		SaltLen:   16,
		Time:      1,
		Memory:    64 * 1024,
		Threads:   1,
		KeyLen:    32,
		ChunkSize: DefaultChunkSize,
		Checksum:  true,
	}

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(plaintext), password, cfg)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestDecryptDetectsStreamFormat(t *testing.T) {
	plaintext := []byte("stream format auto-detect")
	password := []byte("auto-detect")

	var streamBuf bytes.Buffer
	err := EncryptStream(&streamBuf, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = Decrypt(&decBuf, bytes.NewReader(streamBuf.Bytes()), password)
	if err != nil {
		t.Fatalf("Decrypt auto-detect failed: %v", err)
	}

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptStreamEmptyData(t *testing.T) {
	password := []byte("empty-test")

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader([]byte{}), password, nil)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	err = DecryptStream(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if len(decBuf.Bytes()) != 0 {
		t.Fatal("expected empty output")
	}
}
