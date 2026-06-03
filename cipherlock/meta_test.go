package cipherlock

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptStreamWithMeta(t *testing.T) {
	plaintext := []byte("file with metadata")
	password := []byte("meta-pwd")
	modTime := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	meta := &FileMeta{
		Name:    "important.txt",
		Size:    int64(len(plaintext)),
		ModTime: modTime,
	}

	cfg := &Config{
		SaltLen:   16,
		Time:      1,
		Memory:    64 * 1024,
		Threads:   1,
		KeyLen:    32,
		ChunkSize: DefaultChunkSize,
		FileMeta:  meta,
	}

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(plaintext), password, cfg)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	gotMeta, err := DecryptStreamMeta(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStreamMeta failed: %v", err)
	}

	if gotMeta == nil {
		t.Fatal("expected metadata, got nil")
	}
	if gotMeta.Name != meta.Name {
		t.Fatalf("name: got %q, want %q", gotMeta.Name, meta.Name)
	}
	if gotMeta.Size != meta.Size {
		t.Fatalf("size: got %d, want %d", gotMeta.Size, meta.Size)
	}
	if !gotMeta.ModTime.Equal(meta.ModTime) {
		t.Fatalf("modtime: got %v, want %v", gotMeta.ModTime, meta.ModTime)
	}
	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("data: got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptStreamNoMeta(t *testing.T) {
	plaintext := []byte("no metadata")
	password := []byte("no-meta")

	var buf bytes.Buffer
	err := EncryptStream(&buf, bytes.NewReader(plaintext), password, nil)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	var decBuf bytes.Buffer
	gotMeta, err := DecryptStreamMeta(&decBuf, bytes.NewReader(buf.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptStreamMeta failed: %v", err)
	}

	if gotMeta != nil {
		t.Fatalf("expected nil metadata, got %+v", gotMeta)
	}
	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("data: got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestDecryptStreamMetaIgnoresMeta(t *testing.T) {
	plaintext := []byte("Decrypt ignores meta")
	password := []byte("ignore-meta")
	meta := &FileMeta{
		Name:    "test.bin",
		Size:    int64(len(plaintext)),
		ModTime: time.Now(),
	}

	cfg := &Config{
		SaltLen:  16,
		Time:     1,
		Memory:   64 * 1024,
		Threads:  1,
		KeyLen:   32,
		FileMeta: meta,
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
		t.Fatalf("data: got %q, want %q", decBuf.Bytes(), plaintext)
	}
}

func TestEncryptFileRestoresMeta(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "original.txt")
	err := os.WriteFile(src, []byte("file with metadata restoration"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("file-meta")
	encPath := filepath.Join(dir, "file.enc")
	decPath := filepath.Join(dir, "restored.txt")

	err = EncryptFile(src, encPath, password, &Config{
		SaltLen: 16,
		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
		KeyLen:  32,
		FileMeta: &FileMeta{
			Name:    info.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		},
	})
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	err = DecryptFile(encPath, decPath, password)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	restored, err := os.Stat(decPath)
	if err != nil {
		t.Fatal(err)
	}

	if restored.Size() != info.Size() {
		t.Fatalf("size: got %d, want %d", restored.Size(), info.Size())
	}

	data, _ := os.ReadFile(decPath)
	orig, _ := os.ReadFile(src)
	if !bytes.Equal(data, orig) {
		t.Fatal("data mismatch")
	}
}

func TestLargeFileRestore(t *testing.T) {
	src := filepath.Join(t.TempDir(), "large.bin")
	data := make([]byte, 256*1024+1)
	_, _ = io.ReadFull(rand.Reader, data)
	_ = os.WriteFile(src, data, 0644)

	info, _ := os.Stat(src)
	pwd := []byte("large-restore")

	err := EncryptFile(src, src+".enc", pwd, &Config{
		SaltLen: 16, Time: 1, Memory: 64 * 1024, Threads: 1, KeyLen: 32,
		FileMeta: &FileMeta{Name: info.Name(), Size: info.Size(), ModTime: info.ModTime()},
	})
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	err = DecryptFile(src+".enc", src+".dec", pwd)
	if err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	dec, _ := os.ReadFile(src + ".dec")
	if !bytes.Equal(dec, data) {
		t.Fatal("data mismatch")
	}
}
