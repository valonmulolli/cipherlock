package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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

func TestEncryptDecryptStreamV2Compression(t *testing.T) {
	plaintext := bytes.Repeat([]byte("compressible data! "), 4096)
	password := []byte("v06-compress")

	cfg := fastConfig()
	cfg.Compression = true

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("EncryptStreamV2 with compression: %v", err)
	}

	// Verify flagCompressed is set in the header
	encBytes := enc.Bytes()
	if len(encBytes) < 7 {
		t.Fatal("encrypted output too short")
	}
	// Magic(4) + version(1) + flags(1) — flags byte is at offset 5.
	// bit 2 should be set.
	if encBytes[5]&flagCompressed == 0 {
		t.Fatal("flagCompressed not set in header")
	}

	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(encBytes), password); err != nil {
		t.Fatalf("DecryptStreamV2 with compression: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("compressed round-trip data mismatch")
	}
}

func TestEncryptDecryptStreamV2CompressionWithMeta(t *testing.T) {
	plaintext := []byte("compressed and metadatad")
	password := []byte("v06-comp-meta")

	cfg := fastConfig()
	cfg.Compression = true
	cfg.FileMeta = &FileMeta{
		Name:    "secret.doc",
		Size:    int64(len(plaintext)),
		ModTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("encrypt with compression+meta: %v", err)
	}

	var dec bytes.Buffer
	meta, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), password)
	if err != nil {
		t.Fatalf("decrypt with compression+meta: %v", err)
	}
	if meta == nil || meta.Name != "secret.doc" {
		t.Fatalf("expected metadata, got %+v", meta)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("data mismatch with compression+meta")
	}
}

func TestEncryptDecryptStreamV2CompressionWithChecksum(t *testing.T) {
	plaintext := []byte("compressed with checksum")
	password := []byte("v06-comp-sum")

	cfg := fastConfig()
	cfg.Compression = true
	cfg.Checksum = true

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("encrypt with compression+checksum: %v", err)
	}

	var dec bytes.Buffer
	if _, err := DecryptStreamV2(&dec, bytes.NewReader(enc.Bytes()), password); err != nil {
		t.Fatalf("decrypt with compression+checksum: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatal("data mismatch with compression+checksum")
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

func encryptV06WithExpiry(t *testing.T, plaintext, password []byte, expiresAt time.Time) []byte {
	t.Helper()
	cfg := fastConfig()
	cfg.FileMeta = &FileMeta{
		Name:      "gated.bin",
		Size:      int64(len(plaintext)),
		ModTime:   time.Now(),
		ExpiresAt: expiresAt,
	}
	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}
	return enc.Bytes()
}

func TestDecryptWithMetaNoExpiry(t *testing.T) {
	// A FileMeta with a zero ExpiresAt must round-trip with a zero
	// ExpiresAt, so DecryptWithMeta does not enforce any gate.
	plaintext := []byte("no gate")
	password := []byte("v06-nogate-pwd")
	cfg := fastConfig()
	cfg.FileMeta = &FileMeta{
		Name:    "plain.txt",
		Size:    int64(len(plaintext)),
		ModTime: time.Now(),
	}

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	var dec bytes.Buffer
	meta, err := DecryptWithMeta(&dec, bytes.NewReader(enc.Bytes()), password)
	if err != nil {
		t.Fatalf("DecryptWithMeta: %v", err)
	}
	if meta == nil {
		t.Fatal("expected FileMeta")
	}
	if !meta.ExpiresAt.IsZero() {
		t.Fatalf("expected zero ExpiresAt, got %s", meta.ExpiresAt)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", dec.Bytes(), plaintext)
	}
}

func TestDecryptWithMetaEnforcesExpiry(t *testing.T) {
	plaintext := []byte("gated content")
	password := []byte("v06-gate-pwd")

	// Future expiry: decrypt succeeds and returns the expiry.
	future := time.Now().Add(24 * time.Hour)
	enc := encryptV06WithExpiry(t, plaintext, password, future)
	var dec bytes.Buffer
	meta, err := DecryptWithMeta(&dec, bytes.NewReader(enc), password)
	if err != nil {
		t.Fatalf("DecryptWithMeta (future expiry): %v", err)
	}
	if meta == nil || !meta.ExpiresAt.Equal(future) {
		t.Fatalf("expected ExpiresAt %s, got %+v", future, meta)
	}

	// Past expiry: decrypt must fail with ErrExpired even though the
	// password is correct and the data authenticates. Because v0x06
	// enforces the gate inside the decrypt loop before any chunk is
	// written, no plaintext may reach the destination.
	past := time.Now().Add(-time.Hour)
	enc = encryptV06WithExpiry(t, plaintext, password, past)
	dec.Reset()
	if _, err := DecryptWithMeta(&dec, bytes.NewReader(enc), password); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if dec.Len() != 0 {
		t.Fatalf("expected no plaintext written on expired file, got %d bytes", dec.Len())
	}
}

func TestDecryptStreamV2DoesNotEnforceExpiry(t *testing.T) {
	// The low-level DecryptStreamV2 entry point only returns metadata and
	// does not enforce the gate; that is the documented escape hatch for
	// recovering the contents of expired files. Decrypt/DecryptWithMeta are
	// the enforced entry points.
	plaintext := []byte("recover me")
	password := []byte("v06-recover-pwd")
	enc := encryptV06WithExpiry(t, plaintext, password, time.Now().Add(-time.Hour))

	var dec bytes.Buffer
	meta, err := DecryptStreamV2(&dec, bytes.NewReader(enc), password)
	if err != nil {
		t.Fatalf("DecryptStreamV2 (escape hatch): %v", err)
	}
	if meta == nil {
		t.Fatal("expected FileMeta")
	}
	if meta.ExpiresAt.IsZero() {
		t.Fatal("expected the past expiry to be surfaced on metadata")
	}
	if time.Now().Before(meta.ExpiresAt) {
		t.Fatalf("expected expiry in the past, got %s", meta.ExpiresAt)
	}
	if !bytes.Equal(dec.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", dec.Bytes(), plaintext)
	}
}

func TestDecryptWithMetaOldZeroTimeArtifact(t *testing.T) {
	// Backwards compatibility: versions before the serialization fix wrote
	// time.Time{}.UnixNano() (a large negative value) for a zero ExpiresAt,
	// which round-tripped to year 1754. decryptStreamV2Meta must treat any
	// non-positive ExpiresAt value as "no gate" so those files keep
	// decrypting with a zero ExpiresAt.

	// Derive a real key from a v0x06 stream so the crafted chunk is
	// authenticated with the same key material the reader expects.
	plaintext := []byte("legacy file")
	password := []byte("v06-legacy-pwd")
	cfg := fastConfig()
	cfg.FileMeta = &FileMeta{Name: "legacy.txt", Size: int64(len(plaintext)), ModTime: time.Now()}

	var enc bytes.Buffer
	if err := EncryptStreamV2(&enc, bytes.NewReader(plaintext), password, cfg); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	sh, key, err := readStreamV2Header(
		io.MultiReader(bytes.NewReader(append(append([]byte{}, magic[:]...), formatVersionStreamV2)), bytes.NewReader(enc.Bytes()[5:])),
		password,
	)
	if err != nil {
		t.Fatalf("readStreamV2Header: %v", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}

	// Build the meta plaintext the old writer produced: name, size,
	// modtime, then time.Time{}.UnixNano() as ExpiresAt.
	legacy := &FileMeta{Name: "legacy.txt", Size: int64(len(plaintext)), ModTime: time.Now()}
	var raw []byte
	raw = binary.LittleEndian.AppendUint16(raw, uint16(len(legacy.Name)))
	raw = append(raw, legacy.Name...)
	raw = binary.LittleEndian.AppendUint64(raw, uint64(legacy.Size))
	raw = binary.LittleEndian.AppendUint64(raw, uint64(legacy.ModTime.UnixNano()))
	raw = binary.LittleEndian.AppendUint64(raw, uint64(time.Time{}.UnixNano())) // legacy artifact

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	ct := gcm.Seal(nil, nonce, raw, nil)
	var chunk bytes.Buffer
	chunk.Write(nonce)
	if err := binary.Write(&chunk, binary.LittleEndian, uint32(len(ct))); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	chunk.Write(ct)

	got, err := decryptStreamV2Meta(&chunk, gcm)
	if err != nil {
		t.Fatalf("decryptStreamV2Meta: %v", err)
	}
	if got == nil || got.Name != "legacy.txt" {
		t.Fatalf("unexpected meta: %+v", got)
	}
	if !got.ExpiresAt.IsZero() {
		t.Fatalf("legacy artifact must decode as zero ExpiresAt, got %+v", got.ExpiresAt)
	}
	_ = sh // header captured for key derivation; keep the variable bound
}
