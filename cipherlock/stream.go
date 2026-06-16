package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

const maxMetaNameLen = 4096

type streamHeader struct {
	Salt      []byte
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	ChunkSize uint32
	Flags     byte
	Checksum  []byte
	FileMeta  *FileMeta
}

func writeStreamHeader(w io.Writer, password []byte, config *Config) (key []byte, err error) {
	salt := make([]byte, config.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key = argon2.IDKey(password, salt, config.Time, config.Memory, config.Threads, config.KeyLen)

	write := func(data any) {
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, data)
	}

	write(magic)
	write(formatVersionStream)

	var flags byte
	if config.Checksum {
		flags |= flagChecksum
	}
	write(flags)

	write(uint16(len(salt)))
	_, err = w.Write(salt)
	if err != nil {
		return nil, err
	}
	write(config.Time)
	write(config.Memory)
	write(config.Threads)
	write(config.KeyLen)
	write(uint32(config.ChunkSize))

	if config.FileMeta != nil {
		write(byte(1))
		name := []byte(config.FileMeta.Name)
		write(uint16(len(name)))
		_, err = w.Write(name)
		if err != nil {
			return nil, err
		}
		write(config.FileMeta.Size)
		write(config.FileMeta.ModTime.UnixNano())
	} else {
		write(byte(0))
	}

	return key, err
}

func readStreamHeader(r io.Reader, password []byte) (sh streamHeader, key []byte, err error) {
	read := func(data any) {
		if err != nil {
			return
		}
		err = binary.Read(r, binary.LittleEndian, data)
	}

	var hdrMagic [4]byte
	read(&hdrMagic)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if hdrMagic != magic {
		return sh, nil, ErrInvalidFormat
	}

	var version byte
	read(&version)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if version != formatVersionStream {
		return sh, nil, ErrVersionMismatch
	}

	read(&sh.Flags)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}

	sh.Salt, sh.Time, sh.Memory, sh.Threads, sh.KeyLen, err = readArgon2Params(r)
	if err != nil {
		return sh, nil, err
	}
	read(&sh.ChunkSize)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if sh.ChunkSize == 0 || sh.ChunkSize > maxChunkSize {
		return sh, nil, ErrCorrupted
	}

	var hasMeta byte
	read(&hasMeta)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}

	if hasMeta != 0 {
		var nameLen uint16
		read(&nameLen)
		if err != nil {
			return sh, nil, ErrInvalidFormat
		}
		nameBytes := make([]byte, nameLen)
		if _, err = io.ReadFull(r, nameBytes); err != nil {
			return sh, nil, ErrInvalidFormat
		}

		var size int64
		read(&size)

		var modNano int64
		read(&modNano)
		if err != nil {
			return sh, nil, ErrInvalidFormat
		}

		meta := &FileMeta{
			Name:    string(nameBytes),
			Size:    size,
			ModTime: time.Unix(0, modNano),
		}
		sh.FileMeta = meta
	}

	key = argon2.IDKey(password, sh.Salt, sh.Time, sh.Memory, sh.Threads, sh.KeyLen)
	return sh, key, nil
}

func encryptStream(dst io.Writer, src io.Reader, key []byte, chunkSize int, hasher hash.Hash) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	for {
		n, readErr := io.ReadFull(src, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return readErr
		}

		if n == 0 {
			break
		}

		chunk := buf[:n]
		if hasher != nil {
			hasher.Write(chunk)
		}

		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}

		ciphertext := aesgcm.Seal(nil, nonce, chunk, nil)

		if _, err := dst.Write(nonce); err != nil {
			return err
		}
		if err := binary.Write(dst, binary.LittleEndian, uint32(len(ciphertext))); err != nil {
			return err
		}
		if _, err := dst.Write(ciphertext); err != nil {
			return err
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	endNonce := make([]byte, nonceSize)
	if _, err := dst.Write(endNonce); err != nil {
		return err
	}
	if err := binary.Write(dst, binary.LittleEndian, uint32(0)); err != nil {
		return err
	}

	return nil
}

// EncryptStream encrypts src using password with a streaming (chunked) format.
// It supports large data sizes by processing data in chunks. The config controls Argon2
// parameters, chunk size, checksumming, and optional FileMeta.
//
// When config.FileMeta is set, EncryptStream automatically produces the v0x06 format
// (encrypted metadata chunk) instead of v0x05 (cleartext metadata). This avoids leaking
// the original filename, size, or modification time in the header.
//
// It returns a ChunkSize bound error when config.ChunkSize exceeds maxChunkSize.
func EncryptStream(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
	}

	if config.FileMeta != nil {
		return EncryptStreamV2(dst, src, password, config)
	}

	// Take a local copy so we never mutate the caller's config (or the shared
	// DefaultConfig) under concurrent use.
	cfg := *config
	config = &cfg

	chunkSize := cfg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > maxChunkSize {
		return fmt.Errorf("cipherlock: ChunkSize %d exceeds maxChunkSize %d", chunkSize, maxChunkSize)
	}
	cfg.ChunkSize = chunkSize
	if cfg.SaltLen <= 0 {
		cfg.SaltLen = DefaultConfig.SaltLen
	}
	if cfg.KeyLen <= 0 {
		cfg.KeyLen = DefaultConfig.KeyLen
	}

	var hasher hash.Hash
	if config.Checksum {
		hasher = sha256.New()
	}

	key, err := writeStreamHeader(dst, password, config)
	if err != nil {
		return err
	}
	defer clear(key)

	if err := encryptStream(dst, src, key, chunkSize, hasher); err != nil {
		return err
	}

	if config.Checksum && hasher != nil {
		checksum := hasher.Sum(nil)
		if _, err := dst.Write(checksum); err != nil {
			return err
		}
	}

	return nil
}

// DecryptStream decrypts a stream-format cipherlock file from src and writes plaintext to dst.
// It is a convenience wrapper around DecryptStreamMeta that discards the FileMeta.
//
// It returns ErrInvalidFormat if src does not start with the cipherlock magic,
// ErrVersionMismatch for an unrecognized version, ErrAuthFailed on wrong
// password or tampered ciphertext, or ErrChecksumMismatch if the embedded
// checksum does not match.
func DecryptStream(dst io.Writer, src io.Reader, password []byte) error {
	_, err := DecryptStreamMeta(dst, src, password)
	return err
}

// ReadStreamMeta reads the FileMeta from a stream-format cipherlock header without decrypting
// the data. Returns nil if the file is not in stream format or has no metadata. For files
// that use the v0x06 or v0x07 format (which store metadata as an encrypted chunk) it
// returns ErrEncryptedMeta; callers should use ReadStreamMetaWithPassword in that case.
func ReadStreamMeta(src io.Reader) (*FileMeta, error) {
	var hdrMagic [4]byte
	if _, err := io.ReadFull(src, hdrMagic[:]); err != nil {
		return nil, ErrInvalidFormat
	}
	if hdrMagic != magic {
		return nil, ErrInvalidFormat
	}

	var version byte
	if err := binary.Read(src, binary.LittleEndian, &version); err != nil {
		return nil, ErrInvalidFormat
	}
	switch version {
	case formatVersionStreamV2, formatVersionStreamMulti:
		return nil, ErrEncryptedMeta
	case formatVersionStream:
		return readStreamV05Body(src)
	default:
		return nil, nil
	}
}

// ReadStreamMetaWithPassword reads the FileMeta from any stream-format cipherlock header
// (v0x05, v0x06, v0x07) by supplying a password. For v0x05 files the password is unused
// and the metadata is read in cleartext. For v0x06 / v0x07 files the password and KDF
// are required to unseal the metadata chunk. Returns ErrAuthFailed if the password
// does not unlock a v0x06 or v0x07 file. Returns nil (no error) if the file has no
// metadata attached.
func ReadStreamMetaWithPassword(src io.Reader, password []byte) (*FileMeta, error) {
	var hdrMagic [4]byte
	if _, err := io.ReadFull(src, hdrMagic[:]); err != nil {
		return nil, ErrInvalidFormat
	}
	if hdrMagic != magic {
		return nil, ErrInvalidFormat
	}

	var version byte
	if err := binary.Read(src, binary.LittleEndian, &version); err != nil {
		return nil, ErrInvalidFormat
	}

	switch version {
	case formatVersionStream:
		return readStreamV05Body(src)
	case formatVersionStreamV2:
		return readStreamV2MetaOnly(src, password)
	case formatVersionStreamMulti:
		return readStreamMultiMeta(src, password)
	default:
		return nil, nil
	}
}

// readStreamV05Body parses the cleartext metadata fields from a v0x05 header body.
// The version byte has already been consumed; src starts at the flags byte.
func readStreamV05Body(src io.Reader) (*FileMeta, error) {
	if _, err := io.CopyN(io.Discard, src, 1); err != nil {
		return nil, ErrInvalidFormat
	}
	var saltLen uint16
	if err := binary.Read(src, binary.LittleEndian, &saltLen); err != nil {
		return nil, ErrInvalidFormat
	}
	if saltLen > maxSaltLen {
		return nil, ErrCorrupted
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(src, salt); err != nil {
		return nil, ErrInvalidFormat
	}
	if _, err := io.CopyN(io.Discard, src, 17); err != nil {
		return nil, ErrInvalidFormat
	}
	var hasMeta byte
	if err := binary.Read(src, binary.LittleEndian, &hasMeta); err != nil {
		return nil, ErrInvalidFormat
	}
	if hasMeta == 0 {
		return nil, nil
	}
	var nameLen uint16
	if err := binary.Read(src, binary.LittleEndian, &nameLen); err != nil {
		return nil, ErrInvalidFormat
	}
	if nameLen > maxMetaNameLen {
		return nil, ErrCorrupted
	}
	nameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(src, nameBytes); err != nil {
		return nil, ErrInvalidFormat
	}
	var size int64
	if err := binary.Read(src, binary.LittleEndian, &size); err != nil {
		return nil, ErrInvalidFormat
	}
	var modNano int64
	if err := binary.Read(src, binary.LittleEndian, &modNano); err != nil {
		return nil, ErrInvalidFormat
	}
	return &FileMeta{
		Name:    string(nameBytes),
		Size:    size,
		ModTime: time.Unix(0, modNano),
	}, nil
}

// DecryptStreamMeta decrypts a stream-format cipherlock file (v0x05, v0x06, or
// v0x07) and returns the FileMeta attached at encrypt time. The plaintext is
// streamed to dst. The returned *FileMeta is nil if the source had no metadata.
//
// Deprecated: DecryptStreamMeta is identical to DecryptWithMeta. Prefer
// DecryptWithMeta.
//
// It returns ErrInvalidFormat, ErrVersionMismatch, ErrAuthFailed, or
// ErrChecksumMismatch on failure.
func DecryptStreamMeta(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
	return DecryptWithMeta(dst, src, password)
}

func decryptStream(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
	sh, key, err := readStreamHeader(src, password)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash
	if sh.Flags&flagChecksum != 0 {
		hasher = sha256.New()
	}

	for {
		var nonce [nonceSize]byte
		if _, err := io.ReadFull(src, nonce[:]); err != nil {
			return nil, ErrCorrupted
		}

		var ctLen uint32
		if err := binary.Read(src, binary.LittleEndian, &ctLen); err != nil {
			return nil, ErrCorrupted
		}

		if ctLen > uint32(sh.ChunkSize)+16 {
			return nil, ErrCorrupted
		}

		if ctLen == 0 {
			break
		}

		ciphertext := make([]byte, ctLen)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return nil, ErrCorrupted
		}

		plaintext, decryptErr := aesgcm.Open(nil, nonce[:], ciphertext, nil)
		if decryptErr != nil {
			return nil, ErrAuthFailed
		}

		if hasher != nil {
			hasher.Write(plaintext)
		}

		if _, err := dst.Write(plaintext); err != nil {
			return nil, err
		}
	}

	if hasher != nil {
		var expected [checksumSize]byte
		if _, err := io.ReadFull(src, expected[:]); err != nil {
			return nil, ErrCorrupted
		}
		actual := hasher.Sum(nil)
		if !bytes.Equal(expected[:], actual) {
			return nil, ErrChecksumMismatch
		}
	}

	return sh.FileMeta, nil
}
