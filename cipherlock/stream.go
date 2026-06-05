package cipherlock

import (
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

	var version byte
	read(&version)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if version != formatVersionStream {
		return sh, nil, ErrVersionMismatch
	}

	read(&sh.Flags)

	var saltLen uint16
	read(&saltLen)
	if err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if saltLen > maxSaltLen {
		return sh, nil, ErrCorrupted
	}

	sh.Salt = make([]byte, saltLen)
	if _, err = io.ReadFull(r, sh.Salt); err != nil {
		return sh, nil, ErrInvalidFormat
	}

	read(&sh.Time)
	if sh.Time == 0 || sh.Time > maxTime {
		return sh, nil, ErrCorrupted
	}
	read(&sh.Memory)
	if sh.Memory == 0 || sh.Memory > maxMemory {
		return sh, nil, ErrCorrupted
	}
	read(&sh.Threads)
	if sh.Threads == 0 || sh.Threads > maxThreads {
		return sh, nil, ErrCorrupted
	}
	read(&sh.KeyLen)
	if sh.KeyLen == 0 || sh.KeyLen > maxKeyLen {
		return sh, nil, ErrCorrupted
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
// parameters, chunk size, and optional checksumming.
func EncryptStream(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
	}

	// v0x05 stores the FileMeta in the cleartext header. That means
	// anyone holding the ciphertext can read the original filename
	// and modification time. If the caller really wants metadata
	// attached, they should use EncryptStreamV2 (v0x06) which
	// encrypts the metadata chunk under the same key as the data.
	if config.FileMeta != nil {
		return ErrV05MetaUnsupported
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

	var hasher hash.Hash
	if config.Checksum {
		hasher = sha256.New()
	}

	key, err := writeStreamHeader(dst, password, config)
	if err != nil {
		return err
	}

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
		// fall through
	default:
		return nil, nil
	}

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

	// Skip Argon2 parameters (Time=4, Memory=4, Threads=1, KeyLen=4, ChunkSize=4)
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
		return readStreamV05Meta(src)
	case formatVersionStreamV2:
		return readStreamV2MetaOnly(src, password)
	case formatVersionStreamMulti:
		return readStreamMultiMeta(src, password)
	default:
		return nil, nil
	}
}

// readStreamV05Meta parses the cleartext metadata fields from a v0x05 header.
// The version byte has already been consumed; src starts at the flags byte.
func readStreamV05Meta(src io.Reader) (*FileMeta, error) {
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
// This is the format-aware counterpart to DecryptWithMeta: it dispatches on
// the version byte the same way, but is named after the legacy v0x05 helper
// it replaced. New code should prefer DecryptWithMeta.
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
		if expected != [32]byte(actual) {
			return nil, ErrChecksumMismatch
		}
	}

	return sh.FileMeta, nil
}
