package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/argon2"
)

// Encrypt encrypts data read from src using password and writes ciphertext to dst.
// It is a convenience wrapper around EncryptStream and always produces the streaming
// format (v0x05). The config parameter controls Argon2 parameters and whether to
// include a checksum. Returns ErrAuthFailed if authentication fails.
func Encrypt(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	return EncryptStream(dst, src, password, config)
}

// Decrypt decrypts data read from src using password and writes plaintext to dst.
// It supports all format versions (v2, v3, v0x04 multi-key, v0x05 stream,
// v0x06 stream with encrypted metadata, v0x07 streaming multi-recipient).
// Returns ErrInvalidFormat, ErrVersionMismatch, ErrAuthFailed, or
// ErrChecksumMismatch on failure. To recover FileMeta attached to a
// v0x06/v0x07 container use DecryptWithMeta.
func Decrypt(dst io.Writer, src io.Reader, password []byte) error {
	_, err := DecryptWithMeta(dst, src, password)
	return err
}

// DecryptWithMeta is the metadata-aware form of Decrypt. The returned
// *FileMeta is non-nil only when the source was encrypted with v0x06 or
// v0x07 and had a FileMeta attached; v0x02 through v0x05 return nil. It
// exists so that downstream code can recover the original filename and
// modification time without an extra ReadStreamMetaWithPassword call.
func DecryptWithMeta(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
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

	// Each per-version decrypt helper consumes a fixed prefix from src. We
	// prepend that prefix back so the helper sees the same byte stream as
	// the original file. prefixFor returns the bytes to prepend for a helper
	// that consumed 1 byte (just the version) or 5 bytes (magic+version).
	prefixFor := func(consumedBytes int) []byte {
		if consumedBytes == 1 {
			return []byte{version}
		}
		return append(hdrMagic[:], version)
	}

	switch version {
	case formatVersionV2, formatVersion:
		// decryptV2V3 calls readHeader which re-reads magic+version.
		combined := io.MultiReader(bytes.NewReader(prefixFor(5)), src)
		return nil, decryptV2V3(dst, combined, password)
	case formatVersionMulti:
		// decryptMulti reads only the version byte.
		multiSrc := io.MultiReader(bytes.NewReader(prefixFor(1)), src)
		return nil, decryptMulti(dst, multiSrc, password)
	case formatVersionStream:
		streamSrc := io.MultiReader(bytes.NewReader(prefixFor(1)), src)
		meta, streamErr := decryptStream(dst, streamSrc, password)
		return meta, streamErr
	case formatVersionStreamV2:
		streamSrc := io.MultiReader(bytes.NewReader(prefixFor(1)), src)
		meta, streamErr := decryptStreamV2(dst, streamSrc, password)
		return meta, streamErr
	case formatVersionStreamMulti:
		// DecryptStreamMultiFromReader re-reads magic+version.
		multiSrc := io.MultiReader(bytes.NewReader(prefixFor(5)), src)
		meta, streamErr := DecryptStreamMultiFromReader(dst, multiSrc, password)
		return meta, streamErr
	default:
		return nil, ErrVersionMismatch
	}
}

// decryptV2V3 handles v0x02 and v0x03 formats.
// NOTE: loads the entire ciphertext into memory (legacy format).
func decryptV2V3(dst io.Writer, src io.Reader, password []byte) error {
	h, err := readHeader(src)
	if err != nil {
		return err
	}

	config := &Config{
		SaltLen:  len(h.Salt),
		Time:     h.Time,
		Memory:   h.Memory,
		Threads:  h.Threads,
		KeyLen:   h.KeyLen,
		Checksum: h.Flags&flagChecksum != 0,
	}

	key := argon2.IDKey(password, h.Salt, config.Time, config.Memory, config.Threads, config.KeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext, err := io.ReadAll(io.LimitReader(src, maxV04Body))
	if err != nil {
		return err
	}

	plaintext, err := aesgcm.Open(nil, h.Nonce[:], ciphertext, nil)
	if err != nil {
		return ErrAuthFailed
	}

	if config.Checksum {
		if h.Checksum == nil || len(h.Checksum) != checksumSize {
			return ErrCorrupted
		}
		actual := sha256.Sum256(plaintext)
		if !bytes.Equal(h.Checksum, actual[:]) {
			return ErrChecksumMismatch
		}
	}

	if _, err := dst.Write(plaintext); err != nil {
		return err
	}

	return nil
}
