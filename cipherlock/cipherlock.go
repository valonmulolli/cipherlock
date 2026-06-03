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
// ErrChecksumMismatch on failure.
func Decrypt(dst io.Writer, src io.Reader, password []byte) error {
	var hdrMagic [4]byte
	if _, err := io.ReadFull(src, hdrMagic[:]); err != nil {
		return ErrInvalidFormat
	}
	if hdrMagic != magic {
		return ErrInvalidFormat
	}

	var version byte
	if err := binary.Read(src, binary.LittleEndian, &version); err != nil {
		return ErrInvalidFormat
	}

	switch version {
	case formatVersionV2, formatVersion:
		combined := io.MultiReader(bytes.NewReader(append(hdrMagic[:], version)), src)
		return decryptV2V3(dst, combined, password)
	case formatVersionMulti:
		multiSrc := io.MultiReader(bytes.NewReader([]byte{version}), src)
		return decryptMulti(dst, multiSrc, password)
	case formatVersionStream:
		streamSrc := io.MultiReader(bytes.NewReader([]byte{version}), src)
		_, streamErr := decryptStream(dst, streamSrc, password)
		return streamErr
	case formatVersionStreamV2:
		streamSrc := io.MultiReader(bytes.NewReader([]byte{version}), src)
		_, streamErr := decryptStreamV2(dst, streamSrc, password)
		return streamErr
	case formatVersionStreamMulti:
		multiSrc := io.MultiReader(bytes.NewReader(append(hdrMagic[:], version)), src)
		_, streamErr := DecryptStreamMultiFromReader(dst, multiSrc, password)
		return streamErr
	default:
		return ErrVersionMismatch
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

	ciphertext, err := io.ReadAll(src)
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
