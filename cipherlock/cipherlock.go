package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

func Encrypt(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
	}

	salt := make([]byte, config.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	key := argon2.IDKey(password, salt, config.Time, config.Memory, config.Threads, config.KeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	var checksum []byte
	if config.Checksum {
		h := sha256.Sum256(plaintext)
		checksum = h[:]
	}

	if err := writeHeader(dst, salt, nonce, checksum, config); err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	if _, err := dst.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

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
	default:
		return ErrVersionMismatch
	}
}

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
		return errors.New("cipherlock: decryption failed - wrong password or corrupted data")
	}

	if config.Checksum {
		if h.Checksum == nil || len(h.Checksum) != checksumSize {
			return errors.New("cipherlock: corrupted data - missing checksum")
		}
		actual := sha256.Sum256(plaintext)
		if !bytes.Equal(h.Checksum, actual[:]) {
			return errors.New("cipherlock: checksum mismatch - file is corrupted or tampered")
		}
	}

	if _, err := dst.Write(plaintext); err != nil {
		return err
	}

	return nil
}
