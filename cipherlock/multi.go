package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/argon2"
)

const formatVersionMulti byte = 0x04

type recipientEntry struct {
	Salt        []byte
	Time        uint32
	Memory      uint32
	Threads     uint8
	KeyLen      uint32
	KeyNonce    [nonceSize]byte
	SealedKey   []byte
}

type multiHeader struct {
	Flags       byte
	Recipients  []recipientEntry
	FileNonce   [nonceSize]byte
	Checksum    []byte
}

func writeMultiHeader(w io.Writer, entries []recipientEntry, fileNonce []byte, checksum []byte, flags byte) error {
	write := func(data any) error {
		return binary.Write(w, binary.LittleEndian, data)
	}

	if err := write(magic); err != nil {
		return err
	}
	if err := write(formatVersionMulti); err != nil {
		return err
	}
	if err := write(flags); err != nil {
		return err
	}
	if err := write(uint32(len(entries))); err != nil {
		return err
	}

	for _, e := range entries {
		if err := write(uint16(len(e.Salt))); err != nil {
			return err
		}
		if _, err := w.Write(e.Salt); err != nil {
			return err
		}
		if err := write(e.Time); err != nil {
			return err
		}
		if err := write(e.Memory); err != nil {
			return err
		}
		if err := write(e.Threads); err != nil {
			return err
		}
		if err := write(e.KeyLen); err != nil {
			return err
		}
		if _, err := w.Write(e.KeyNonce[:]); err != nil {
			return err
		}
		if err := write(uint16(len(e.SealedKey))); err != nil {
			return err
		}
		if _, err := w.Write(e.SealedKey); err != nil {
			return err
		}
	}

	if _, err := w.Write(fileNonce); err != nil {
		return err
	}

	if checksum != nil {
		if _, err := w.Write(checksum); err != nil {
			return err
		}
	}

	return nil
}

func readMultiHeader(r io.Reader) (multiHeader, error) {
	var h multiHeader

	read := func(data any) error {
		return binary.Read(r, binary.LittleEndian, data)
	}

	var version byte
	if err := read(&version); err != nil {
		return h, ErrInvalidFormat
	}
	if version != formatVersionMulti {
		return h, ErrVersionMismatch
	}

	if err := read(&h.Flags); err != nil {
		return h, ErrInvalidFormat
	}

	var numRecipients uint32
	if err := read(&numRecipients); err != nil {
		return h, ErrInvalidFormat
	}

	h.Recipients = make([]recipientEntry, numRecipients)
	for i := range h.Recipients {
		e := &h.Recipients[i]

		var saltLen uint16
		if err := read(&saltLen); err != nil {
			return h, ErrInvalidFormat
		}
		e.Salt = make([]byte, saltLen)
		if _, err := io.ReadFull(r, e.Salt); err != nil {
			return h, ErrInvalidFormat
		}

		if err := read(&e.Time); err != nil {
			return h, ErrInvalidFormat
		}
		if err := read(&e.Memory); err != nil {
			return h, ErrInvalidFormat
		}
		if err := read(&e.Threads); err != nil {
			return h, ErrInvalidFormat
		}
		if err := read(&e.KeyLen); err != nil {
			return h, ErrInvalidFormat
		}
		if _, err := io.ReadFull(r, e.KeyNonce[:]); err != nil {
			return h, ErrInvalidFormat
		}

		var keyLen uint16
		if err := read(&keyLen); err != nil {
			return h, ErrInvalidFormat
		}
		e.SealedKey = make([]byte, keyLen)
		if _, err := io.ReadFull(r, e.SealedKey); err != nil {
			return h, ErrInvalidFormat
		}
	}

	if _, err := io.ReadFull(r, h.FileNonce[:]); err != nil {
		return h, ErrInvalidFormat
	}

	if h.Flags&flagChecksum != 0 {
		h.Checksum = make([]byte, checksumSize)
		if _, err := io.ReadFull(r, h.Checksum); err != nil {
			return h, ErrInvalidFormat
		}
	}

	return h, nil
}

// EncryptMulti encrypts data using multiple passwords, each of which can decrypt independently.
// It generates a random file key, seals it under each password, and stores all recipient entries
// in the header. Returns ErrAtLeastOnePassword if no passwords are provided.
func EncryptMulti(dst io.Writer, src io.Reader, passwords [][]byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
	}
	if len(passwords) == 0 {
		return ErrAtLeastOnePassword
	}

	plaintext, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	fileKey := make([]byte, 32)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}

	fileBlock, err := aes.NewCipher(fileKey)
	if err != nil {
		return err
	}
	fileGCM, err := cipher.NewGCM(fileBlock)
	if err != nil {
		return err
	}

	fileNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, fileNonce); err != nil {
		return err
	}

	ciphertext := fileGCM.Seal(nil, fileNonce, plaintext, nil)

	var flags byte
	var checksum []byte
	if config.Checksum {
		h := sha256.Sum256(plaintext)
		checksum = h[:]
		flags |= flagChecksum
	}

	entries := make([]recipientEntry, len(passwords))
	for i, pwd := range passwords {
		salt := make([]byte, config.SaltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return err
		}

		key := argon2.IDKey(pwd, salt, config.Time, config.Memory, config.Threads, config.KeyLen)
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}

		keyNonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, keyNonce); err != nil {
			return err
		}

		sealedKey := gcm.Seal(nil, keyNonce, fileKey, nil)

		entries[i] = recipientEntry{
			Salt:      salt,
			Time:      config.Time,
			Memory:    config.Memory,
			Threads:   config.Threads,
			KeyLen:    config.KeyLen,
			KeyNonce:  [nonceSize]byte(keyNonce),
			SealedKey: sealedKey,
		}
	}

	if err := writeMultiHeader(dst, entries, fileNonce, checksum, flags); err != nil {
		return err
	}

	_, err = dst.Write(ciphertext)
	return err
}

func decryptMulti(dst io.Writer, remaining io.Reader, password []byte) error {
	h, err := readMultiHeader(remaining)
	if err != nil {
		return err
	}

	var fileKey []byte
	for _, entry := range h.Recipients {
		key := argon2.IDKey(password, entry.Salt, entry.Time, entry.Memory, entry.Threads, entry.KeyLen)
		block, aesErr := aes.NewCipher(key)
		if aesErr != nil {
			continue
		}
		gcm, aesErr := cipher.NewGCM(block)
		if aesErr != nil {
			continue
		}

		decrypted, aesErr := gcm.Open(nil, entry.KeyNonce[:], entry.SealedKey, nil)
		if aesErr != nil {
			continue
		}
		fileKey = decrypted
		break
	}

	if fileKey == nil {
		return ErrAuthFailed
	}

	ciphertext, err := io.ReadAll(remaining)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, h.FileNonce[:], ciphertext, nil)
	if err != nil {
		return ErrAuthFailed
	}

	if h.Flags&flagChecksum != 0 {
		if len(h.Checksum) != checksumSize {
			return ErrCorrupted
		}
		actual := sha256.Sum256(plaintext)
		if !bytes.Equal(h.Checksum, actual[:]) {
			return ErrChecksumMismatch
		}
	}

	_, err = dst.Write(plaintext)
	return err
}
