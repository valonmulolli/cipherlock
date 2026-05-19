package cipherlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
)

const formatVersionStream byte = 0x05

type streamHeader struct {
	Salt      []byte
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	ChunkSize uint32
	Flags     byte
	Checksum  []byte
}

func writeStreamHeader(w io.Writer, password []byte, config *Config) (salt []byte, key []byte, err error) {
	salt = make([]byte, config.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	write(config.Time)
	write(config.Memory)
	write(config.Threads)
	write(config.KeyLen)
	write(uint32(config.ChunkSize))

	return salt, key, err
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

	sh.Salt = make([]byte, saltLen)
	if _, err = io.ReadFull(r, sh.Salt); err != nil {
		return sh, nil, ErrInvalidFormat
	}

	read(&sh.Time)
	read(&sh.Memory)
	read(&sh.Threads)
	read(&sh.KeyLen)
	read(&sh.ChunkSize)
	if err != nil {
		return sh, nil, ErrInvalidFormat
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

func EncryptStream(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
	}

	chunkSize := config.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	var hasher hash.Hash
	if config.Checksum {
		hasher = sha256.New()
	}

	salt, key, err := writeStreamHeader(dst, password, config)
	if err != nil {
		return err
	}
	_ = salt

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

func DecryptStream(dst io.Writer, src io.Reader, password []byte) error {
	var hdrMagic [4]byte
	if _, err := io.ReadFull(src, hdrMagic[:]); err != nil {
		return ErrInvalidFormat
	}
	if hdrMagic != magic {
		return ErrInvalidFormat
	}
	return decryptStream(dst, src, password)
}

func decryptStream(dst io.Writer, src io.Reader, password []byte) error {
	sh, key, err := readStreamHeader(src, password)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var hasher hash.Hash
	if sh.Flags&flagChecksum != 0 {
		hasher = sha256.New()
	}

	for {
		var nonce [nonceSize]byte
		if _, err := io.ReadFull(src, nonce[:]); err != nil {
			return errors.New("cipherlock: unexpected end of stream")
		}

		var ctLen uint32
		if err := binary.Read(src, binary.LittleEndian, &ctLen); err != nil {
			return errors.New("cipherlock: unexpected end of stream")
		}

		if ctLen == 0 {
			break
		}

		ciphertext := make([]byte, ctLen)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return errors.New("cipherlock: corrupted stream data")
		}

		plaintext, decryptErr := aesgcm.Open(nil, nonce[:], ciphertext, nil)
		if decryptErr != nil {
			return errors.New("cipherlock: decryption failed - wrong password or corrupted data")
		}

		if hasher != nil {
			hasher.Write(plaintext)
		}

		if _, err := dst.Write(plaintext); err != nil {
			return err
		}
	}

	if hasher != nil {
		var expected [checksumSize]byte
		if _, err := io.ReadFull(src, expected[:]); err != nil {
			return errors.New("cipherlock: corrupted data - missing checksum")
		}
		actual := hasher.Sum(nil)
		if expected != [32]byte(actual) {
			return errors.New("cipherlock: checksum mismatch - file is corrupted or tampered")
		}
	}

	return nil
}
