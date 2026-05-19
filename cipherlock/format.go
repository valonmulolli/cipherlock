package cipherlock

import (
	"encoding/binary"
	"errors"
	"io"
)

var magic = [4]byte{'C', 'V', '2', 0}

// ErrInvalidFormat is returned when the input does not contain a valid cipherlock header.
var ErrInvalidFormat = errors.New("cipherlock: invalid file format")
// ErrVersionMismatch is returned when the cipherlock format version is not supported.
var ErrVersionMismatch = errors.New("cipherlock: unsupported version")
// ErrAuthFailed is returned when decryption authentication fails.
// This typically indicates an incorrect password or corrupted data.
var ErrAuthFailed = errors.New("cipherlock: authentication failed")
// ErrChecksumMismatch is returned when the decrypted data's checksum does not match the stored checksum.
var ErrChecksumMismatch = errors.New("cipherlock: checksum mismatch")
// ErrCorrupted is returned when the encrypted data is malformed or incomplete.
var ErrCorrupted = errors.New("cipherlock: corrupted data")
// ErrAtLeastOnePassword is returned when no passwords are provided for multi-key encryption.
var ErrAtLeastOnePassword = errors.New("cipherlock: at least one password required")

const (
	formatVersionV2 byte = 0x02
	formatVersion   byte = 0x03
	nonceSize             = 12
	checksumSize          = 32

	flagChecksum byte = 1 << 0
)

type header struct {
	Magic    [4]byte
	Version  byte
	Flags    byte
	Salt     []byte
	Time     uint32
	Memory   uint32
	Threads  uint8
	KeyLen   uint32
	Nonce    [nonceSize]byte
	Checksum []byte
}

func writeHeader(w io.Writer, salt []byte, nonce []byte, checksum []byte, config *Config) error {
	var err error
	write := func(data any) {
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, data)
	}

	write(magic)
	write(formatVersion)

	var flags byte
	if config.Checksum {
		flags |= flagChecksum
	}
	write(flags)

	write(uint16(len(salt)))
	write(salt)
	write(config.Time)
	write(config.Memory)
	write(config.Threads)
	write(config.KeyLen)
	write(nonce)

	if config.Checksum && checksum != nil {
		write(checksum)
	}

	return err
}

func readHeader(r io.Reader) (header, error) {
	var h header

	if err := binary.Read(r, binary.LittleEndian, &h.Magic); err != nil {
		return h, ErrInvalidFormat
	}
	if h.Magic != magic {
		return h, ErrInvalidFormat
	}

	if err := binary.Read(r, binary.LittleEndian, &h.Version); err != nil {
		return h, ErrInvalidFormat
	}

	switch h.Version {
	case formatVersion: // 0x03 with flags byte
		if err := binary.Read(r, binary.LittleEndian, &h.Flags); err != nil {
			return h, ErrInvalidFormat
		}
	case formatVersionV2: // 0x02 without flags byte
		h.Flags = 0
	default:
		return h, ErrVersionMismatch
	}

	var saltLen uint16
	if err := binary.Read(r, binary.LittleEndian, &saltLen); err != nil {
		return h, ErrInvalidFormat
	}

	h.Salt = make([]byte, saltLen)
	if _, err := io.ReadFull(r, h.Salt); err != nil {
		return h, ErrInvalidFormat
	}

	if err := binary.Read(r, binary.LittleEndian, &h.Time); err != nil {
		return h, ErrInvalidFormat
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Memory); err != nil {
		return h, ErrInvalidFormat
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Threads); err != nil {
		return h, ErrInvalidFormat
	}
	if err := binary.Read(r, binary.LittleEndian, &h.KeyLen); err != nil {
		return h, ErrInvalidFormat
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Nonce); err != nil {
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
