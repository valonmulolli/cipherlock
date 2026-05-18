package cipherlock

import (
	"encoding/binary"
	"errors"
	"io"
)

var magic = [4]byte{'C', 'V', '2', 0}

var ErrInvalidFormat = errors.New("cipherlock: invalid file format")
var ErrVersionMismatch = errors.New("cipherlock: unsupported version")

const formatVersion byte = 0x02
const nonceSize = 12

type header struct {
	Magic   [4]byte
	Version byte
	Salt    []byte
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	Nonce   [nonceSize]byte
}

func writeHeader(w io.Writer, salt []byte, nonce []byte, config *Config) error {
	var err error
	write := func(data any) {
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, data)
	}

	write(magic)
	write(formatVersion)
	write(uint16(len(salt)))
	write(salt)
	write(config.Time)
	write(config.Memory)
	write(config.Threads)
	write(config.KeyLen)
	write(nonce)

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
	if h.Version != formatVersion {
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

	return h, nil
}
