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

// ErrEncryptedMeta is returned by ReadStreamMeta when the file uses an encrypted-metadata
// format version (v0x06 or v0x07) and the caller must supply a password to ReadStreamMetaWithPassword.
var ErrEncryptedMeta = errors.New("cipherlock: file metadata is encrypted; password required")

// ErrV05MetaUnsupported is returned by EncryptStream (v0x05) when a
// FileMeta is supplied on the Config. v0x05 stores metadata in the
// cleartext header, which leaks the original filename and modification
// time to anyone holding the blob. Use EncryptStreamV2 (v0x06) when
// metadata is required.
var ErrV05MetaUnsupported = errors.New("cipherlock: EncryptStream (v0x05) cannot attach FileMeta; use EncryptStreamV2")

const (
	formatVersionV2          byte = 0x02
	formatVersionV3          byte = 0x03
	formatVersionMulti       byte = 0x04
	formatVersionStream      byte = 0x05
	formatVersionStreamV2    byte = 0x06
	formatVersionStreamMulti byte = 0x07
	nonceSize                     = 12
	checksumSize                  = 32

	flagChecksum    byte = 1 << 0
	flagHasMetadata byte = 1 << 1
)

// maxSaltLen bounds the salt length accepted in any format header to prevent OOM
// via a maliciously crafted file. 1024 bytes is well beyond what any sane Argon2id
// configuration would use.
const maxSaltLen = 1024

// maxChunkSize bounds the chunk size field accepted in streaming headers. It must
// be large enough to hold a fully-encrypted chunk (plaintext + 16 byte GCM tag)
// for legitimate use cases.
const maxChunkSize = 16 * 1024 * 1024

// maxKeyLen bounds the key length field accepted in any header. AES-256 needs 32
// bytes; anything larger is a malicious or corrupted file.
const maxKeyLen = 64

// maxV04Body bounds the v0x04 ciphertext body. v0x04 is a single-blob format
// with no per-chunk length, so an unbounded read would let a 1KB header claim
// a 100GB body. 1 GiB is well beyond any realistic single-file use case.
const maxV04Body = 1 << 30

// maxMemory bounds the Argon2id Memory parameter accepted from any header.
// 256 MiB matches OWASP's 2024 high-security recommendation; any sane profile
// sits well below this. Without this, a 1KB hostile file can claim
// Memory=0xFFFFFFFF and force a multi-GB allocation when the decrypt path
// runs Argon2id.
const maxMemory = 256 * 1024

// maxTime bounds the Argon2id Time parameter. The OWASP recommendation is
// 3-7 iterations; anything beyond 60 is a hostile or corrupted file.
const maxTime = 60

// maxThreads bounds the Argon2id Threads parameter. Real Argon2id is rarely
// run with more than 8 threads; 32 is a generous upper bound.
const maxThreads uint8 = 32

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
	case formatVersionV3: // 0x03 with flags byte
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
	if saltLen > maxSaltLen {
		return h, ErrCorrupted
	}

	h.Salt = make([]byte, saltLen)
	if _, err := io.ReadFull(r, h.Salt); err != nil {
		return h, ErrInvalidFormat
	}

	if err := binary.Read(r, binary.LittleEndian, &h.Time); err != nil {
		return h, ErrInvalidFormat
	}
	if h.Time == 0 || h.Time > maxTime {
		return h, ErrCorrupted
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Memory); err != nil {
		return h, ErrInvalidFormat
	}
	if h.Memory == 0 || h.Memory > maxMemory {
		return h, ErrCorrupted
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Threads); err != nil {
		return h, ErrInvalidFormat
	}
	if h.Threads == 0 || h.Threads > maxThreads {
		return h, ErrCorrupted
	}
	if err := binary.Read(r, binary.LittleEndian, &h.KeyLen); err != nil {
		return h, ErrInvalidFormat
	}
	if h.KeyLen == 0 || h.KeyLen > maxKeyLen {
		return h, ErrCorrupted
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
