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

// ErrConfigInvalid is returned when Config.Validate() detects invalid parameters.
var ErrConfigInvalid = errors.New("cipherlock: invalid configuration")

// ErrUnsupportedIdentity is returned when an asymmetric identity type is not recognized.
var ErrUnsupportedIdentity = errors.New("cipherlock: unsupported identity type")

// ErrIdentityNeedsPassphrase is returned when attempting to deserialize an
// encrypted identity without providing a passphrase.
var ErrIdentityNeedsPassphrase = errors.New("cipherlock: identity is encrypted, provide a passphrase")

const (
	formatVersionV2          byte = 0x02
	formatVersionV3          byte = 0x03
	formatVersionMulti       byte = 0x04
	formatVersionStream      byte = 0x05
	formatVersionStreamV2    byte = 0x06
	formatVersionStreamMulti byte = 0x07
	formatVersionAsymmetric  byte = 0x08
	identityTypeX25519       byte = 0x01
	nonceSize                     = 12
	checksumSize                  = 32
	x25519PublicKeySize           = 32
	x25519PrivateKeySize          = 32
	sealedKeySize                 = 32 + 16 // 32-byte key + 16-byte GCM tag

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

// maxAsymmetricRecipients bounds the number of asymmetric recipients in a v0x08
// header. Each recipient adds ~80 bytes of overhead; 64 keeps headers well under 8KB.
const maxAsymmetricRecipients = 64

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

// readArgon2Params reads the common Argon2id parameter set shared across all
// symmetric encryption formats: salt length + salt, time, memory, threads,
// and key length. Each field is validated against defensive upper bounds to
// prevent resource-exhaustion attacks.
func readArgon2Params(r io.Reader) (salt []byte, time uint32, memory uint32, threads uint8, keyLen uint32, err error) {
	var saltLen uint16
	if err := binary.Read(r, binary.LittleEndian, &saltLen); err != nil {
		return nil, 0, 0, 0, 0, ErrInvalidFormat
	}
	if saltLen > maxSaltLen {
		return nil, 0, 0, 0, 0, ErrCorrupted
	}
	salt = make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, 0, 0, 0, 0, ErrInvalidFormat
	}
	if err := binary.Read(r, binary.LittleEndian, &time); err != nil {
		return nil, 0, 0, 0, 0, ErrInvalidFormat
	}
	if time == 0 || time > maxTime {
		return nil, 0, 0, 0, 0, ErrCorrupted
	}
	if err := binary.Read(r, binary.LittleEndian, &memory); err != nil {
		return nil, 0, 0, 0, 0, ErrInvalidFormat
	}
	if memory == 0 || memory > maxMemory {
		return nil, 0, 0, 0, 0, ErrCorrupted
	}
	if err := binary.Read(r, binary.LittleEndian, &threads); err != nil {
		return nil, 0, 0, 0, 0, ErrInvalidFormat
	}
	if threads == 0 || threads > maxThreads {
		return nil, 0, 0, 0, 0, ErrCorrupted
	}
	if err := binary.Read(r, binary.LittleEndian, &keyLen); err != nil {
		return nil, 0, 0, 0, 0, ErrInvalidFormat
	}
	if keyLen == 0 || keyLen > maxKeyLen {
		return nil, 0, 0, 0, 0, ErrCorrupted
	}
	return salt, time, memory, threads, keyLen, nil
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

	var err error
	h.Salt, h.Time, h.Memory, h.Threads, h.KeyLen, err = readArgon2Params(r)
	if err != nil {
		return h, err
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
