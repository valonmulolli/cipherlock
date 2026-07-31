package cipherlock

import (
	"bytes"
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

// streamV2Header describes the v0x06 single-recipient streaming header. The metadata
// (filename, size, modtime), when present, is stored as the first encrypted chunk so
// it is not visible without the password.
type streamV2Header struct {
	Salt      []byte
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	ChunkSize uint32
	Flags     byte
}

func writeStreamV2Header(w io.Writer, password []byte, config *Config) ([]byte, error) {
	salt := make([]byte, config.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(password, salt, config.Time, config.Memory, config.Threads, config.KeyLen)

	write := func(data any) error {
		return binary.Write(w, binary.LittleEndian, data)
	}

	if err := write(magic); err != nil {
		return nil, err
	}
	if err := write(formatVersionStreamV2); err != nil {
		return nil, err
	}

	var flags byte
	if config.Checksum {
		flags |= flagChecksum
	}
	if config.FileMeta != nil {
		flags |= flagHasMetadata
	}
	if config.Compression {
		flags |= flagCompressed
	}
	if err := write(flags); err != nil {
		return nil, err
	}

	if err := write(uint16(len(salt))); err != nil {
		return nil, err
	}
	if _, err := w.Write(salt); err != nil {
		return nil, err
	}
	if err := write(config.Time); err != nil {
		return nil, err
	}
	if err := write(config.Memory); err != nil {
		return nil, err
	}
	if err := write(config.Threads); err != nil {
		return nil, err
	}
	if err := write(config.KeyLen); err != nil {
		return nil, err
	}
	if err := write(uint32(config.ChunkSize)); err != nil {
		return nil, err
	}

	return key, nil
}

func readStreamV2Header(r io.Reader, password []byte) (streamV2Header, []byte, error) {
	var sh streamV2Header

	read := func(data any) error {
		return binary.Read(r, binary.LittleEndian, data)
	}

	var hdrMagic [4]byte
	if err := read(&hdrMagic); err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if hdrMagic != magic {
		return sh, nil, ErrInvalidFormat
	}

	var version byte
	if err := read(&version); err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if version != formatVersionStreamV2 {
		return sh, nil, ErrVersionMismatch
	}

	if err := read(&sh.Flags); err != nil {
		return sh, nil, ErrInvalidFormat
	}

	salt, time, memory, threads, keyLen, err := readArgon2Params(r)
	if err != nil {
		return sh, nil, err
	}
	sh.Salt = salt
	sh.Time = time
	sh.Memory = memory
	sh.Threads = threads
	sh.KeyLen = keyLen
	if err := read(&sh.ChunkSize); err != nil {
		return sh, nil, ErrInvalidFormat
	}
	if sh.ChunkSize == 0 || sh.ChunkSize > maxChunkSize {
		return sh, nil, ErrCorrupted
	}

	key := argon2.IDKey(password, sh.Salt, sh.Time, sh.Memory, sh.Threads, sh.KeyLen)
	return sh, key, nil
}

// encryptStreamV2Meta writes the optional encrypted metadata chunk for v0x06/v0x07.
// Returns nil if no metadata is provided. The chunk format matches data chunks so the
// streaming decrypt loop can consume it transparently.
func encryptStreamV2Meta(dst io.Writer, aesgcm cipher.AEAD, meta *FileMeta) error {
	if meta == nil {
		return nil
	}
	name := []byte(meta.Name)

	if len(name) > maxMetaNameLen {
		return fmt.Errorf("cipherlock: metadata name too long (%d bytes)", len(name))
	}

	var buf []byte
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(name)))
	buf = append(buf, name...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(meta.Size))
	buf = binary.LittleEndian.AppendUint64(buf, uint64(meta.ModTime.UnixNano()))

	// A zero ExpiresAt (no time gate) must be serialized as 0, not as
	// time.Time{}.UnixNano(), which is a large negative value that would
	// round-trip to a year-1754 timestamp in the past. Gates are always set
	// in the future, so positive UnixNano values unambiguously denote a real
	// expiry and 0 denotes "no expiry" on the read side.
	var expNano int64
	if !meta.ExpiresAt.IsZero() {
		expNano = meta.ExpiresAt.UnixNano()
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(expNano))

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := aesgcm.Seal(nil, nonce, buf, nil)

	if _, err := dst.Write(nonce); err != nil {
		return err
	}
	if err := binary.Write(dst, binary.LittleEndian, uint32(len(ciphertext))); err != nil {
		return err
	}
	if _, err := dst.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

// decryptStreamV2Meta reads the encrypted metadata chunk from r using aesgcm and returns
// the decrypted FileMeta. Returns (nil, nil) when the chunk is empty (no metadata).
func decryptStreamV2Meta(r io.Reader, aesgcm cipher.AEAD) (*FileMeta, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, ErrCorrupted
	}

	var ctLen uint32
	if err := binary.Read(r, binary.LittleEndian, &ctLen); err != nil {
		return nil, ErrCorrupted
	}
	if ctLen == 0 {
		return nil, nil
	}
	// Bound the chunk length: max metadata plaintext is uint16(2)+name(65535)+size(8)+time(8)
	// = 65553, plus 16 bytes GCM tag = 65569. Allow 128KB as a generous upper bound.
	if ctLen > 128*1024 {
		return nil, ErrCorrupted
	}

	ciphertext := make([]byte, ctLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, ErrCorrupted
	}

	plaintext, err := aesgcm.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}

	if len(plaintext) < 2 {
		return nil, ErrCorrupted
	}
	nameLen := int(binary.LittleEndian.Uint16(plaintext[:2]))
	if len(plaintext) < 2+nameLen+8+8+8 { // Size(8) + ModTime(8) + ExpiresAt(8)
		return nil, ErrCorrupted
	}
	name := string(plaintext[2 : 2+nameLen])
	off := 2 + nameLen
	size := int64(binary.LittleEndian.Uint64(plaintext[off : off+8]))
	modNano := int64(binary.LittleEndian.Uint64(plaintext[off+8 : off+16]))

	meta := &FileMeta{
		Name:    name,
		Size:    size,
		ModTime: time.Unix(0, modNano),
	}

	if len(plaintext) >= off+24 {
		expNano := int64(binary.LittleEndian.Uint64(plaintext[off+16 : off+24]))
		// Only positive values denote a real expiry. 0 is the "no gate"
		// sentinel written since the fix, and negative values are the
		// zero-time artifact written by older versions (time.Time{}.UnixNano())
		// that round-tripped to year 1754; both mean "no expiry". Real gates
		// are always set in the future, so their UnixNano is positive.
		if expNano > 0 {
			meta.ExpiresAt = time.Unix(0, expNano)
		}
	}

	return meta, nil
}

// encryptStreamV2 encrypts src in chunks (with optional leading metadata chunk) using
// the v0x06 single-recipient streaming format. The header has already been written to
// dst. hasher, if non-nil, is fed the plaintext and the digest is written as a trailer.
func encryptStreamV2(dst io.Writer, src io.Reader, key []byte, chunkSize int, meta *FileMeta, hasher hash.Hash) error {
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	if err := encryptStreamV2Meta(dst, aesgcm, meta); err != nil {
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

// decryptStreamV2 handles the v0x06 streaming body. The header (including the version
// byte) has already been consumed; r contains the salt, params, chunks, and optional
// checksum trailer. When hasMetadata is set in the header flags, the first chunk is
// decrypted as metadata; otherwise data chunks follow directly. The optional checksum
// is verified when present in the flags.
func decryptStreamV2(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
	return decryptStreamV2Impl(dst, src, password, false)
}

// decryptStreamV2Impl is the shared v0x06 decrypt implementation. When
// enforceExpiry is true it returns ErrExpired right after the authenticated
// metadata chunk is parsed and before any plaintext chunk is written, so an
// expired time-gated file never leaks plaintext to dst. The exported
// DecryptStreamV2 passes false: it is the documented escape hatch for
// recovering the contents of expired files you authored.
func decryptStreamV2Impl(dst io.Writer, src io.Reader, password []byte, enforceExpiry bool) (*FileMeta, error) {
	sh, key, err := readStreamV2Header(src, password)
	if err != nil {
		return nil, err
	}

	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var meta *FileMeta
	if sh.Flags&flagHasMetadata != 0 {
		meta, err = decryptStreamV2Meta(src, aesgcm)
		if err != nil {
			return nil, err
		}
		if enforceExpiry && meta != nil && !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
			return nil, ErrExpired
		}
	}

	var hasher hash.Hash
	if sh.Flags&flagChecksum != 0 {
		hasher = sha256.New()
	}

	var decompress func()
	if sh.Flags&flagCompressed != 0 {
		dst, decompress = decompressWriter(dst)
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
		if !bytes.Equal(expected[:], actual) {
			return nil, ErrChecksumMismatch
		}
	}

	if decompress != nil {
		decompress()
	}

	return meta, nil
}

// EncryptStreamV2 encrypts src using password with the v0x06 streaming format. Unlike
// v0x05, the optional FileMeta is stored as an encrypted chunk so it is not visible
// without the password. Use this when you need streaming encryption and want to keep
// the original filename and size confidential.
//
// It returns a ChunkSize bound error when config.ChunkSize exceeds maxChunkSize.
func EncryptStreamV2(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
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
	if cfg.SaltLen <= 0 {
		cfg.SaltLen = DefaultConfig.SaltLen
	}
	if cfg.KeyLen <= 0 {
		cfg.KeyLen = DefaultConfig.KeyLen
	}

	var hasher hash.Hash
	if config.Checksum {
		hasher = sha256.New()
	}

	if config.Compression {
		src = compressReader(src)
	}

	key, err := writeStreamV2Header(dst, password, config)
	if err != nil {
		return err
	}
	defer clear(key)

	if err := encryptStreamV2(dst, src, key, chunkSize, config.FileMeta, hasher); err != nil {
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

// DecryptStreamV2 decrypts a v0x06 stream-format cipherlock file. The returned FileMeta
// is non-nil only if the source file was encrypted with a FileMeta attached.
//
// It returns ErrInvalidFormat, ErrAuthFailed, ErrCorrupted, or ErrChecksumMismatch.
func DecryptStreamV2(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
	return decryptStreamV2(dst, src, password)
}

// readStreamV2MetaOnly peeks at the v0x06 header to learn chunk size and flags, then
// reads + decrypts the metadata chunk using the supplied password and KDF parameters.
// The version byte has already been consumed by the caller.
func readStreamV2MetaOnly(r io.Reader, password []byte) (*FileMeta, error) {
	// Prepend magic+version; readStreamV2Header expects the full prefix.
	prefix := make([]byte, 0, 5)
	prefix = append(prefix, magic[:]...)
	prefix = append(prefix, formatVersionStreamV2)
	sh, key, err := readStreamV2Header(
		io.MultiReader(bytes.NewReader(prefix), r),
		password,
	)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if sh.Flags&flagHasMetadata == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return decryptStreamV2Meta(r, aesgcm)
}
