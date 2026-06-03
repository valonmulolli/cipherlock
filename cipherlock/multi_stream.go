package cipherlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
)

// streamMultiHeader describes the v0x07 multi-recipient streaming header. Each
// recipient entry stores a sealed copy of the file key, which is then used to
// encrypt the metadata chunk (if present) and the data chunks that follow.
type streamMultiHeader struct {
	Flags      byte
	Recipients []recipientEntry
}

// maxRecipients bounds the number of recipient entries accepted in a v0x07 header
// to prevent OOM via a maliciously crafted file. 1024 is generous for any real
// use case (you almost never encrypt for a thousand recipients).
const maxRecipients = 1024

func writeStreamMultiHeader(w io.Writer, entries []recipientEntry, flags byte) error {
	write := func(data any) error {
		return binary.Write(w, binary.LittleEndian, data)
	}

	if err := write(magic); err != nil {
		return err
	}
	if err := write(formatVersionStreamMulti); err != nil {
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

	return nil
}

func readStreamMultiHeader(r io.Reader) (streamMultiHeader, error) {
	var h streamMultiHeader

	read := func(data any) error {
		return binary.Read(r, binary.LittleEndian, data)
	}

	if err := read(&h.Flags); err != nil {
		return h, ErrInvalidFormat
	}

	var numRecipients uint32
	if err := read(&numRecipients); err != nil {
		return h, ErrInvalidFormat
	}
	if numRecipients == 0 {
		return h, ErrCorrupted
	}
	if numRecipients > maxRecipients {
		return h, ErrCorrupted
	}

	h.Recipients = make([]recipientEntry, numRecipients)
	for i := range h.Recipients {
		e := &h.Recipients[i]

		var saltLen uint16
		if err := read(&saltLen); err != nil {
			return h, ErrInvalidFormat
		}
		if saltLen > maxSaltLen {
			return h, ErrCorrupted
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
		if e.KeyLen == 0 || e.KeyLen > maxKeyLen {
			return h, ErrCorrupted
		}
		if _, err := io.ReadFull(r, e.KeyNonce[:]); err != nil {
			return h, ErrInvalidFormat
		}

		var keyLen uint16
		if err := read(&keyLen); err != nil {
			return h, ErrInvalidFormat
		}
		if keyLen == 0 || int(keyLen) > int(e.KeyLen)+16 {
			return h, ErrCorrupted
		}
		e.SealedKey = make([]byte, keyLen)
		if _, err := io.ReadFull(r, e.SealedKey); err != nil {
			return h, ErrInvalidFormat
		}
	}

	return h, nil
}

// unsealFileKey iterates over recipient entries and returns the first file key that
// successfully authenticates with password. Returns ErrAuthFailed if no entry matches.
func unsealFileKey(entries []recipientEntry, password []byte) ([]byte, error) {
	for _, entry := range entries {
		key := argon2.IDKey(password, entry.Salt, entry.Time, entry.Memory, entry.Threads, entry.KeyLen)
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plain, err := gcm.Open(nil, entry.KeyNonce[:], entry.SealedKey, nil)
		if err != nil {
			continue
		}
		return plain, nil
	}
	return nil, ErrAuthFailed
}

// encryptStreamMultiBody writes the optional metadata chunk (if meta is non-nil) and
// the data chunks to dst, all encrypted with fileKey. hasher, if non-nil, is fed
// only the data plaintext and the digest is written as a trailer.
func encryptStreamMultiBody(dst io.Writer, src io.Reader, fileKey []byte, chunkSize int, meta *FileMeta, hasher hash.Hash) error {
	block, err := aes.NewCipher(fileKey)
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

// EncryptStreamMulti encrypts src to dst using the v0x07 streaming multi-recipient
// format. A fresh random file key encrypts the data (and optional metadata chunk),
// and the file key is sealed once per password. Each password can independently
// decrypt the file. The config controls Argon2id parameters, chunk size, optional
// SHA-256 checksum, and optional FileMeta. Returns ErrAtLeastOnePassword if no
// passwords are provided.
//
// Unlike the legacy v0x04 EncryptMulti this routine streams the plaintext and never
// loads the entire input into memory, so it is safe for arbitrarily large files.
func EncryptStreamMulti(dst io.Writer, src io.Reader, passwords [][]byte, config *Config) error {
	if config == nil {
		config = DefaultConfig
	}
	if len(passwords) == 0 {
		return ErrAtLeastOnePassword
	}

	// Take a local copy so we never mutate the caller's config (or the shared
	// DefaultConfig) under concurrent use.
	cfg := *config
	config = &cfg

	chunkSize := cfg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	cfg.ChunkSize = chunkSize

	fileKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
		return err
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

		sealed := gcm.Seal(nil, keyNonce, fileKey, nil)
		entries[i] = recipientEntry{
			Salt:      salt,
			Time:      config.Time,
			Memory:    config.Memory,
			Threads:   config.Threads,
			KeyLen:    config.KeyLen,
			KeyNonce:  [nonceSize]byte(keyNonce),
			SealedKey: sealed,
		}
	}

	var flags byte
	if config.Checksum {
		flags |= flagChecksum
	}
	if config.FileMeta != nil {
		flags |= flagHasMetadata
	}

	if err := writeStreamMultiHeader(dst, entries, flags); err != nil {
		return err
	}

	var hasher hash.Hash
	if config.Checksum {
		hasher = sha256.New()
	}

	if err := encryptStreamMultiBody(dst, src, fileKey, chunkSize, config.FileMeta, hasher); err != nil {
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

// decryptStreamMultiBody reads the chunked body using fileKey. The optional leading
// metadata chunk is decrypted when the flag is set; data chunks are decrypted and
// written to dst; the optional checksum trailer is verified when set.
func decryptStreamMultiBody(dst io.Writer, src io.Reader, fileKey []byte, flags byte, hasher hash.Hash) (*FileMeta, error) {
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var meta *FileMeta
	if flags&flagHasMetadata != 0 {
		meta, err = decryptStreamV2Meta(src, aesgcm)
		if err != nil {
			return nil, err
		}
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
		if ctLen == 0 {
			break
		}
		if ctLen > maxChunkSize+16 {
			return nil, ErrCorrupted
		}

		ciphertext := make([]byte, ctLen)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return nil, ErrCorrupted
		}

		plaintext, err := aesgcm.Open(nil, nonce[:], ciphertext, nil)
		if err != nil {
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
		if expected != [32]byte(actual) {
			return nil, ErrChecksumMismatch
		}
	}

	return meta, nil
}

// DecryptStreamMulti handles the v0x07 streaming multi-recipient body. The magic
// header and version byte have already been consumed; r contains the recipient
// list followed by the chunked body. Returns the FileMeta when present.
func DecryptStreamMulti(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
	h, err := readStreamMultiHeader(src)
	if err != nil {
		return nil, err
	}

	fileKey, err := unsealFileKey(h.Recipients, password)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash
	if h.Flags&flagChecksum != 0 {
		hasher = sha256.New()
	}

	return decryptStreamMultiBody(dst, src, fileKey, h.Flags, hasher)
}

// DecryptStreamMultiFromReader is a convenience wrapper for DecryptStreamMulti that
// reads and validates the magic + version prefix.
func DecryptStreamMultiFromReader(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
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
	if version != formatVersionStreamMulti {
		return nil, ErrVersionMismatch
	}

	return DecryptStreamMulti(dst, src, password)
}

// readStreamMultiMeta peeks at the v0x07 header to recover the file key, then reads
// and decrypts the metadata chunk (if any). This is used by ReadStreamMetaWithPassword
// for files encrypted with EncryptStreamMulti. The version byte has already been
// consumed by the caller.
func readStreamMultiMeta(r io.Reader, password []byte) (*FileMeta, error) {
	var h streamMultiHeader

	read := func(data any) error {
		return binary.Read(r, binary.LittleEndian, data)
	}

	if err := read(&h.Flags); err != nil {
		return nil, ErrInvalidFormat
	}

	var numRecipients uint32
	if err := read(&numRecipients); err != nil {
		return nil, ErrInvalidFormat
	}
	if numRecipients == 0 {
		return nil, ErrAtLeastOnePassword
	}

	h.Recipients = make([]recipientEntry, numRecipients)
	for i := range h.Recipients {
		e := &h.Recipients[i]

		var saltLen uint16
		if err := read(&saltLen); err != nil {
			return nil, ErrInvalidFormat
		}
		if saltLen > maxSaltLen {
			return nil, ErrCorrupted
		}
		e.Salt = make([]byte, saltLen)
		if _, err := io.ReadFull(r, e.Salt); err != nil {
			return nil, ErrInvalidFormat
		}

		if err := read(&e.Time); err != nil {
			return nil, ErrInvalidFormat
		}
		if err := read(&e.Memory); err != nil {
			return nil, ErrInvalidFormat
		}
		if err := read(&e.Threads); err != nil {
			return nil, ErrInvalidFormat
		}
		if err := read(&e.KeyLen); err != nil {
			return nil, ErrInvalidFormat
		}
		if e.KeyLen == 0 || e.KeyLen > maxKeyLen {
			return nil, ErrCorrupted
		}
		if _, err := io.ReadFull(r, e.KeyNonce[:]); err != nil {
			return nil, ErrInvalidFormat
		}

		var keyLen uint16
		if err := read(&keyLen); err != nil {
			return nil, ErrInvalidFormat
		}
		if keyLen == 0 || int(keyLen) > int(e.KeyLen)+16 {
			return nil, ErrCorrupted
		}
		e.SealedKey = make([]byte, keyLen)
		if _, err := io.ReadFull(r, e.SealedKey); err != nil {
			return nil, ErrInvalidFormat
		}
	}

	if h.Flags&flagHasMetadata == 0 {
		return nil, nil
	}

	fileKey, err := unsealFileKey(h.Recipients, password)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return decryptStreamV2Meta(r, aesgcm)
}
