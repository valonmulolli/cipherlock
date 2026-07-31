package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/argon2"
)

// Pool of 32KB buffers reused by io.CopyBuffer in compress/decompress goroutines.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Pools for zstd encoder and decoder instances to reuse their internal buffers
// (window size ~8MB, hash tables, etc.) across encrypt/decrypt operations.
var zstdEncoderPool sync.Pool

func getZstdEncoder(w io.Writer) *zstd.Encoder {
	if enc, ok := zstdEncoderPool.Get().(*zstd.Encoder); ok {
		enc.Reset(w)
		return enc
	}
	enc, _ := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1))
	return enc
}

func putZstdEncoder(enc *zstd.Encoder) {
	enc.Close()
	zstdEncoderPool.Put(enc)
}

func compressReader(src io.Reader) io.Reader {
	pr, pw := io.Pipe()
	zw := getZstdEncoder(pw)
	go func() {
		buf := copyBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(zw, src, *buf)
		copyBufPool.Put(buf)
		putZstdEncoder(zw)
		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()
	return pr
}

func decompressWriter(dst io.Writer) (io.Writer, func()) {
	pr, pw := io.Pipe()
	zr, _ := zstd.NewReader(pr, zstd.WithDecoderConcurrency(1))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		buf := copyBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, zr, *buf)
		copyBufPool.Put(buf)
		zr.Close()
		wg.Done()
	}()
	return pw, func() {
		pw.Close()
		wg.Wait()
	}
}

// Encrypt encrypts data read from src using password and writes ciphertext to dst.
// It is a convenience wrapper around EncryptStream and always produces the streaming
// format (v0x05). The config parameter controls Argon2 parameters and whether to
// include a checksum. Returns ErrAuthFailed if authentication fails.
//
// Deprecated: Encrypt is identical to EncryptStream. Prefer EncryptStream for clarity.
func Encrypt(dst io.Writer, src io.Reader, password []byte, config *Config) error {
	return EncryptStream(dst, src, password, config)
}

// Decrypt decrypts data read from src using password and writes plaintext to dst.
// It supports all format versions (v2, v3, v0x04 multi-key, v0x05 stream,
// v0x06 stream with encrypted metadata, v0x07 streaming multi-recipient).
// Returns ErrInvalidFormat, ErrVersionMismatch, ErrAuthFailed, or
// ErrChecksumMismatch on failure. To recover FileMeta attached to a
// v0x06/v0x07 container use DecryptWithMeta.
func Decrypt(dst io.Writer, src io.Reader, password []byte) error {
	_, err := DecryptWithMeta(dst, src, password)
	return err
}

// DecryptWithMeta is the metadata-aware form of Decrypt. The returned
// *FileMeta is non-nil only when the source was encrypted with v0x06 or
// v0x07 and had a FileMeta attached; v0x02 through v0x05 return nil. It
// exists so that downstream code can recover the original filename and
// modification time without an extra ReadStreamMetaWithPassword call.
//
// It enforces time-gated expiry: if the file was created with a non-zero
// FileMeta.ExpiresAt in the past, it returns ErrExpired after successfully
// authenticating the data (so wrong-password errors still surface first).
//
// It returns ErrInvalidFormat if src does not start with the cipherlock magic,
// ErrVersionMismatch for an unrecognized format version, ErrAuthFailed on
// wrong password or tampered ciphertext, ErrChecksumMismatch if the
// embedded SHA-256 checksum does not match the decrypted plaintext, or
// ErrExpired for a time-gated file past its expiration.
func DecryptWithMeta(dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
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

	// Every per-version decrypt helper re-reads magic+version from scratch, so
	// we always prepend the full 5-byte prefix back onto src.
	prefix := append(hdrMagic[:], version)

	var meta *FileMeta
	var decryptErr error
	switch version {
	case formatVersionV2, formatVersionV3:
		combined := io.MultiReader(bytes.NewReader(prefix), src)
		decryptErr = decryptV2V3(dst, combined, password)
	case formatVersionMulti:
		multiSrc := io.MultiReader(bytes.NewReader(prefix), src)
		decryptErr = decryptMulti(dst, multiSrc, password)
	case formatVersionStream:
		streamSrc := io.MultiReader(bytes.NewReader(prefix), src)
		meta, decryptErr = decryptStream(dst, streamSrc, password)
	case formatVersionStreamV2:
		streamSrc := io.MultiReader(bytes.NewReader(prefix), src)
		meta, decryptErr = decryptStreamV2Impl(dst, streamSrc, password, true)
	case formatVersionStreamMulti:
		multiSrc := io.MultiReader(bytes.NewReader(prefix), src)
		meta, decryptErr = DecryptStreamMultiFromReader(dst, multiSrc, password)
	case formatVersionAsymmetric:
		asymSrc := io.MultiReader(bytes.NewReader(prefix), src)
		meta, decryptErr = DecryptAsymmetricWithMeta(dst, asymSrc, nil)
	default:
		return nil, ErrVersionMismatch
	}
	if decryptErr != nil {
		return nil, decryptErr
	}
	// v0x06 enforces expiry inside decryptStreamV2Impl before writing any
	// plaintext. v0x07 multi-recipient files share the same metadata chunk
	// format and therefore also carry ExpiresAt; enforcement for them happens
	// here (after the full decrypt). CLI decrypt paths always write to a temp
	// file that is removed on error, so no expired plaintext survives. The
	// exported DecryptStreamV2 and DecryptStreamMultiFromReader remain the
	// documented escape hatches for recovering expired files.
	if meta != nil && !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
		return nil, ErrExpired
	}
	return meta, nil
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
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext, err := io.ReadAll(io.LimitReader(src, maxV04Body))
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

// GeneratePassword generates a cryptographically random hex-encoded password.
// The length parameter controls the number of random bytes before hex encoding,
// resulting in a password of length len*2 hex characters.
// A length of 32 produces a 64-character hex string (256 bits of entropy).
func GeneratePassword(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b)
	clear(b)
	return dst, nil
}
