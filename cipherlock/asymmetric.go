package cipherlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// X25519Recipient is a public key that can encrypt data for its corresponding identity.
type X25519Recipient struct {
	PublicKey []byte // 32 bytes
}

// X25519Identity is a private key that can decrypt data encrypted to its public key.
type X25519Identity struct {
	PrivateKey []byte // 32 bytes seed/scalar
	PublicKey  []byte // 32 bytes point
}

// GenerateX25519Keypair generates a new X25519 key pair from crypto/rand.
func GenerateX25519Keypair() (*X25519Identity, error) {
	privKey := make([]byte, x25519PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, privKey); err != nil {
		return nil, err
	}
	return X25519IdentityFromPrivateKey(privKey)
}

// X25519IdentityFromPrivateKey derives the public key from a private key seed.
func X25519IdentityFromPrivateKey(privKey []byte) (*X25519Identity, error) {
	if len(privKey) != x25519PrivateKeySize {
		return nil, fmt.Errorf("cipherlock: invalid private key length %d", len(privKey))
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("cipherlock: invalid private key: %w", err)
	}
	return &X25519Identity{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// IdentityFromSSHPrivateKey parses a PEM-encoded SSH private key (Ed25519)
// and returns an X25519Identity derived from it. Ed25519 and X25519 share
// the same curve (Curve25519); the seed is converted via SHA-512 + standard
// X25519 clamping. The resulting identity can be used to decrypt files that
// were encrypted to the derived X25519 public key.
//
// For RSA and ECDSA keys, it returns ErrUnsupportedKeyType.
func IdentityFromSSHPrivateKey(pemData []byte) (*X25519Identity, error) {
	key, err := ssh.ParseRawPrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("cipherlock: parse SSH key: %w", err)
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cipherlock: unsupported SSH key type %T (only Ed25519 is supported)", key)
	}

	seed := priv.Seed()
	h := sha512.Sum512(seed)
	clear(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	privKey := make([]byte, x25519PrivateKeySize)
	copy(privKey, h[:32])
	clear(h[:])
	return X25519IdentityFromPrivateKey(privKey)
}

// NewX25519Recipient creates a recipient from a raw 32-byte public key.
func NewX25519Recipient(pubKey []byte) (*X25519Recipient, error) {
	if len(pubKey) != x25519PublicKeySize {
		return nil, fmt.Errorf("cipherlock: invalid public key length %d", len(pubKey))
	}
	return &X25519Recipient{PublicKey: pubKey}, nil
}

// asymmetricRecipientEntry stores a sealed file key for a single asymmetric recipient.
type asymmetricRecipientEntry struct {
	IdentityType byte   // 0x01 = X25519
	EphemeralPK  []byte // 32 bytes, the ephemeral public key used in ECDH
	Nonce        []byte // 12 bytes
	SealedKey    []byte // 48 bytes = 32-byte file key + 16-byte GCM tag
}

// writeAsymmetricHeader writes the v0x08 header to w.
func writeAsymmetricHeader(w io.Writer, entries []asymmetricRecipientEntry, flags byte) error {
	write := func(data any) error {
		return binary.Write(w, binary.LittleEndian, data)
	}

	if err := write(magic); err != nil {
		return err
	}
	if err := write(formatVersionAsymmetric); err != nil {
		return err
	}
	if err := write(flags); err != nil {
		return err
	}
	if err := write(uint32(len(entries))); err != nil {
		return err
	}

	for _, e := range entries {
		if err := write(e.IdentityType); err != nil {
			return err
		}
		if _, err := w.Write(e.EphemeralPK); err != nil {
			return err
		}
		if _, err := w.Write(e.Nonce); err != nil {
			return err
		}
		if _, err := w.Write(e.SealedKey); err != nil {
			return err
		}
	}

	return nil
}

// readAsymmetricHeader reads the v0x08 header from r (magic+version already consumed).
func readAsymmetricHeader(r io.Reader) ([]asymmetricRecipientEntry, byte, error) {
	read := func(data any) error {
		return binary.Read(r, binary.LittleEndian, data)
	}

	var flags byte
	if err := read(&flags); err != nil {
		return nil, 0, ErrInvalidFormat
	}

	var numRecipients uint32
	if err := read(&numRecipients); err != nil {
		return nil, 0, ErrInvalidFormat
	}
	if numRecipients == 0 || numRecipients > maxAsymmetricRecipients {
		return nil, 0, ErrCorrupted
	}

	entries := make([]asymmetricRecipientEntry, numRecipients)
	for i := range entries {
		e := &entries[i]

		if err := read(&e.IdentityType); err != nil {
			return nil, 0, ErrInvalidFormat
		}
		if e.IdentityType != identityTypeX25519 {
			return nil, 0, ErrUnsupportedIdentity
		}

		e.EphemeralPK = make([]byte, x25519PublicKeySize)
		if _, err := io.ReadFull(r, e.EphemeralPK); err != nil {
			return nil, 0, ErrInvalidFormat
		}

		e.Nonce = make([]byte, nonceSize)
		if _, err := io.ReadFull(r, e.Nonce); err != nil {
			return nil, 0, ErrInvalidFormat
		}

		e.SealedKey = make([]byte, sealedKeySize)
		if _, err := io.ReadFull(r, e.SealedKey); err != nil {
			return nil, 0, ErrInvalidFormat
		}
	}

	return entries, flags, nil
}

// sealFileKey encrypts the fileKey so that only the holder of the private key
// corresponding to recipient.PublicKey can recover it.
//
// It generates an ephemeral X25519 key pair, performs ECDH, derives a wrapping
// key via HKDF-SHA256, and AES-256-GCM encrypts the file key.
func sealFileKey(fileKey []byte, recipient *X25519Recipient) (*asymmetricRecipientEntry, error) {
	ephemeralPriv := make([]byte, x25519PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPriv); err != nil {
		return nil, err
	}
	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(ephemeralPriv, recipient.PublicKey)
	clear(ephemeralPriv)
	if err != nil {
		return nil, err
	}

	wrappingKey, nonce, err := deriveWrappingKey(shared, ephemeralPub, recipient.PublicKey)
	clear(shared)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, fileKey, nil)

	return &asymmetricRecipientEntry{
		IdentityType: identityTypeX25519,
		EphemeralPK:  ephemeralPub,
		Nonce:        nonce,
		SealedKey:    sealed,
	}, nil
}

// unsealFileKey recovers the file key from an asymmetric recipient entry using the
// identity's private key.
func unsealAsymmetricFileKey(entry *asymmetricRecipientEntry, identity *X25519Identity) ([]byte, error) {
	if entry.IdentityType != identityTypeX25519 {
		return nil, ErrUnsupportedIdentity
	}

	shared, err := curve25519.X25519(identity.PrivateKey, entry.EphemeralPK)
	if err != nil {
		return nil, err
	}

	wrappingKey, _, err := deriveWrappingKey(shared, entry.EphemeralPK, identity.PublicKey)
	clear(shared)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	fileKey, err := gcm.Open(nil, entry.Nonce, entry.SealedKey, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return fileKey, nil
}

// deriveWrappingKey derives an AES-256 key and GCM nonce from an ECDH shared
// secret using HKDF-SHA256. The salt is ephemeralPub || recipientPub to ensure
// unique keys per (file, recipient) pair.
func deriveWrappingKey(sharedSecret, ephemeralPub, recipientPub []byte) (key, nonce []byte, err error) {
	salt := make([]byte, len(ephemeralPub)+len(recipientPub))
	copy(salt, ephemeralPub)
	copy(salt[len(ephemeralPub):], recipientPub)

	material, err := hkdf.Key(sha256.New, sharedSecret, salt, "cipherlock-x25519-key", 32+nonceSize)
	if err != nil {
		return nil, nil, err
	}
	return material[:32], material[32:], nil
}

// EncryptAsymmetric encrypts src to dst using the v0x08 asymmetric streaming format.
// The data is encrypted with a random file key using AES-256-GCM, and the file key
// is sealed once per recipient. Each recipient can independently decrypt the file.
//
// It returns an error if no recipients are provided.
func EncryptAsymmetric(dst io.Writer, src io.Reader, recipients []*X25519Recipient, config *Config) error {
	if len(recipients) == 0 {
		return errors.New("cipherlock: at least one recipient required")
	}

	if config == nil {
		config = DefaultConfig
	}
	cfg := *config

	chunkSize := cfg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > maxChunkSize {
		return fmt.Errorf("cipherlock: ChunkSize %d exceeds maxChunkSize %d", chunkSize, maxChunkSize)
	}

	fileKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
		return err
	}
	defer clear(fileKey)

	for i, rec := range recipients {
		if rec == nil {
			return fmt.Errorf("cipherlock: nil recipient at index %d", i)
		}
		if len(rec.PublicKey) != x25519PublicKeySize {
			return fmt.Errorf("cipherlock: invalid recipient public key length at index %d", i)
		}
	}

	entries := make([]asymmetricRecipientEntry, len(recipients))
	for i, rec := range recipients {
		entry, err := sealFileKey(fileKey, rec)
		if err != nil {
			return err
		}
		entries[i] = *entry
	}

	var flags byte
	if cfg.Checksum {
		flags |= flagChecksum
	}
	if cfg.FileMeta != nil {
		flags |= flagHasMetadata
	}
	if cfg.Compression {
		flags |= flagCompressed
		src = compressReader(src)
	}

	if err := writeAsymmetricHeader(dst, entries, flags); err != nil {
		return err
	}

	var hasher hash.Hash
	if cfg.Checksum {
		hasher = sha256.New()
	}

	if err := encryptAsymmetricBody(dst, src, fileKey, chunkSize, cfg.FileMeta, hasher); err != nil {
		return err
	}

	if cfg.Checksum && hasher != nil {
		checksum := hasher.Sum(nil)
		if _, err := dst.Write(checksum); err != nil {
			return err
		}
	}
	return nil
}

// encryptAsymmetricBody writes the optional metadata chunk and data chunks to dst,
// all encrypted with fileKey.
func encryptAsymmetricBody(dst io.Writer, src io.Reader, fileKey []byte, chunkSize int, meta *FileMeta, hasher hash.Hash) error {
	defer clear(fileKey)
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

// DecryptAsymmetric decrypts a v0x08 asymmetric cipherlock file from src and writes
// the plaintext to dst. The identity is used to unseal the file key.
//
// It returns ErrInvalidFormat, ErrVersionMismatch, ErrAuthFailed, or
// ErrChecksumMismatch on failure.
func DecryptAsymmetric(dst io.Writer, src io.Reader, identity *X25519Identity) error {
	_, err := DecryptAsymmetricWithMeta(dst, src, identity)
	return err
}

// DecryptAsymmetricWithMeta is the metadata-aware form of DecryptAsymmetric.
// The returned *FileMeta is non-nil when the encrypted file was created with
// FileMeta attached (original filename, size, modification time).
func DecryptAsymmetricWithMeta(dst io.Writer, src io.Reader, identity *X25519Identity) (*FileMeta, error) {
	if identity == nil {
		return nil, errors.New("cipherlock: identity is required for asymmetric decryption")
	}

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
	if version != formatVersionAsymmetric {
		return nil, ErrVersionMismatch
	}

	entries, flags, err := readAsymmetricHeader(src)
	if err != nil {
		return nil, err
	}

	fileKey, err := tryUnsealAsymmetric(entries, identity)
	if err != nil {
		return nil, err
	}

	return decryptAsymmetricBody(dst, src, fileKey, flags)
}

func tryUnsealAsymmetric(entries []asymmetricRecipientEntry, identity *X25519Identity) ([]byte, error) {
	for _, entry := range entries {
		key, err := unsealAsymmetricFileKey(&entry, identity)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, ErrAuthFailed) {
			return nil, err
		}
	}
	return nil, ErrAuthFailed
}

func decryptAsymmetricBody(dst io.Writer, src io.Reader, fileKey []byte, flags byte) (*FileMeta, error) {
	defer clear(fileKey)
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash
	if flags&flagChecksum != 0 {
		hasher = sha256.New()
	}

	var meta *FileMeta
	if flags&flagHasMetadata != 0 {
		meta, err = decryptStreamV2Meta(src, aesgcm)
		if err != nil {
			return nil, err
		}
	}

	var decompress func()
	if flags&flagCompressed != 0 {
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
		if ctLen == 0 {
			break
		}

		if ctLen > uint32(maxChunkSize)+16 {
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
		if !bytes.Equal(expected[:], actual) {
			return nil, ErrChecksumMismatch
		}
	}

	if decompress != nil {
		decompress()
	}

	return meta, nil
}

const (
	identityEncryptVersion = 1
	identitySaltLen        = 32
	identityArgon2Time     = 2
	identityArgon2Memory   = 64 * 1024
	identityArgon2Threads  = 4
	identityKeyLen         = 32
)

// SerializeX25519Identity serializes an identity's private key to a PEM-like armored
// format. If passphrase is non-nil, the key is encrypted with Argon2id + AES-256-GCM.
func SerializeX25519Identity(identity *X25519Identity, passphrase []byte) ([]byte, error) {
	var payload []byte
	if len(passphrase) > 0 {
		salt := make([]byte, identitySaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generating salt: %w", err)
		}

		key := argon2.IDKey(passphrase, salt, identityArgon2Time, identityArgon2Memory,
			identityArgon2Threads, identityKeyLen)
		defer clear(key)

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, aesgcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating nonce: %w", err)
		}

		ciphertext := aesgcm.Seal(nil, nonce, identity.PrivateKey, nil)

		payload = make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
		payload = append(payload, identityEncryptVersion)
		payload = append(payload, salt...)
		payload = append(payload, nonce...)
		payload = append(payload, ciphertext...)
	} else {
		payload = identity.PrivateKey
	}

	var buf bytes.Buffer
	if err := Armor(&buf, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeserializeX25519Identity deserializes an identity from the PEM-like armored format.
// If the identity was encrypted, passphrase must be provided.
func DeserializeX25519Identity(data, passphrase []byte) (*X25519Identity, error) {
	payload, err := UnarmorBytes(data)
	if err != nil {
		return nil, err
	}

	var privKey []byte
	if len(payload) == x25519PublicKeySize {
		privKey = payload
	} else if len(payload) > 0 && payload[0] == identityEncryptVersion {
		if len(passphrase) == 0 {
			return nil, ErrIdentityNeedsPassphrase
		}
		if len(payload) < 1+identitySaltLen+12+16 {
			return nil, ErrCorrupted
		}

		salt := payload[1 : 1+identitySaltLen]
		nonce := payload[1+identitySaltLen : 1+identitySaltLen+12]
		ciphertext := payload[1+identitySaltLen+12:]

		key := argon2.IDKey(passphrase, salt, identityArgon2Time, identityArgon2Memory,
			identityArgon2Threads, identityKeyLen)
		defer clear(key)

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, ErrAuthFailed
		}
		privKey = plaintext
	} else {
		privKey = payload
	}

	return X25519IdentityFromPrivateKey(privKey)
}
