package cipherlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	v1NonceSize  = 12
	v1TagSize    = 16
	v1Iterations = 4096
	v1KeyLen     = 32
)

// DecryptFileV1 decrypts a v1-format encrypted file using PBKDF2 key derivation.
// This is provided for backward compatibility with legacy cipherlock files.
// It returns ErrInvalidFormat if the ciphertext is too short.
func DecryptFileV1(source, dest string, password []byte) error {
	ciphertext, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	if len(ciphertext) < v1NonceSize+v1TagSize {
		return ErrInvalidFormat
	}

	salt := ciphertext[len(ciphertext)-v1NonceSize:]
	body := ciphertext[:len(ciphertext)-v1NonceSize]

	key := pbkdf2.Key(password, salt, v1Iterations, v1KeyLen, sha1.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, v1NonceSize)
	copy(nonce, salt)

	plaintext, err := aesgcm.Open(nil, nonce, body, nil)
	if err != nil {
		return err
	}

	if dest == "" {
		dest = source + ".decrypted"
	}

	return os.WriteFile(dest, plaintext, 0644)
}
