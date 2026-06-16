package cipherlock

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// EncryptFile encrypts a source file and writes the ciphertext to a destination file.
// If dest is empty, the source path with a .encrypted suffix is used.
//
// The output format is v0x05 (streaming) by default. When config.FileMeta
// is set the output is v0x06 so the metadata chunk is encrypted (v0x05
// would leak the original filename and mtime in the cleartext header).
// EncryptFile explicitly selects EncryptStreamV2 in that case.
//
// It returns errors from os.Open/os.Create, or any error returned by
// Encrypt or EncryptStreamV2 (see those functions for details).
func EncryptFile(source, dest string, password []byte, config *Config) error {
	if dest == "" {
		dest = source + ".encrypted"
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close() //nolint:errcheck

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close() //nolint:errcheck

	if config != nil && config.FileMeta != nil {
		return EncryptStreamV2(destFile, srcFile, password, config)
	}
	return Encrypt(destFile, srcFile, password, config)
}

// DecryptFile decrypts a source file and writes the plaintext to a destination file.
// If dest is empty, the .encrypted or .cipherlock suffix is stripped, or .decrypted is appended.
//
// It returns errors from os.Open/os.Create, or ErrInvalidFormat, ErrVersionMismatch,
// ErrAuthFailed, or ErrChecksumMismatch.
func DecryptFile(source, dest string, password []byte) error {
	if dest == "" {
		dest = defaultDecryptPath(source)
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close() //nolint:errcheck

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close() //nolint:errcheck

	return Decrypt(destFile, srcFile, password)
}

// DecryptFileWithMeta is the metadata-aware form of DecryptFile. The
// returned *FileMeta is non-nil only when the source was a v0x06 or v0x07
// container with a FileMeta attached.
//
// It returns errors from os.Open/os.Create, or any error returned by
// DecryptWithMeta (see that function for details).
func DecryptFileWithMeta(source, dest string, password []byte) (*FileMeta, error) {
	if dest == "" {
		dest = defaultDecryptPath(source)
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer srcFile.Close() //nolint:errcheck

	destFile, err := os.Create(dest)
	if err != nil {
		return nil, err
	}
	defer destFile.Close() //nolint:errcheck

	return DecryptWithMeta(destFile, srcFile, password)
}

// IsEncrypted reports whether the file at path starts with the cipherlock magic bytes.
// It returns false without error if the file cannot be read or is too short.
func IsEncrypted(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck

	var buf [4]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return buf == magic, nil
}

func defaultDecryptPath(source string) string {
	ext := filepath.Ext(source)
	if ext == ".encrypted" || ext == ".cipherlock" {
		return strings.TrimSuffix(source, ext)
	}
	return source + ".decrypted"
}
