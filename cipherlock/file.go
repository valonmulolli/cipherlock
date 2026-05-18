package cipherlock

import (
	"os"
	"path/filepath"
	"strings"
)

func EncryptFile(source, dest string, password []byte, config *Config) error {
	if dest == "" {
		dest = source + ".encrypted"
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	return Encrypt(destFile, srcFile, password, config)
}

func DecryptFile(source, dest string, password []byte) error {
	if dest == "" {
		dest = defaultDecryptPath(source)
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	return Decrypt(destFile, srcFile, password)
}

func IsEncrypted(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	h, err := readHeader(f)
	if err != nil {
		return false, nil
	}

	return h.Magic == magic, nil
}

func defaultDecryptPath(source string) string {
	ext := filepath.Ext(source)
	if ext == ".encrypted" || ext == ".cipherlock" {
		return strings.TrimSuffix(source, ext)
	}
	return source + ".decrypted"
}
