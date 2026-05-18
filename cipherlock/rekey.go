package cipherlock

import (
	"bytes"
	"io"
	"os"
)

func ReKey(dst io.Writer, src io.Reader, oldPassword, newPassword []byte, config *Config) error {
	var buf bytes.Buffer
	if err := Decrypt(&buf, src, oldPassword); err != nil {
		return err
	}
	return Encrypt(dst, &buf, newPassword, config)
}

func ReKeyFile(source, dest string, oldPassword, newPassword []byte, config *Config) error {
	if dest == "" {
		dest = source
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

	return ReKey(destFile, srcFile, oldPassword, newPassword, config)
}
