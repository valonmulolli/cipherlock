package cipherlock

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
)

// ReKey decrypts data from src with oldPassword and re-encrypts it with newPassword.
// For stream-format files it performs the operation without buffering the entire plaintext.
func ReKey(dst io.Writer, src io.Reader, oldPassword, newPassword []byte, config *Config) error {
	var hdrMagic [4]byte
	if _, err := io.ReadFull(src, hdrMagic[:]); err != nil {
		return ErrInvalidFormat
	}
	if hdrMagic != magic {
		return ErrInvalidFormat
	}

	var version byte
	if err := binary.Read(src, binary.LittleEndian, &version); err != nil {
		return ErrInvalidFormat
	}

	if version == formatVersionStream {
		pipeR, pipeW := io.Pipe()
		errCh := make(chan error, 2)

		fullSrc := io.MultiReader(bytes.NewReader(append(hdrMagic[:], version)), src)

		go func() {
			err := DecryptStream(pipeW, fullSrc, oldPassword)
			pipeW.CloseWithError(err)
		}()

		go func() {
			err := EncryptStream(dst, pipeR, newPassword, config)
			errCh <- err
		}()

		return <-errCh
	}

	var buf bytes.Buffer
	if err := Decrypt(&buf, io.MultiReader(
		bytes.NewReader(append(hdrMagic[:], version)), src,
	), oldPassword); err != nil {
		return err
	}
	return Encrypt(dst, &buf, newPassword, config)
}

// ReKeyFile decrypts a file with oldPassword and re-encrypts it with newPassword in place.
// If dest is empty, the source file is overwritten.
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
