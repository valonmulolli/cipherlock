package cipherlock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// ReKey decrypts data from src with oldPassword and re-encrypts it with newPassword.
// For stream-format files (v0x05, v0x06, v0x07) it performs the operation without
// buffering the entire plaintext. The output is always written in v0x05 streaming
// format because only one password is in play after re-keying.
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

	if version == formatVersionStream || version == formatVersionStreamV2 || version == formatVersionStreamMulti {
		pipeR, pipeW := io.Pipe()
		errCh := make(chan error, 2)

		// Re-prepend magic+version so the per-version decrypt helpers (which each
		// read magic+version themselves) see the full stream.
		fullSrc := io.MultiReader(bytes.NewReader(append(hdrMagic[:], version)), src)

		go func() {
			var err error
			switch version {
			case formatVersionStream:
				_, err = DecryptStreamMeta(pipeW, fullSrc, oldPassword)
			case formatVersionStreamV2:
				_, err = DecryptStreamV2(pipeW, fullSrc, oldPassword)
			case formatVersionStreamMulti:
				_, err = DecryptStreamMultiFromReader(pipeW, fullSrc, oldPassword)
			}
			pipeW.CloseWithError(err)
			errCh <- err
		}()

		go func() {
			defer pipeR.Close() //nolint:errcheck
			err := EncryptStream(dst, pipeR, newPassword, config)
			errCh <- err
		}()

		// Consume both goroutine errors. Return the one that is
		// not a broken-pipe cascade error.
		err1 := <-errCh
		err2 := <-errCh
		if err1 != nil && !errors.Is(err1, io.ErrClosedPipe) {
			return err1
		}
		return err2
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
	defer srcFile.Close() //nolint:errcheck
	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close() //nolint:errcheck

	return ReKey(destFile, srcFile, oldPassword, newPassword, config)
}
