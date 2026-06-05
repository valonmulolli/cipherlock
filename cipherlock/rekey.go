package cipherlock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// ReKey decrypts data from src with oldPassword and re-encrypts it with
// newPassword. The output format mirrors the input format:
//   - v0x05 in -> v0x05 out
//   - v0x06 in -> v0x06 out (preserves the attached FileMeta)
//   - v0x07 in -> v0x07 out (collapses the recipient list to newPassword)
//
// For all streaming inputs the operation is performed without buffering
// the entire plaintext. For legacy v0x02/v0x03/v0x04 inputs the plaintext
// is held in memory during re-encryption.
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
		// The streaming decrypt helpers consume magic+version themselves,
		// so we need to chain those bytes back in front of src for the
		// final fullSrc. For v0x06 / v0x07 we also need to capture the
		// FileMeta before launching the streaming pipe so the re-encrypt
		// side can re-attach it. We do that by teeing the captured bytes
		// into a buffer that we then chain in front of the remaining src.
		var fullSrc io.Reader
		var meta *FileMeta
		if version == formatVersionStreamV2 || version == formatVersionStreamMulti {
			var captured bytes.Buffer
			captured.Write(hdrMagic[:])
			captured.WriteByte(version)
			tee := io.TeeReader(src, &captured)
			var err error
			meta, err = captureMeta(tee, version, oldPassword)
			if err != nil {
				return err
			}
			fullSrc = io.MultiReader(&captured, src)
		} else {
			fullSrc = io.MultiReader(bytes.NewReader(append(hdrMagic[:], version)), src)
		}

		pipeR, pipeW := io.Pipe()
		errCh := make(chan error, 2)

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
			// Re-encrypt in the same format as the input. meta is only
			// non-nil for v0x06 and v0x07. Default to DefaultConfig if
			// the caller passed nil, matching the rest of the API.
			cfg := config
			if cfg == nil {
				cfg = DefaultConfig
			}
			local := *cfg
			local.FileMeta = meta
			var err error
			switch version {
			case formatVersionStream:
				err = EncryptStream(dst, pipeR, newPassword, &local)
			case formatVersionStreamV2:
				err = EncryptStreamV2(dst, pipeR, newPassword, &local)
			case formatVersionStreamMulti:
				err = EncryptStreamMulti(dst, pipeR, [][]byte{newPassword}, &local)
			}
			errCh <- err
		}()

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

// captureMeta reads the header + optional meta chunk from src and
// returns the captured FileMeta. src is expected to be positioned
// just after the magic+version bytes (since readStreamV2MetaOnly
// and readStreamMultiMeta both expect that).
func captureMeta(src io.Reader, version byte, password []byte) (*FileMeta, error) {
	switch version {
	case formatVersionStreamV2:
		return readStreamV2MetaOnly(src, password)
	case formatVersionStreamMulti:
		return readStreamMultiMeta(src, password)
	default:
		return nil, ErrInvalidFormat
	}
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
