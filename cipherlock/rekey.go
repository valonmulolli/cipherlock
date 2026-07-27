package cipherlock

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
)

const rekeyBufThreshold = 64 * 1024

// safeWriter buffers writes up to rekeyBufThreshold bytes before flushing
// to dst. On Commit(), buffered data is flushed to dst. On Discard(),
// buffered data is dropped.
//
// This prevents partial output on error: if the decrypt goroutine fails
// (wrong password, corrupt header) before the encrypt goroutine finishes
// writing its header, the header is discarded and dst is untouched. Once
// the buffer threshold is exceeded (i.e., the decrypt has produced enough
// data that the encrypt is well past the header), writes pass through
// directly and Discard no longer prevents data from reaching dst.
type safeWriter struct {
	dst       io.Writer
	buf       bytes.Buffer
	threshold int
	direct    bool
}

func newSafeWriter(dst io.Writer) *safeWriter {
	return &safeWriter{dst: dst, threshold: rekeyBufThreshold}
}

func (sw *safeWriter) Write(p []byte) (int, error) {
	if sw.direct {
		return sw.dst.Write(p)
	}
	n, err := sw.buf.Write(p)
	if err != nil {
		return n, err
	}
	if sw.buf.Len() >= sw.threshold {
		if _, err := sw.buf.WriteTo(sw.dst); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (sw *safeWriter) Commit() error {
	if sw.buf.Len() == 0 {
		sw.direct = true
		return nil
	}
	expected := int64(sw.buf.Len())
	n, err := sw.buf.WriteTo(sw.dst)
	sw.direct = true
	if err != nil {
		return err
	}
	if n < expected {
		return io.ErrShortWrite
	}
	return nil
}

func (sw *safeWriter) Discard() {
	sw.buf.Reset()
}

// ReKey decrypts data from src with oldPassword and re-encrypts it with
// newPassword. The output format mirrors the input format:
//   - v0x05 in -> v0x05 out
//   - v0x06 in -> v0x06 out (preserves the attached FileMeta)
//   - v0x07 in -> v0x07 out (collapses the recipient list to newPassword)
//
// For all streaming inputs the operation is performed without buffering
// the entire plaintext. For legacy v0x02/v0x03/v0x04 inputs the plaintext
// is held in memory during re-encryption.
//
// It returns ErrInvalidFormat, ErrVersionMismatch, ErrAuthFailed,
// ErrChecksumMismatch, or ErrCorrupted from the decrypt step, or any
// encrypt error from the re-encrypt step.
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
		sw := newSafeWriter(dst)

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
				err = EncryptStream(sw, pipeR, newPassword, &local)
			case formatVersionStreamV2:
				err = EncryptStreamV2(sw, pipeR, newPassword, &local)
			case formatVersionStreamMulti:
				err = EncryptStreamMulti(sw, pipeR, [][]byte{newPassword}, &local)
			}
			errCh <- err
		}()

		err1 := <-errCh
		err2 := <-errCh
		if err1 != nil {
			sw.Discard()
			return err1
		}
		if err2 != nil {
			sw.Discard()
			return err2
		}
		return sw.Commit()
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

// ReKeyFile decrypts a file with oldPassword and re-encrypts it with newPassword.
// If dest is empty, the source file is overwritten in place.
//
// The in-place case (source == dest) is implemented as a write to a
// sibling tempfile followed by Shred(source) + atomic rename. This
// guarantees the source is preserved if the rekey fails partway: the
// old behavior was to os.Create(dest) which truncates the file to
// zero bytes before any decryption runs, leaving the user with an
// empty file and a "wrong password" error.
//
// It returns errors from os.Open/os.Create, or any error from ReKey
// (ErrInvalidFormat, ErrAuthFailed, etc.).
func ReKeyFile(source, dest string, oldPassword, newPassword []byte, config *Config) error {
	if dest == "" {
		dest = source
	}

	if source != dest {
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

	// In-place: rename original to a safe backup, write to tempfile,
	// then rename temp into place. This is SIGINT-safe: the original is
	// preserved as .cipherlock-bak until the temp is in place at source.
	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close() //nolint:errcheck

	bak := source + ".cipherlock-bak"
	if err := os.Rename(source, bak); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(source), ".cipherlock-rekey-*")
	if err != nil {
		os.Rename(bak, source)
		return err
	}
	tmpName := tmp.Name()

	if err := ReKey(tmp, srcFile, oldPassword, newPassword, config); err != nil {
		tmp.Close() //nolint:errcheck
		os.Remove(tmpName)
		os.Rename(bak, source) // restore original
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		os.Rename(bak, source) // restore original
		return err
	}

	if err := os.Rename(tmpName, source); err != nil {
		os.Remove(tmpName)
		os.Rename(bak, source) // restore original
		return err
	}

	_ = Shred(bak)
	return nil
}
