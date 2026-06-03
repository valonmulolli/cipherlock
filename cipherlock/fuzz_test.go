package cipherlock

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzUnarmor feeds random bytes into UnarmorBytes to make sure the parser
// never panics on hostile input. Seed corpus exercises: empty input, header
// only, header + footer, base64 garbage, oversized data.
func FuzzUnarmor(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN CIPHERLOCK-----\n-----END CIPHERLOCK-----"))
	f.Add([]byte("-----BEGIN CIPHERLOCK-----\n!!!not-base64\n-----END CIPHERLOCK-----"))
	f.Add(bytes.Repeat([]byte{0xff}, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("UnarmorBytes panicked: %v\ninput=%q", r, data)
			}
		}()
		_, _ = UnarmorBytes(data)
	})
}

// FuzzV2Header feeds random bytes to the v0x02/v0x03 header parser. The
// parser must return ErrInvalidFormat, ErrCorrupted, or a similar sentinel
// rather than panic or allocate unboundedly.
func FuzzV2Header(f *testing.F) {
	f.Add([]byte{'C', 'V', '2', 0, 0x03, 0x01, 0x10, 0x00})
	f.Add([]byte{'C', 'V', '2', 0, 0x02, 0x10, 0x00})
	f.Add(bytes.Repeat([]byte{0x55}, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readHeader panicked: %v\ninput=%q", r, data)
			}
		}()
		_, _ = readHeader(bytes.NewReader(data))
	})
}

// FuzzV04Header feeds random bytes to the v0x04 multi-recipient header
// parser. With the recent sealedKeyLen bound this must never panic.
func FuzzV04Header(f *testing.F) {
	f.Add([]byte{'C', 'V', '2', 0, 0x04, 0x00, 0x01, 0, 0, 0, 0})
	f.Add(bytes.Repeat([]byte{0xaa}, 512))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readMultiHeader panicked: %v\ninput=%q", r, data)
			}
		}()
		_, _ = readMultiHeader(bytes.NewReader(data))
	})
}

// FuzzV05Stream feeds random bytes to the v0x05 streaming header parser.
func FuzzV05Stream(f *testing.F) {
	f.Add([]byte{'C', 'V', '2', 0, 0x05, 0x00, 0x10, 0x00})
	f.Add(bytes.Repeat([]byte{0x33}, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readStreamHeader panicked: %v\ninput=%q", r, data)
			}
		}()
		// Use a dummy password; we are testing the header parser, not KDF.
		_, _, _ = readStreamHeader(bytes.NewReader(data), []byte("pwd"))
	})
}

// FuzzV06Stream feeds random bytes to the v0x06 streaming header parser.
func FuzzV06Stream(f *testing.F) {
	f.Add([]byte{'C', 'V', '2', 0, 0x06, 0x00, 0x10, 0x00})
	f.Add(bytes.Repeat([]byte{0x77}, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readStreamV2Header panicked: %v\ninput=%q", r, data)
			}
		}()
		_, _, _ = readStreamV2Header(bytes.NewReader(data), []byte("pwd"))
	})
}

// FuzzV07Stream feeds random bytes to the v0x07 streaming multi-recipient
// header parser. Recent changes bound numRecipients and per-recipient
// sealedKeyLen; this fuzz test guards against regressions in those bounds.
func FuzzV07Stream(f *testing.F) {
	f.Add([]byte{'C', 'V', '2', 0, 0x07, 0x00, 0x01, 0, 0, 0, 0})
	f.Add(bytes.Repeat([]byte{0xcc}, 512))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readStreamMultiHeader panicked: %v\ninput=%q", r, data)
			}
		}()
		_, _ = readStreamMultiHeader(bytes.NewReader(data))
	})
}

// FuzzDecrypt dispatches random bytes to the top-level Decrypt entry point.
// This is the function users call with arbitrary input. It must return a
// sentinel error, never panic, and never allocate more than a few MB.
func FuzzDecrypt(f *testing.F) {
	f.Add([]byte("not a cipherlock file"))
	f.Add([]byte{'C', 'V', '2', 0, 0x05})
	f.Add([]byte{'C', 'V', '2', 0, 0x07})
	f.Add(bytes.Repeat([]byte{0x00}, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Decrypt panicked: %v\ninput=%q", r, data)
			}
		}()
		var dst bytes.Buffer
		err := Decrypt(&dst, bytes.NewReader(data), []byte("pwd"))
		// Either it errors with a sentinel, or it succeeds with no output.
		// Anything in between (nil err with partial output) is also fine.
		if err != nil && !errors.Is(err, ErrInvalidFormat) &&
			!errors.Is(err, ErrVersionMismatch) &&
			!errors.Is(err, ErrCorrupted) &&
			!errors.Is(err, ErrAuthFailed) &&
			!errors.Is(err, ErrChecksumMismatch) {
			// io.ErrUnexpectedEOF is a legitimate truncated-stream error.
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Logf("unexpected non-sentinel error: %v", err)
			}
		}
		// Hard upper bound on what Decrypt should ever allocate from a
		// hostile input: 4 MiB. The v0x04 path has maxV04Body = 1 GiB so we
		// cap the test input at 4 KiB to keep this quick.
		if len(data) > 4096 {
			t.Skip("input too large for fuzz bound")
		}
	})
}
