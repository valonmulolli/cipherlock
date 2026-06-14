package cipherlock

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// armorHeader is the header line of the ASCII-armor format.
	armorHeader = "-----BEGIN CIPHERLOCK-----"
	// armorFooter is the footer line of the ASCII-armor format.
	armorFooter  = "-----END CIPHERLOCK-----"
	armorLineLen = 64
)

var (
	ErrNotArmored = errors.New("cipherlock: not an armored file")
)

// MagicArmorHeader is the ASCII armor header line as a byte slice.
// It can be used to detect whether a byte stream uses the cipherlock
// armored format before calling Unarmor or IsArmored.
var MagicArmorHeader = []byte(armorHeader)

// Armor writes data to w in ASCII-armor format (base64 encoded with header/footer lines).
// It returns any write error from the underlying io.Writer.
func Armor(w io.Writer, data []byte) error {
	if _, err := fmt.Fprintln(w, armorHeader); err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	for i := 0; i < len(encoded); i += armorLineLen {
		end := i + armorLineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		if _, err := fmt.Fprintln(w, encoded[i:end]); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, armorFooter); err != nil {
		return err
	}

	return nil
}

// Unarmor reads ASCII-armor encoded data from r and returns the decoded bytes.
// It buffers the entire stream into memory; for large armored inputs use
// NewUnarmorReader to stream the decoded bytes into a downstream reader.
//
// It returns ErrNotArmored if the input does not contain a valid armor header,
// or a base64 decode error if the encapsulated data is malformed.
func Unarmor(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return UnarmorBytes(data)
}

// UnarmorBytes decodes ASCII-armor encoded data and returns the original bytes.
//
// It returns ErrNotArmored if the data does not contain a valid armor header,
// or a base64 decode error if the encapsulated portion is malformed.
func UnarmorBytes(data []byte) ([]byte, error) {
	text := string(data)
	lines := strings.Split(text, "\n")

	start := -1
	end := -1
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r\n\t ")
		if trimmed == armorHeader {
			start = i
		}
		if trimmed == armorFooter {
			end = i
			break
		}
	}

	if start == -1 || end == -1 || end <= start {
		return nil, ErrNotArmored
	}

	var b64Buf bytes.Buffer
	for _, line := range lines[start+1 : end] {
		trimmed := strings.TrimRight(line, "\r\n\t ")
		b64Buf.WriteString(trimmed)
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(b64Buf.Len()))
	n, err := base64.StdEncoding.Decode(decoded, b64Buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cipherlock: base64 decode: %w", err)
	}

	return decoded[:n], nil
}

// IsArmored reports whether data begins with a cipherlock armor header.
func IsArmored(data []byte) bool {
	text := string(data)
	lines := strings.SplitN(text, "\n", 2)
	if len(lines) == 0 {
		return false
	}
	return strings.TrimRight(lines[0], "\r\n\t ") == armorHeader
}

// IsArmoredReader peeks at the reader to determine if the stream starts with an armor header.
// It returns the result along with a new reader that includes the peeked bytes.
func IsArmoredReader(r io.Reader) (bool, io.Reader, error) {
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, r, int64(len(MagicArmorHeader)))
	if err != nil && err != io.EOF {
		return false, nil, err
	}
	combined := io.MultiReader(&buf, r)
	return IsArmored(buf.Bytes()), combined, nil
}

// lineWriter wraps an io.Writer and breaks its output into
// armorLineLen-character lines, terminated by '\n'. Used internally by
// NewArmorWriter to convert base64.NewEncoder's arbitrary-sized output
// into the line-wrapped format.
type lineWriter struct {
	w   io.Writer
	buf []byte
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	lw.buf = append(lw.buf, p...)
	for len(lw.buf) >= armorLineLen {
		if _, err := fmt.Fprintln(lw.w, string(lw.buf[:armorLineLen])); err != nil {
			return 0, err
		}
		lw.buf = lw.buf[armorLineLen:]
	}
	return n, nil
}

func (lw *lineWriter) Flush() error {
	if len(lw.buf) > 0 {
		if _, err := fmt.Fprintln(lw.w, string(lw.buf)); err != nil {
			return err
		}
		lw.buf = lw.buf[:0]
	}
	return nil
}

// NewArmorWriter returns a writer that base64-encodes anything written to
// it and emits the result on w as ASCII-armored cipherlock data (header,
// wrapped at armorLineLen-character lines, footer). Close must be called
// to flush the base64 encoder, emit the final partial line, and write the
// footer; callers should defer Close.
//
// The armor header is written on the first Write call (not on Close), so a
// partial output that never receives Close will have a header but no footer.
// Callers MUST call Close after checking the encrypt error to ensure the
// armor footer is present.
//
// The returned writer is not safe for concurrent use.
func NewArmorWriter(w io.Writer) io.WriteCloser {
	lw := &lineWriter{w: w, buf: make([]byte, 0, armorLineLen*2)}
	enc := base64.NewEncoder(base64.StdEncoding, lw)
	return &armorWriter{lw: lw, b64Enc: enc}
}

type armorWriter struct {
	lw         *lineWriter
	b64Enc     io.WriteCloser
	headerSent bool
	wroteBytes int64
	closed     bool
}

func (aw *armorWriter) Write(p []byte) (int, error) {
	if aw.closed {
		return 0, errors.New("cipherlock: write to closed ArmorWriter")
	}
	if !aw.headerSent {
		if _, err := fmt.Fprintln(aw.lw.w, armorHeader); err != nil {
			return 0, err
		}
		aw.headerSent = true
	}
	n, err := aw.b64Enc.Write(p)
	aw.wroteBytes += int64(n)
	return n, err
}

func (aw *armorWriter) Close() error {
	if aw.closed {
		return nil
	}
	aw.closed = true
	if !aw.headerSent {
		if _, err := fmt.Fprintln(aw.lw.w, armorHeader); err != nil {
			return err
		}
		aw.headerSent = true
	}
	if err := aw.b64Enc.Close(); err != nil {
		return err
	}
	if err := aw.lw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(aw.lw.w, armorFooter)
	return err
}

// BytesWritten reports the total number of plaintext bytes that have been
// fed to Write. Useful for progress reporting alongside an io.Copy loop.
func (aw *armorWriter) BytesWritten() int64 {
	return aw.wroteBytes
}

// NewUnarmorReader returns an io.Reader that decodes ASCII-armored
// cipherlock data on the fly. It scans r for the armorHeader, then
// base64-decodes each subsequent line, and stops at armorFooter.
//
// Use NewUnarmorReader to pipe an armored source directly into a
// streaming Decrypt path without buffering the full plaintext in memory.
// If the input does not begin with armorHeader, NewUnarmorReader returns
// the original reader unchanged so callers can transparently handle both
// armored and raw inputs.
//
// The returned reader is not safe for concurrent reads.
func NewUnarmorReader(r io.Reader) (io.Reader, error) {
	// Peek the first line up to and including '\n' to decide whether r
	// is armored. The peeked bytes are preserved in the returned reader.
	br := bufio.NewReader(r)
	firstLine, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	trimmed := strings.TrimRight(firstLine, "\r\n\t ")
	if trimmed != armorHeader {
		// Not armored: replay the consumed line in front of the rest.
		return &prefixedReader{prefix: []byte(firstLine), src: br}, nil
	}
	return &unarmorReader{br: br}, nil
}

type prefixedReader struct {
	prefix []byte
	src    io.Reader
}

func (pr *prefixedReader) Read(p []byte) (int, error) {
	if len(pr.prefix) > 0 {
		n := copy(p, pr.prefix)
		pr.prefix = pr.prefix[n:]
		return n, nil
	}
	return pr.src.Read(p)
}

type unarmorReader struct {
	br     *bufio.Reader
	footer bool
	// decodedBuf holds whatever is left of the in-progress base64 decode.
	decodedBuf []byte
	// decodedPos is the read cursor into decodedBuf.
	decodedPos int
}

func (u *unarmorReader) Read(p []byte) (int, error) {
	for {
		if u.footer {
			return 0, io.EOF
		}
		// Drain any pending decoded bytes first.
		if u.decodedPos < len(u.decodedBuf) {
			n := copy(p, u.decodedBuf[u.decodedPos:])
			u.decodedPos += n
			return n, nil
		}

		// Read the next line. If the line is the footer, we're done.
		line, err := u.br.ReadString('\n')
		if err != nil && err != io.EOF {
			return 0, err
		}
		if err == io.EOF && len(line) == 0 {
			u.footer = true
			return 0, io.ErrUnexpectedEOF
		}
		trimmed := strings.TrimRight(line, "\r\n\t ")
		if trimmed == armorFooter {
			u.footer = true
			return 0, io.EOF
		}
		if trimmed == "" {
			// Blank line: skip and continue the loop.
			continue
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
		n, decErr := base64.StdEncoding.Decode(decoded, []byte(trimmed))
		if decErr != nil {
			return 0, fmt.Errorf("cipherlock: base64 decode: %w", decErr)
		}
		u.decodedBuf = decoded[:n]
		u.decodedPos = 0
		continue
	}
}
