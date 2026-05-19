package cipherlock

import (
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
	armorFooter = "-----END CIPHERLOCK-----"
	armorLineLen = 64
)

var (
	ErrNotArmored = errors.New("cipherlock: not an armored file")

	MagicArmorHeader = []byte(armorHeader)
)

// Armor writes data to w in ASCII-armor format (base64 encoded with header/footer lines).
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
func Unarmor(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return UnarmorBytes(data)
}

// UnarmorBytes decodes ASCII-armor encoded data and returns the original bytes.
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
