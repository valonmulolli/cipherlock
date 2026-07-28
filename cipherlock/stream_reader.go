package cipherlock

import (
	"io"
)

// EncryptReader reads plaintext from a source and produces encrypted ciphertext
// on demand. It is an io.ReadCloser wrapping an encryption stream.
type EncryptReader struct {
	io.ReadCloser
}

// NewEncryptReader returns an EncryptReader that reads plaintext from src and
// produces encrypted ciphertext. The underlying encryption runs in a separate
// goroutine; errors are surfaced on the next Read call after they occur.
//
// Close the reader to abort encryption early. The returned reader is safe for
// use with io.Copy, http.Post, or any io.Reader consumer.
//
// Example:
//
//	f, _ := os.Open("secret.txt")
//	enc := cipherlock.NewEncryptReader(f, password, config)
//	defer enc.Close()
//	http.Post("https://example.com/upload", "application/octet-stream", enc)
func NewEncryptReader(src io.Reader, password []byte, config *Config) *EncryptReader {
	pr, pw := io.Pipe()
	go func() {
		err := EncryptStream(pw, src, password, config)
		pw.CloseWithError(err)
	}()
	return &EncryptReader{ReadCloser: pr}
}

// DecryptReader reads encrypted ciphertext from a source and produces plaintext
// on demand. It is an io.ReadCloser wrapping a decryption stream.
type DecryptReader struct {
	io.ReadCloser
}

// NewDecryptReader returns a DecryptReader that reads ciphertext from src and
// produces decrypted plaintext. The underlying decryption runs in a separate
// goroutine; errors are surfaced on the next Read call after they occur.
//
// Close the reader to abort decryption early. The returned reader is safe for
// use with io.Copy, io.TeeReader, or any io.Reader consumer.
//
// Example:
//
//	resp, _ := http.Get("https://example.com/secret.cipherlock")
//	defer resp.Body.Close()
//	dec := cipherlock.NewDecryptReader(resp.Body, password)
//	defer dec.Close()
//	io.Copy(os.Stdout, dec)
func NewDecryptReader(src io.Reader, password []byte) *DecryptReader {
	pr, pw := io.Pipe()
	go func() {
		_, err := DecryptWithMeta(pw, src, password)
		pw.CloseWithError(err)
	}()
	return &DecryptReader{ReadCloser: pr}
}

// NewEncryptWriter returns an io.WriteCloser that encrypts plaintext written to
// it and writes the resulting ciphertext to dst. The underlying encryption runs
// in a separate goroutine; errors are surfaced on the next Write or Close call.
//
// Close the writer to flush any remaining data and finalize the encryption stream.
// The returned writer is safe for use with io.Copy, http.ResponseWriter, or any
// io.Writer consumer.
//
// Example:
//
//	f, _ := os.Create("out.cipherlock")
//	w := cipherlock.NewEncryptWriter(f, password, config)
//	io.Copy(w, plaintextFile)
//	w.Close()
func NewEncryptWriter(dst io.Writer, password []byte, config *Config) io.WriteCloser {
	pr, pw := io.Pipe()
	go func() {
		err := EncryptStream(dst, pr, password, config)
		pw.CloseWithError(err)
	}()
	return pw
}

// NewDecryptWriter returns an io.WriteCloser that decrypts ciphertext written to
// it and writes the resulting plaintext to dst. The underlying decryption runs
// in a separate goroutine; errors are surfaced on the next Write or Close call.
//
// Close the writer to signal the end of ciphertext input and finalize the
// decryption stream. The returned writer is safe for use with io.Copy or any
// io.Writer consumer.
//
// Example:
//
//	f, _ := os.Open("secret.cipherlock")
//	var plain bytes.Buffer
//	w := cipherlock.NewDecryptWriter(&plain, password)
//	io.Copy(w, f)
//	w.Close()
func NewDecryptWriter(dst io.Writer, password []byte) io.WriteCloser {
	pr, pw := io.Pipe()
	go func() {
		_, err := DecryptWithMeta(dst, pr, password)
		pw.CloseWithError(err)
	}()
	return pw
}

