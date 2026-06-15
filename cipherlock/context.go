// WARNING: KDF CANNOT BE CANCELLED.
//
// All *Context functions spawn a goroutine that runs the full Argon2id key
// derivation to completion, even when ctx is cancelled. The goroutine is
// "leaked" until KDF finishes — it cannot be interrupted.
//
// This means:
//   - A cancelled context does NOT speed up a running KDF.
//   - Memory and CPU for Argon2id are fully consumed regardless of ctx.
//   - Only the subsequent encrypt/decrypt phases (AES-GCM) can be cancelled.
//
// If you need to bound KDF runtime, adjust Config.Time, Config.Memory, or
// set a deadline on ctx *before* calling KDF.
package cipherlock

import (
	"context"
	"io"
)

// cancellableReader wraps an io.Reader and checks ctx.Err() before each
// Read call. When the context is cancelled, Read returns ctx.Err()
// immediately instead of blocking on the underlying reader. This allows
// streaming encrypt/decrypt loops to terminate promptly.
type cancellableReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *cancellableReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}

func withCancel(ctx context.Context, src io.Reader) io.Reader {
	return &cancellableReader{ctx: ctx, r: src}
}

type result struct {
	meta *FileMeta
	err  error
}

// EncryptContext is a context-aware wrapper around Encrypt.
// It cancels encryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled. Only the AES-GCM encrypt phase can be cancelled early.
func EncryptContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- Encrypt(dst, withCancel(ctx, src), password, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DecryptContext is a context-aware wrapper around Decrypt.
// It cancels decryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte) error {
	done := make(chan error, 1)
	go func() {
		done <- Decrypt(dst, withCancel(ctx, src), password)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// EncryptStreamContext is a context-aware wrapper around EncryptStream.
// It cancels stream encryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func EncryptStreamContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- EncryptStream(dst, withCancel(ctx, src), password, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DecryptStreamContext is a context-aware wrapper around DecryptStream.
// It cancels stream decryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptStreamContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte) error {
	done := make(chan error, 1)
	go func() {
		done <- DecryptStream(dst, withCancel(ctx, src), password)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// EncryptMultiContext is a context-aware wrapper around EncryptMulti.
// It cancels multi-key encryption if the context is done before completion.
//
// Deprecated: EncryptMulti (and this wrapper) is retained only for v0x04
// backward compatibility. New code should use EncryptStreamMulti (v0x07).
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func EncryptMultiContext(ctx context.Context, dst io.Writer, src io.Reader, passwords [][]byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- EncryptMulti(dst, withCancel(ctx, src), passwords, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// EncryptStreamV2Context is a context-aware wrapper around EncryptStreamV2.
// It cancels v0x06 streaming encryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func EncryptStreamV2Context(ctx context.Context, dst io.Writer, src io.Reader, password []byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- EncryptStreamV2(dst, withCancel(ctx, src), password, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DecryptStreamV2Context is a context-aware wrapper around DecryptStreamV2.
// It cancels v0x06 streaming decryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptStreamV2Context(ctx context.Context, dst io.Writer, src io.Reader, password []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := DecryptStreamV2(dst, withCancel(ctx, src), password)
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// EncryptStreamMultiContext is a context-aware wrapper around EncryptStreamMulti.
// It cancels v0x07 streaming multi-recipient encryption if the context is done
// before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func EncryptStreamMultiContext(ctx context.Context, dst io.Writer, src io.Reader, passwords [][]byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- EncryptStreamMulti(dst, withCancel(ctx, src), passwords, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DecryptWithMetaContext is a context-aware wrapper around DecryptWithMeta.
// It cancels decryption if the context is done before completion and returns
// the FileMeta (if present, v0x06/v0x07 only) alongside the decrypt error.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptWithMetaContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte) (*FileMeta, error) {
	done := make(chan result, 1)
	go func() {
		meta, err := DecryptWithMeta(dst, withCancel(ctx, src), password)
		done <- result{meta: meta, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		return r.meta, r.err
	}
}

// DecryptStreamMultiContext is a context-aware wrapper around the v0x07 streaming
// multi-recipient decrypt path. Metadata is always returned via
// ReadStreamMetaWithPassword when needed.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptStreamMultiContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := DecryptStreamMultiFromReader(dst, withCancel(ctx, src), password)
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// ReKeyContext is a context-aware wrapper around ReKey.
// It cancels streaming re-key if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func ReKeyContext(ctx context.Context, dst io.Writer, src io.Reader, oldPassword, newPassword []byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- ReKey(dst, withCancel(ctx, src), oldPassword, newPassword, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// EncryptDirContext is a context-aware wrapper around EncryptDir.
// It cancels directory encryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func EncryptDirContext(ctx context.Context, source, dest string, password []byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- EncryptDir(source, dest, password, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DecryptDirContext is a context-aware wrapper around DecryptDir.
// It cancels directory decryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptDirContext(ctx context.Context, source, dest string, password []byte) error {
	done := make(chan error, 1)
	go func() {
		done <- DecryptDir(source, dest, password)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
