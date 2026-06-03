package cipherlock

import (
	"context"
	"io"
)

// EncryptContext is a context-aware wrapper around Encrypt.
// It cancels encryption if the context is done before completion.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled. Only the AES-GCM encrypt phase can be cancelled early.
func EncryptContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte, config *Config) error {
	done := make(chan error, 1)
	go func() {
		done <- Encrypt(dst, src, password, config)
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
		done <- Decrypt(dst, src, password)
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
		done <- EncryptStream(dst, src, password, config)
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
		done <- DecryptStream(dst, src, password)
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
		done <- EncryptMulti(dst, src, passwords, config)
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
		done <- EncryptStreamV2(dst, src, password, config)
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
		_, err := DecryptStreamV2(dst, src, password)
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
		done <- EncryptStreamMulti(dst, src, passwords, config)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DecryptStreamMultiContext is a context-aware wrapper around the v0x07 streaming
// multi-recipient decrypt path. The meta argument is unused and kept for symmetry
// with other DecryptContext variants; metadata is always returned via
// ReadStreamMetaWithPassword when needed.
//
// NOTE: Context cancellation does not interrupt an in-progress Argon2id key
// derivation. The spawned goroutine runs the KDF to completion even after
// ctx is cancelled.
func DecryptStreamMultiContext(ctx context.Context, dst io.Writer, src io.Reader, password []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := DecryptStreamMultiFromReader(dst, src, password)
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
