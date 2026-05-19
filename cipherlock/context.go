package cipherlock

import (
	"context"
	"io"
)

// EncryptContext is a context-aware wrapper around Encrypt.
// It cancels encryption if the context is done before completion.
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
