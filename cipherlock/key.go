package cipherlock

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadIdentity reads a private key file and returns the corresponding identity.

// LoadIdentity reads a private key file and returns the corresponding identity.
// It supports two formats:
//   - cipherlock armored identity files (*.identity) created by SerializeX25519Identity
//   - Ed25519 SSH private keys (e.g. ~/.ssh/id_ed25519)
//
// If the identity file is passphrase-protected, passphrase must be provided.
// For an SSH key with a passphrase, use IdentityFromSSHPrivateKey directly
// after decrypting the PEM block.
func LoadIdentity(path string, passphrase []byte) (*X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cipherlock: reading identity %q: %w", path, err)
	}

	// Try Ed25519 SSH private key first (fast path, no KDF).
	if identity, err := IdentityFromSSHPrivateKey(data); err == nil {
		return identity, nil
	}

	// Try cipherlock armored identity format.
	identity, err := DeserializeX25519Identity(data, passphrase)
	if err != nil {
		if errors.Is(err, ErrIdentityNeedsPassphrase) {
			return nil, fmt.Errorf("cipherlock: %q is passphrase-protected; provide a passphrase", path)
		}
		return nil, fmt.Errorf("cipherlock: unable to load identity from %q: %w", path, err)
	}
	return identity, nil
}

// LoadPublicKey reads a public key file and returns the corresponding recipient.
//
// The file must contain a base64-encoded X25519 public key (32 bytes),
// as produced by the cipherlock dial command (.pub files).
func LoadPublicKey(path string) (*X25519Recipient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cipherlock: reading public key %q: %w", path, err)
	}

	data = bytes.TrimSpace(data)
	pubKey := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(pubKey, data)
	if err != nil {
		return nil, fmt.Errorf("cipherlock: invalid public key in %q: not valid base64: %w", path, err)
	}

	return NewX25519Recipient(pubKey[:n])
}

// Fingerprint computes a human-readable SHA-256 fingerprint of a raw X25519 public key.
// The output is 32 hex bytes grouped in pairs separated by spaces, matching the format
// of the 'cipherlock key fingerprint' command (e.g. "A1B2 C3D4 E5F6 0718 ...").
//
// Use this to verify public keys out-of-band: share the fingerprint over a separate
// channel and compare visually.
func Fingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	var parts []string
	for i := 0; i < len(hash); i += 2 {
		parts = append(parts, fmt.Sprintf("%02X%02X", hash[i], hash[i+1]))
	}
	return strings.Join(parts, " ")
}
