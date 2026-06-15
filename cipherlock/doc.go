/*
Package cipherlock implements AES-256-GCM encryption with Argon2id key derivation.

# FORMAT

All versions share a 4-byte magic prefix "CV2\0" followed by a version byte.
Unless otherwise noted, multi-byte integers are little-endian.

V2/V3 (single-recipient, non-streaming)

	4 bytes   Magic: "CV2\0"
	1 byte    Version: 0x02 or 0x03
	1 byte    Flags (v0x03 only): bit 0 = checksum present
	2 bytes   Salt length
	N bytes   Argon2id salt
	4 bytes   Argon2 time
	4 bytes   Argon2 memory
	1 byte    Argon2 threads
	4 bytes   Key length
	12 bytes  AES-GCM nonce
	[32 bytes SHA-256 checksum (v0x03, when flags bit 0 set)]
	Variable  Ciphertext + 16-byte GCM tag

V4 (multi-recipient, non-streaming)

	4 bytes   Magic: "CV2\0"
	1 byte    Version: 0x04
	1 byte    Flags: bit 0 = checksum present
	4 bytes   Number of recipients
	For each recipient:
	  2 bytes  Salt length
	  N bytes  Argon2id salt
	  4 bytes  Time
	  4 bytes  Memory
	  1 byte   Threads
	  4 bytes  Key length
	  12 bytes Nonce for key encryption
	  2 bytes  Sealed key length
	  M bytes  Encrypted file key + GCM tag
	12 bytes   File nonce
	[32 bytes SHA-256 checksum (when flags bit 0 set)]
	Variable  Ciphertext + GCM tag

The plaintext is buffered in memory — use V7 for large files.

V5 (streaming, cleartext metadata)

	4 bytes   Magic: "CV2\0"
	1 byte    Version: 0x05
	1 byte    Flags: bit 0 = checksum present
	2 bytes   Salt length
	N bytes   Argon2id salt
	4 bytes   Time
	4 bytes   Memory
	1 byte    Threads
	4 bytes   Key length
	4 bytes   Chunk size
	1 byte    Has metadata (0/1)
	[If metadata:]
	  2 bytes  Filename length
	  M bytes  Filename (UTF-8)
	  8 bytes  File size
	  8 bytes  Modification time (Unix nanosecond)
	[32 bytes SHA-256 checksum (trailer, when flags bit 0 set)]

	Zero or more data chunks:
	  12 bytes  Nonce
	  4 bytes   Ciphertext + GCM tag length (0 = end of stream)
	  N bytes   Ciphertext + 16-byte GCM tag

	4 zero bytes (end marker)

V6 (streaming, encrypted metadata)

	4 bytes   Magic: "CV2\0"
	1 byte    Version: 0x06
	1 byte    Flags: bit 0 = checksum present, bit 1 = has metadata
	2 bytes   Salt length
	N bytes   Argon2id salt
	4 bytes   Time
	4 bytes   Memory
	1 byte    Threads
	4 bytes   Key length
	4 bytes   Chunk size

	[Optional encrypted metadata chunk, when flags bit 1 set:]
	  12 bytes  Nonce
	  4 bytes   Ciphertext length
	  M bytes   Ciphertext + GCM tag (decrypts to: nameLen(2)+name+size(8)+mtime(8))

	Zero or more data chunks — same as V5.
	4 zero bytes (end marker)
	[32 bytes SHA-256 checksum trailer, when flags bit 0 set]

Metadata is encrypted under the same key as the data so filename and size
are not visible without the password. EncryptStreamV2 selects this format
automatically when FileMeta is provided.

V7 (streaming, multi-recipient)

	4 bytes   Magic: "CV2\0"
	1 byte    Version: 0x07
	1 byte    Flags: bit 0 = checksum present, bit 1 = has metadata
	4 bytes   Number of recipients
	For each recipient:
	  2 bytes  Salt length
	  N bytes  Argon2id salt
	  4 bytes  Time
	  4 bytes  Memory
	  1 byte   Threads
	  4 bytes  Key length
	  12 bytes Nonce for key encryption
	  2 bytes  Sealed key length
	  M bytes  Encrypted file key + GCM tag

	[Optional encrypted metadata chunk — same layout as V6]
	Zero or more data chunks — same as V5.
	4 zero bytes (end marker)
	[32 bytes SHA-256 checksum trailer, when flags bit 0 set]

A fresh random file key encrypts the data and metadata chunk. The file key
is sealed once per recipient with their derived key. This is the streaming
replacement for V4 — use EncryptStreamMulti / DecryptStreamMulti.

V8 (asymmetric, X25519)

	4 bytes   Magic: "CV2\0"
	1 byte    Version: 0x08
	1 byte    Flags: bit 0 = checksum present, bit 1 = has metadata
	4 bytes   Number of X25519 recipients
	For each recipient:
	  1 byte   Identity type (0x01 = X25519)
	  32 bytes Ephemeral X25519 public key
	  12 bytes Nonce for key sealing
	  48 bytes Sealed file key (AES-256-GCM, ciphertext + 16-byte tag)

	[Optional encrypted metadata chunk — same layout as V6]
	Zero or more data chunks — same as V5.
	4 zero bytes (end marker)
	[32 bytes SHA-256 checksum trailer, when flags bit 0 set]

Uses ECDH + HKDF-SHA256 for key agreement. Use --recipient-pubkey (CLI)
or EncryptAsymmetric / DecryptAsymmetric (library).

# ASCII-armor

When --armor is used, the binary format is base64-encoded with PEM-style
delimiters:

	-----BEGIN CIPHERLOCK-----
	<base64, wrapped at 64 columns>
	-----END CIPHERLOCK-----

Decrypt detects armor automatically.
*/
package cipherlock
