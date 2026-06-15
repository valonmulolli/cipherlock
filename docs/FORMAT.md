# File format

cipherlock uses a self-describing binary format with versioned headers:

### V2/V3 (single-recipient)

    4 bytes    Magic: "CV2\0"
    1 byte     Version: 0x02 or 0x03
    1 byte     Flags (v0x03 only): bit 0 = checksum present
    2 bytes    Salt length (little-endian)
    N bytes    Argon2id salt
    4 bytes    Argon2 time parameter (little-endian)
    4 bytes    Argon2 memory parameter (little-endian)
    1 byte     Argon2 threads parameter
    4 bytes    Key length (little-endian)
    12 bytes   AES-GCM nonce
    [32 bytes  SHA-256 checksum (v0x03 only, present when flags bit 0 set)]
    Variable   Ciphertext + GCM authentication tag (last 16 bytes)

### V4 (multi-recipient)

    4 bytes    Magic: "CV2\0"
    1 byte     Version: 0x04
    1 byte     Flags: bit 0 = checksum present
    4 bytes    Number of recipients (little-endian)
    For each recipient:
      2 bytes  Salt length (little-endian)
      N bytes  Argon2id salt
      4 bytes  Time parameter (little-endian)
      4 bytes  Memory parameter (little-endian)
      1 byte   Threads
      4 bytes  Key length (little-endian)
      12 bytes Nonce for key encryption
      2 bytes  Sealed key length (little-endian)
      M bytes  Encrypted file key + GCM tag
    12 bytes   File nonce
    [32 bytes  SHA-256 checksum (when flags bit 0 set)]
    Variable   Ciphertext + GCM authentication tag (last 16 bytes)

The ciphertext is encrypted with a random file key, which is then encrypted once per recipient. Each recipient independently derives their own key with Argon2id to decrypt the file key. The entire plaintext is buffered in memory before encryption — use V7 instead for large files.

### V5 (streaming)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x05
     1 byte     Flags: bit 0 = checksum present
     2 bytes    Salt length (little-endian)
     N bytes    Argon2id salt
     4 bytes    Time parameter (little-endian)
     4 bytes    Memory parameter (little-endian)
     1 byte     Threads parameter
     4 bytes    Key length (little-endian)
     4 bytes    Chunk size (plaintext bytes per chunk)
     1 byte     Has metadata (0 = no, 1 = yes)
     [If has metadata:]
       2 bytes  Filename length (little-endian)
       M bytes  Filename (UTF-8)
       8 bytes  File size (little-endian)
       8 bytes  Modification time (Unix nanosecond, little-endian)
     [32 bytes  SHA-256 checksum (trailer, when flags bit 0 set)]

     Zero or more data chunks:
       12 bytes  Nonce
       4 bytes   Ciphertext + GCM tag length (little-endian, 0 = end of stream)
       N bytes   Ciphertext + 16-byte GCM tag

     End of stream: 4 zero bytes in place of ciphertext length

The streaming format encrypts data incrementally in fixed-size chunks. Only one chunk is held in memory at a time. Each chunk uses a unique random nonce and is independently authenticated. The checksum (when enabled) is computed incrementally and stored as a trailer.

Metadata (filename, size, modtime) is stored in the cleartext header for zero-cost inspection without decryption. This means anyone with access to the encrypted file can see the original filename and size. To keep this metadata confidential, use v0x06 instead.

### V6 (streaming, encrypted metadata)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x06
     1 byte     Flags: bit 0 = checksum present, bit 1 = has metadata
     2 bytes    Salt length
     N bytes    Argon2id salt
     4 bytes    Time
     4 bytes    Memory
     1 byte     Threads
     4 bytes    Key length
     4 bytes    Chunk size

     [Optional encrypted metadata chunk, when flags bit 1 is set:]
       12 bytes  Nonce
       4 bytes   Ciphertext + GCM tag length
       M bytes   Ciphertext + 16-byte GCM tag (decrypts to: filenameLen(2) + name + size(8) + modtime(8))

     Zero or more data chunks: same as v0x05

     End of stream: 4 zero bytes
     [Optional 32-byte SHA-256 checksum trailer, when flags bit 0 is set]

Identical to v0x05 except the optional metadata is encrypted under the same key as the data, so the original filename and size are not visible without the password. Use `EncryptStreamV2` / `DecryptStreamV2` from the library, or the `cipherlock` CLI which auto-selects this format when the source has metadata.

### V7 (streaming, multi-recipient)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x07
     1 byte     Flags: bit 0 = checksum present, bit 1 = has metadata
     4 bytes    Number of recipients (little-endian)
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

     [Optional encrypted metadata chunk, when flags bit 1 is set:]
       12 bytes  Nonce
       4 bytes   Ciphertext length
       M bytes   Encrypted metadata (filename + size + modtime)

     Zero or more data chunks: each chunk is encrypted with the shared file key
       12 bytes  Nonce
       4 bytes   Ciphertext length (0 = end)
       N bytes   Ciphertext + 16-byte GCM tag

     End of stream: 4 zero bytes
     [Optional 32-byte SHA-256 checksum trailer, when flags bit 0 is set]

A fresh random file key encrypts the data (and optional metadata chunk). The file key is then sealed once per recipient using their derived key. This is the streaming replacement for the legacy v0x04 `EncryptMulti` and supports arbitrarily large files without buffering the plaintext. Use `EncryptStreamMulti` / `DecryptStreamMulti` from the library, or the `cipherlock` CLI which auto-selects this format when `--recipient` is given more than once.

### V8 (asymmetric, X25519)

     4 bytes    Magic: "CV2\0"
     1 byte     Version: 0x08
     1 byte     Flags: bit 0 = checksum present, bit 1 = has metadata
     4 bytes    Number of X25519 recipients (little-endian)
     For each recipient:
       1 byte   Identity type (0x01 = X25519)
       32 bytes Ephemeral X25519 public key
       12 bytes Nonce for key sealing
       48 bytes Sealed file key (AES-256-GCM, ciphertext + 16-byte tag)

     [Optional encrypted metadata chunk, when flags bit 1 is set:]
       12 bytes  Nonce
       4 bytes   Ciphertext length
       M bytes   Encrypted metadata (filename + size + modtime)

     Zero or more data chunks: encrypted with the shared file key
       12 bytes  Nonce
       4 bytes   Ciphertext length (0 = end)
       N bytes   Ciphertext + 16-byte GCM tag

     End of stream: 4 zero bytes
     [Optional 32-byte SHA-256 checksum trailer, when flags bit 0 is set]

A random 32-byte file key encrypts the data. For each recipient, an ephemeral X25519 key pair is generated, ECDH produces a shared secret, HKDF-SHA256 derives a wrapping key, and AES-256-GCM seals the file key. This mirrors the v0x07 multi-recipient model but uses asymmetric keys instead of passwords.

Use the CLI with `--recipient-pubkey` or the library via `EncryptAsymmetric` / `DecryptAsymmetric`.

### ASCII-armor format

When using `--armor`, the binary format above is wrapped in base64 encoding with PEM-style delimiters:

    -----BEGIN CIPHERLOCK-----
    <base64-encoded ciphertext, wrapped at 64 columns>
    -----END CIPHERLOCK-----

The armored format is self-identifying -- decrypt detects it automatically by reading the header line.
