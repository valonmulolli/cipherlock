## cipherlock encrypt

Encrypt a file or directory

### Synopsis

Encrypt one or more files, or a single directory.

If <path> is a regular file, it is encrypted with AES-256-GCM.
If <path> is a directory, it is archived (tar+gzip) before encryption.
If multiple paths are given, they are all encrypted with the same password.

If no output path is specified, the encrypted output is written to
<path>.encrypted for files or <path>.cipherlock for directories.
Use --out-dir to write all outputs to a specific directory.
Use --in-place to overwrite the source after successful encryption.
Use --gen-password to generate a cryptographically random password.

When <path> is "-", read from stdin and write encrypted data to stdout.

```
cipherlock encrypt [flags] <path> [<path>...]
```

### Options

```
      --armor                          encode output in base64 ASCII-armor format
      --checksum                       embed SHA-256 checksum of plaintext and verify on decrypt
      --compress                       compress data with zstd before encryption
      --force                          overwrite existing output files without prompting
      --gen-password                   generate a random password and print it to stderr
  -h, --help                           help for encrypt
  -j, --jobs int                       number of parallel jobs (default: sequential)
      --key-file string                read password from file instead of prompting
      --keychain                       read password from system keychain
      --memory uint32                  Argon2id memory in KB (overrides profile)
      --out-dir string                 output directory for batch encryption
  -o, --output string                  output file path
      --password-env string            read password from environment variable
      --password-fd string             read password from file descriptor number (e.g. 0 for stdin pipe)
      --password-stdin                 read password from stdin
      --profile string                 use a saved configuration profile
      --recipient stringArray          additional recipient password (can be specified multiple times)
      --recipient-pubkey stringArray   path to recipient's X25519 public key file (can be specified multiple times)
      --save-keychain                  save password to system keychain after encryption
      --threads uint8                  Argon2id parallelism (overrides profile)
      --time uint32                    Argon2id time parameter (overrides profile)
```

### Options inherited from parent commands

```
      --backup           save original with .bak extension before overwriting
      --color1 string    color for errors (default "#e3342f")
      --color2 string    color for text/labels (default "#22808c")
      --color3 string    color for spinner chars (default "#ffffff")
      --color4 string    color for filled bar (default "#32b8c6")
      --color5 string    color for empty bar (default "#d6d5d4")
      --color6 string    color for gradient B (default "#0f3639")
      --dry-run          simulate the operation without writing any files
      --exclude string   exclude files matching this glob pattern
      --in-place         overwrite the source file instead of creating a new one
      --include string   only process files matching this glob pattern
      --keep             keep the original file (opposite of --in-place)
      --quiet            suppress progress output
      --recursive        process directories recursively
```

### SEE ALSO

* [cipherlock](cipherlock.md)	 - AES-256-GCM file encryption with Argon2id key derivation

