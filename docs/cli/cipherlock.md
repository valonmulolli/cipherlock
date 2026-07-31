## cipherlock

AES-256-GCM file encryption with Argon2id key derivation

### Synopsis

cipherlock encrypts and decrypts files using AES-256-GCM authenticated
encryption with Argon2id memory-hard key derivation.

It supports single files, entire directories, and stdin/stdout pipe mode.

### Options

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
  -h, --help             help for cipherlock
      --in-place         overwrite the source file instead of creating a new one
      --include string   only process files matching this glob pattern
      --keep             keep the original file (opposite of --in-place)
      --no-color         disable ANSI color output
      --quiet            suppress progress output
      --recursive        process directories recursively
```

### SEE ALSO

* [cipherlock bench](cipherlock_bench.md)	 - Benchmark Argon2id performance and recommend KDF parameters
* [cipherlock bombe](cipherlock_bombe.md)	 - Verify file integrity
* [cipherlock click](cipherlock_click.md)	 - Verify password and file integrity
* [cipherlock completion](cipherlock_completion.md)	 - Generate shell completion script
* [cipherlock config](cipherlock_config.md)	 - Manage configuration profiles
* [cipherlock decrypt](cipherlock_decrypt.md)	 - Decrypt a file
* [cipherlock dial](cipherlock_dial.md)	 - Generate an X25519 encryption key pair
* [cipherlock encrypt](cipherlock_encrypt.md)	 - Encrypt a file or directory
* [cipherlock gate](cipherlock_gate.md)	 - Time-gated file encryption
* [cipherlock key](cipherlock_key.md)	 - Manage encryption keys
* [cipherlock rotor](cipherlock_rotor.md)	 - Re-encrypt a file with a new password
* [cipherlock show-profile](cipherlock_show-profile.md)	 - Display a configuration profile
* [cipherlock shred](cipherlock_shred.md)	 - Securely delete files
* [cipherlock tumbler](cipherlock_tumbler.md)	 - Display encrypted file metadata
* [cipherlock version](cipherlock_version.md)	 - Print version information

