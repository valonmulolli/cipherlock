## cipherlock gate

Time-gated file encryption

### Synopsis

Encrypt or decrypt files with time-based access control.

Encrypt a file with an expiration time. After the expiration, the file
can no longer be decrypted — the decryption will fail with an error

  cipherlock gate encrypt --expires-in 24h secret.txt
  cipherlock gate decrypt secret.cipherlock

### Options

```
  -h, --help   help for gate
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
      --no-color         disable ANSI color output
      --quiet            suppress progress output
      --recursive        process directories recursively
```

### SEE ALSO

* [cipherlock](cipherlock.md)	 - AES-256-GCM file encryption with Argon2id key derivation
* [cipherlock gate decrypt](cipherlock_gate_decrypt.md)	 - Decrypt a time-gated file
* [cipherlock gate encrypt](cipherlock_gate_encrypt.md)	 - Encrypt a file with an expiration time

