## cipherlock gate encrypt

Encrypt a file with an expiration time

### Synopsis

Encrypt a file that can only be decrypted before the expiration time.

The expiration time is embedded in the encrypted file metadata.
Attempting to decrypt after the expiration will fail.

```
cipherlock gate encrypt [flags] <path>
```

### Options

```
      --checksum              enable integrity checksum
      --compress              compress data with zstd before encryption
      --expires-in string     duration until file expires (e.g. 24h, 168h, 30m)
      --force                 overwrite existing output file without prompting
      --gen-password          generate a random password
  -h, --help                  help for encrypt
      --output string         output file path
      --password-env string   read password from environment variable
      --password-fd string    read password from file descriptor number (e.g. 0 for stdin pipe)
      --password-stdin        read password from stdin
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

* [cipherlock gate](cipherlock_gate.md)	 - Time-gated file encryption

