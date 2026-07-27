## cipherlock dial

Generate an X25519 encryption key pair

### Synopsis

Generate a new X25519 key pair for asymmetric encryption.

The identity (private key) is saved to a file that can be used with
--identity on the decrypt command. The public key is saved alongside
it and can be shared with anyone who needs to encrypt files for you.

Use --recipient-pubkey <pubkey-file> with the encrypt command and
--identity <identity-file> with the decrypt command.

Keys are written to the current directory as:
  <name>.identity   (private key, armored)
  <name>.pub        (public key, base64)

```
cipherlock dial <name> [flags]
```

### Options

```
  -h, --help                     help for dial
      --output-dir string        directory to write key files (default: current directory)
      --passphrase-file string   read passphrase from file to encrypt the identity key
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

