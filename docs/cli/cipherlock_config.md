## cipherlock config

Manage configuration profiles

### Options

```
  -h, --help   help for config
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
* [cipherlock config list-profiles](cipherlock_config_list-profiles.md)	 - List all saved configuration profiles
* [cipherlock config remove-profile](cipherlock_config_remove-profile.md)	 - Remove a configuration profile
* [cipherlock config set-profile](cipherlock_config_set-profile.md)	 - Create or update a configuration profile

