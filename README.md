# File Encryption

File Encryption is a Go package that provides a simple and secure way to encrypt and decrypt files using the AES-GCM encryption algorithm. This tool is designed to protect your sensitive data with strong encryption and minimal hassle.

## Features

- **Strong Encryption:** Utilizes the AES-GCM encryption algorithm to ensure robust security for your files.
- **Simple Usage:** Easy-to-use commands for both encryption and decryption processes.
- **Password Protection:** Encrypt and decrypt files with a password only you know.
- **Error Handling:** Provides improved error handling and graceful failure options.

## Installation

You can easily install the File Encryption package using Go modules:

```bash
  git clone https://github.com/valonmulolli/file-encryption.git
  cd file-encryption
```

### Encryption

```bash
# Encrypts a file
$ go run . encrypt gopher.png
```

### Decryption

```bash
# Decrypts a file
$ go run . decrypt gopher.png
```
