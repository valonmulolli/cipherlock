package cipherlock

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestGenerateX25519Keypair(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair: %v", err)
	}
	if len(id.PrivateKey) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(id.PrivateKey))
	}
	if len(id.PublicKey) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(id.PublicKey))
	}
}

func TestX25519IdentityFromPrivateKey(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	id, err := X25519IdentityFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("X25519IdentityFromPrivateKey: %v", err)
	}
	if !bytes.Equal(id.PrivateKey, priv) {
		t.Fatal("private key mismatch")
	}
}

func TestEncryptDecryptAsymmetric(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	recipient, err := NewX25519Recipient(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello asymmetric world")
	var encrypted bytes.Buffer
	err = EncryptAsymmetric(&encrypted, bytes.NewReader(plaintext), []*X25519Recipient{recipient}, nil)
	if err != nil {
		t.Fatalf("EncryptAsymmetric: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptAsymmetric(&decrypted, &encrypted, id)
	if err != nil {
		t.Fatalf("DecryptAsymmetric: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted.Bytes(), plaintext)
	}
}

func TestEncryptAsymmetricMultipleRecipients(t *testing.T) {
	alice, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	aliceRec, _ := NewX25519Recipient(alice.PublicKey)
	bobRec, _ := NewX25519Recipient(bob.PublicKey)

	plaintext := []byte("multi-recipient asymmetric test")
	var encrypted bytes.Buffer
	err = EncryptAsymmetric(&encrypted, bytes.NewReader(plaintext), []*X25519Recipient{aliceRec, bobRec}, nil)
	if err != nil {
		t.Fatalf("EncryptAsymmetric: %v", err)
	}

	for name, id := range map[string]*X25519Identity{"alice": alice, "bob": bob} {
		var decrypted bytes.Buffer
		err := DecryptAsymmetric(&decrypted, bytes.NewReader(encrypted.Bytes()), id)
		if err != nil {
			t.Fatalf("%s DecryptAsymmetric: %v", name, err)
		}
		if !bytes.Equal(plaintext, decrypted.Bytes()) {
			t.Fatalf("%s round-trip mismatch", name)
		}
	}
}

func TestDecryptAsymmetricWrongIdentity(t *testing.T) {
	alice, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	eve, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	aliceRec, _ := NewX25519Recipient(alice.PublicKey)

	plaintext := []byte("secret for alice only")
	var encrypted bytes.Buffer
	err = EncryptAsymmetric(&encrypted, bytes.NewReader(plaintext), []*X25519Recipient{aliceRec}, nil)
	if err != nil {
		t.Fatalf("EncryptAsymmetric: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptAsymmetric(&decrypted, &encrypted, eve)
	if err == nil {
		t.Fatal("expected ErrAuthFailed, got nil")
	}
}

func TestEncryptAsymmetricNoRecipients(t *testing.T) {
	err := EncryptAsymmetric(nil, nil, []*X25519Recipient{}, nil)
	if err != ErrAtLeastOnePassword {
		t.Fatalf("expected ErrAtLeastOnePassword, got %v", err)
	}
}

func TestNewX25519RecipientInvalidKey(t *testing.T) {
	_, err := NewX25519Recipient([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestX25519IdentityFromInvalidKey(t *testing.T) {
	_, err := X25519IdentityFromPrivateKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestEncryptAsymmetricWithChecksum(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := NewX25519Recipient(id.PublicKey)

	cfg := *DefaultConfig
	cfg.Checksum = true

	plaintext := []byte("asymmetric with checksum")
	var encrypted bytes.Buffer
	err = EncryptAsymmetric(&encrypted, bytes.NewReader(plaintext), []*X25519Recipient{rec}, &cfg)
	if err != nil {
		t.Fatalf("EncryptAsymmetric: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptAsymmetric(&decrypted, &encrypted, id)
	if err != nil {
		t.Fatalf("DecryptAsymmetric: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestSerializeDeserializeIdentity(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := SerializeX25519Identity(id, nil)
	if err != nil {
		t.Fatalf("SerializeX25519Identity: %v", err)
	}

	deserialized, err := DeserializeX25519Identity(serialized, nil)
	if err != nil {
		t.Fatalf("DeserializeX25519Identity: %v", err)
	}

	if !bytes.Equal(id.PrivateKey, deserialized.PrivateKey) {
		t.Fatal("private key mismatch after serialize/deserialize")
	}
	if !bytes.Equal(id.PublicKey, deserialized.PublicKey) {
		t.Fatal("public key mismatch after serialize/deserialize")
	}
}

func TestSerializeDeserializeIdentityWithPassphrase(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("hunter2")

	serialized, err := SerializeX25519Identity(id, passphrase)
	if err != nil {
		t.Fatalf("SerializeX25519Identity with passphrase: %v", err)
	}

	deserialized, err := DeserializeX25519Identity(serialized, nil)
	if !errors.Is(err, ErrIdentityNeedsPassphrase) {
		t.Fatalf("expected ErrIdentityNeedsPassphrase, got %v", err)
	}

	deserialized, err = DeserializeX25519Identity(serialized, passphrase)
	if err != nil {
		t.Fatalf("DeserializeX25519Identity with passphrase: %v", err)
	}

	if !bytes.Equal(id.PrivateKey, deserialized.PrivateKey) {
		t.Fatal("private key mismatch after encrypted serialize/deserialize")
	}
	if !bytes.Equal(id.PublicKey, deserialized.PublicKey) {
		t.Fatal("public key mismatch after encrypted serialize/deserialize")
	}

	_, err = DeserializeX25519Identity(serialized, []byte("wrong-passphrase"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed for wrong passphrase, got %v", err)
	}
}

func TestEncryptAsymmetricEmpty(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := NewX25519Recipient(id.PublicKey)

	var encrypted bytes.Buffer
	err = EncryptAsymmetric(&encrypted, bytes.NewReader(nil), []*X25519Recipient{rec}, nil)
	if err != nil {
		t.Fatalf("EncryptAsymmetric empty: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptAsymmetric(&decrypted, &encrypted, id)
	if err != nil {
		t.Fatalf("DecryptAsymmetric empty: %v", err)
	}

	if len(decrypted.Bytes()) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(decrypted.Bytes()))
	}
}

func TestEncryptAsymmetricLarge(t *testing.T) {
	id, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := NewX25519Recipient(id.PublicKey)

	plaintext := make([]byte, 256*1024+1)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var encrypted bytes.Buffer
	err = EncryptAsymmetric(&encrypted, bytes.NewReader(plaintext), []*X25519Recipient{rec}, nil)
	if err != nil {
		t.Fatalf("EncryptAsymmetric large: %v", err)
	}

	var decrypted bytes.Buffer
	err = DecryptAsymmetric(&decrypted, &encrypted, id)
	if err != nil {
		t.Fatalf("DecryptAsymmetric large: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Fatal("round-trip mismatch for large data")
	}
}
