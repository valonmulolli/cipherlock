package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var genkeyDir string
var genkeyPassphraseFile string

var genKeyCmd = &cobra.Command{
	Use:   "dial <name>",
	Short: "Generate an X25519 encryption key pair",
	Long: `Generate a new X25519 key pair for asymmetric encryption.

The identity (private key) is saved to a file that can be used with
--identity on the decrypt command. The public key is saved alongside
it and can be shared with anyone who needs to encrypt files for you.

Use --recipient-pubkey <pubkey-file> with the encrypt command and
--identity <identity-file> with the decrypt command.

Keys are written to the current directory as:
  <name>.identity   (private key, armored)
  <name>.pub        (public key, base64)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := cipherlock.GenerateX25519Keypair()
		if err != nil {
			return fmt.Errorf("generating key pair: %w", err)
		}

		// Use the name argument as the base (may include a directory path).
		// --output-dir overrides just the directory portion.
		base := args[0]
		if genkeyDir != "" {
			// --output-dir sets the directory; args[0] is just the filename stem.
			base = filepath.Join(genkeyDir, filepath.Base(args[0]))
		}
		if err := os.MkdirAll(filepath.Dir(base), 0700); err != nil {
			return err
		}
		identityPath := base + ".identity"
		pubPath := base + ".pub"

		var passphrase []byte
		if genkeyPassphraseFile != "" {
			p, err := os.ReadFile(genkeyPassphraseFile)
			if err != nil {
				return fmt.Errorf("reading passphrase file: %w", err)
			}
			passphrase = bytes.TrimRight(p, "\n\r")
			defer clear(passphrase)
		}

		pubEncoded := base64.StdEncoding.EncodeToString(id.PublicKey)
		if _, err := os.Stat(pubPath); err == nil {
			return fmt.Errorf("output %q exists", pubPath)
		}

		serialized, err := cipherlock.SerializeX25519Identity(id, passphrase)
		if err != nil {
			return fmt.Errorf("serializing identity: %w", err)
		}

		f, err := os.OpenFile(identityPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("output %q exists", identityPath)
			}
			return fmt.Errorf("writing identity: %w", err)
		}
		if _, err := f.Write(serialized); err != nil {
			f.Close()
			return fmt.Errorf("writing identity: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("writing identity: %w", err)
		}

		if err := os.WriteFile(pubPath, []byte(pubEncoded+"\n"), 0644); err != nil {
			return fmt.Errorf("writing public key: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Identity (private key): %s\n", identityPath)
		fmt.Fprintf(os.Stderr, "Public key: %s\n", pubPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(genKeyCmd)
	genKeyCmd.Flags().StringVar(&genkeyDir, "output-dir", "", "directory to write key files (default: current directory)")
	genKeyCmd.Flags().StringVar(&genkeyPassphraseFile, "passphrase-file", "", "read passphrase from file to encrypt the identity key")
}
