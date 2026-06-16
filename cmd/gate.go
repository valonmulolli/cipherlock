package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/valonmulolli/cipherlock/cipherlock"
)

var (
	gateExpiresIn string
)

var gateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Time-gated file encryption",
	Long: `Encrypt or decrypt files with time-based access control.

Encrypt a file with an expiration time. After the expiration, the file
can no longer be decrypted — the decryption will fail with an error

  cipherlock gate encrypt --expires-in 24h secret.txt
  cipherlock gate decrypt secret.cipherlock`,
}

var gateEncryptCmd = &cobra.Command{
	Use:   "encrypt [flags] <path>",
	Short: "Encrypt a file with an expiration time",
	Long: `Encrypt a file that can only be decrypted before the expiration time.

The expiration time is embedded in the encrypted file metadata.
Attempting to decrypt after the expiration will fail.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcPath := args[0]

		if gateExpiresIn == "" {
			return fmt.Errorf("--expires-in is required")
		}

		duration, err := time.ParseDuration(gateExpiresIn)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", gateExpiresIn, err)
		}

		dest := srcPath + ".cipherlock"

		info, err := os.Stat(srcPath)
		if err != nil {
			return err
		}

		password, err := resolvePassword(passwordSource{
			FD: passwordFD, Env: passwordEnv, KeyFile: keyFilePath,
			Stdin: passwordStdin, GenPwd: genPassword, Label: "Enter password: ",
		})
		if err != nil {
			return err
		}
		showStrength(password)

		config := &cipherlock.Config{
			SaltLen:  cipherlock.DefaultConfig.SaltLen,
			Time:     cipherlock.DefaultConfig.Time,
			Memory:   cipherlock.DefaultConfig.Memory,
			Threads:  cipherlock.DefaultConfig.Threads,
			KeyLen:   cipherlock.DefaultConfig.KeyLen,
			Checksum: checksumFlag,
			FileMeta: &cipherlock.FileMeta{
				Name:      info.Name(),
				Size:      info.Size(),
				ModTime:   info.ModTime(),
				ExpiresAt: time.Now().Add(duration),
			},
		}

		if outputPath != "" {
			dest = outputPath
		}

		if !forceEncrypt {
			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("output %q exists; use --force to overwrite", dest)
			}
		}

		stopKDF := showKDF()
		err = cipherlock.EncryptFile(srcPath, dest, password, config)
		stopKDF()
		quietStatus("gate encrypted", err)
		return err
	},
}

var gateDecryptCmd = &cobra.Command{
	Use:   "decrypt [flags] <path>",
	Short: "Decrypt a time-gated file",
	Long: `Decrypt a file that was encrypted with an expiration time.

If the current time is past the expiration time embedded in the file,
the decryption will fail.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcPath := args[0]

		password, err := resolvePassword(passwordSource{
			FD: decryptPasswordFD, Env: decryptPasswordEnv, KeyFile: decryptKeyFile,
			Stdin: decryptPasswordStdin, Label: "Enter password: ",
		})
		if err != nil {
			return err
		}

		dest := decryptOutput
		if dest == "" {
			dest = defaultDecryptPath(srcPath)
		}

		if !forceOverwrite && !inPlace {
			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("output %q exists; use --force to overwrite", dest)
			}
		}

		tmp := dest + ".tmp"
		meta, err := cipherlock.DecryptFileWithMeta(srcPath, tmp, password)
		if err != nil {
			os.Remove(tmp)
			return err
		}

		if meta != nil && !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
			os.Remove(tmp)
			return fmt.Errorf("file expired at %s", meta.ExpiresAt.Format(time.RFC3339))
		}

		if inPlace {
			if err := os.Rename(tmp, srcPath); err != nil {
				return err
			}
		} else {
			if err := os.Rename(tmp, dest); err != nil {
				return err
			}
		}

		quietStatus("gate decrypted", nil)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(gateCmd)
	gateCmd.AddCommand(gateEncryptCmd)
	gateCmd.AddCommand(gateDecryptCmd)

	gateEncryptCmd.Flags().StringVar(&gateExpiresIn, "expires-in", "", "duration until file expires (e.g. 24h, 7d, 30m)")
	gateEncryptCmd.Flags().StringVar(&outputPath, "output", "", "output file path")
	gateEncryptCmd.Flags().StringVar(&passwordEnv, "password-env", "", "read password from environment variable")
	gateEncryptCmd.Flags().StringVar(&passwordFD, "password-fd", "", "read password from file descriptor number (e.g. 0 for stdin pipe)")
	gateEncryptCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
	gateEncryptCmd.Flags().BoolVar(&genPassword, "gen-password", false, "generate a random password")
	gateEncryptCmd.Flags().BoolVar(&forceEncrypt, "force", false, "overwrite existing output file without prompting")
	gateEncryptCmd.Flags().BoolVar(&checksumFlag, "checksum", false, "enable integrity checksum")

	gateDecryptCmd.Flags().StringVar(&decryptOutput, "output", "", "output file path")
	gateDecryptCmd.Flags().BoolVar(&inPlace, "in-place", false, "overwrite source on success")
	gateDecryptCmd.Flags().StringVar(&decryptPasswordEnv, "password-env", "", "read password from environment variable")
	gateDecryptCmd.Flags().StringVar(&decryptPasswordFD, "password-fd", "", "read password from file descriptor number (e.g. 0 for stdin pipe)")
	gateDecryptCmd.Flags().BoolVar(&decryptPasswordStdin, "password-stdin", false, "read password from stdin")
	gateDecryptCmd.Flags().BoolVar(&forceOverwrite, "force", false, "overwrite existing output file without prompting")
}
