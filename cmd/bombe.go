package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/valonmulolli/cipherlock/cipherlock"
)

var bombeCmd = &cobra.Command{
	Use:   "bombe [flags] <file>",
	Short: "Verify file integrity",
	Long: `Verify that an encrypted file has not been tampered with.

Decrypts the file in memory and verifies the embedded checksum
without writing any output. Returns exit code 0 if the file is
intact and the password is correct, or a non-zero exit code if
the file has been corrupted or the password is wrong.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcPath := args[0]

		var password []byte
		if keychainFlag {
			pwd, err := resolvePassword(passwordSource{KeychainOn: true, KeychainAc: getKeychainAccount(srcPath)})
			if err != nil {
				return err
			}
			password = pwd
		} else {
			pwd, err := resolvePassword(passwordSource{
				FD: decryptPasswordFD, Env: decryptPasswordEnv, KeyFile: decryptKeyFile,
				Stdin: decryptPasswordStdin, Label: "Enter password: ",
			})
			if err != nil {
				return err
			}
			password = pwd
		}

		srcFile, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		info, err := srcFile.Stat()
		if err != nil {
			return err
		}

		stopKDF := showKDF()
		var reader io.Reader
		if info.Size() > 0 && info.Mode().IsRegular() {
			reader = progressReader(srcFile, info.Size(), "checking")
		} else {
			reader = srcFile
		}
		err = decryptFromReader(io.Discard, reader, password)
		stopKDF()
		if err != nil {
			if errors.Is(err, cipherlock.ErrChecksumMismatch) {
				return errors.New("integrity check failed: checksum mismatch — file may be corrupted")
			}
			if isAuthError(err) {
				return errors.New("wrong password")
			}
			return err
		}

		fmt.Fprintln(os.Stderr, "integrity verified, file is intact")
		quietStatus("verified", nil)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bombeCmd)
	bombeCmd.Flags().StringVar(&decryptPasswordEnv, "password-env", "", "read password from environment variable")
	bombeCmd.Flags().StringVar(&decryptPasswordFD, "password-fd", "", "read password from file descriptor number (e.g. 0 for stdin pipe)")
	bombeCmd.Flags().BoolVar(&decryptPasswordStdin, "password-stdin", false, "read password from stdin")
	bombeCmd.Flags().BoolVar(&keychainFlag, "keychain", false, "read password from system keychain")
}
