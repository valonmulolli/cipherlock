package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var clickCmd = &cobra.Command{
	Use:   "click [flags] <file>",
	Short: "Verify password and file integrity",
	Long: `Quickly verify that a password is correct for an encrypted file.

The command decrypts the file header to check if the password is valid
without writing any output. Returns exit code 0 if the password is correct
and the file is intact, or a non-zero exit code otherwise.

This is the same as 'decrypt --check'.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcPath := args[0]
		srcFile, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		info, err := srcFile.Stat()
		if err != nil {
			return err
		}

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
			if isAuthError(err) {
				return errors.New("decryption failed: wrong password or corrupted data")
			}
			return err
		}

		fmt.Fprintln(os.Stderr, "password correct, file is intact")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(clickCmd)
	clickCmd.Flags().StringVar(&decryptPasswordEnv, "password-env", "", "read password from environment variable")
	clickCmd.Flags().StringVar(&decryptPasswordFD, "password-fd", "", "read password from file descriptor number (e.g. 0 for stdin pipe)")
	clickCmd.Flags().BoolVar(&decryptPasswordStdin, "password-stdin", false, "read password from stdin")
	clickCmd.Flags().BoolVar(&keychainFlag, "keychain", false, "read password from system keychain")
}
