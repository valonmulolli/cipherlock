package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var (
	rekeyOutput         string
	newPwdFile          string
	rekeyForce          bool
	rekeyKeyFile        string
	rekeyPasswordEnv    string
	rekeyPasswordFD     string
	rekeyNewPasswordEnv string
	rekeyNewPasswordFD  string
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey [flags] <file>",
	Short: "Re-encrypt a file with a new password",
	Long: `Decrypt a file with the old password and re-encrypt it with a new one.

The plaintext is never written to disk -- it streams through memory.

By default the re-keyed file overwrites the original. Use --output to
write to a different path (the original is preserved).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]

		var oldPwd []byte
		var err error
		if keychainFlag {
			if rekeyKeyFile != "" {
				return fmt.Errorf("--keychain and --key-file are mutually exclusive")
			}
			pwdStr, err := keychainGet(getKeychainAccount(source))
			if err != nil {
				return fmt.Errorf("keychain lookup failed: %w", err)
			}
			oldPwd = []byte(pwdStr)
		} else if rekeyPasswordFD != "" {
			oldPwd, err = readPasswordFromFD(rekeyPasswordFD)
			if err != nil {
				return err
			}
		} else if rekeyPasswordEnv != "" {
			oldPwd, err = readPasswordFromEnv(rekeyPasswordEnv)
			if err != nil {
				return err
			}
		} else if rekeyKeyFile != "" {
			oldPwd, err = os.ReadFile(rekeyKeyFile)
			if err != nil {
				return fmt.Errorf("reading key file: %w", err)
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter current password: ")
			oldPwd, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
		}

		var newPwd []byte
		switch {
		case rekeyNewPasswordFD != "":
			newPwd, err = readPasswordFromFD(rekeyNewPasswordFD)
			if err != nil {
				return err
			}
		case rekeyNewPasswordEnv != "":
			newPwd, err = readPasswordFromEnv(rekeyNewPasswordEnv)
			if err != nil {
				return err
			}
		case newPwdFile != "":
			newPwd, err = os.ReadFile(newPwdFile)
			if err != nil {
				return fmt.Errorf("reading new key file: %w", err)
			}
		default:
			newPwd, err = promptPassword("Enter new password: ", true)
			if err != nil {
				return err
			}
			showStrength(newPwd)
		}

		dest := rekeyOutput
		if dest == "" {
			dest = source
		}

		if !rekeyForce && dest != source {
			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("output %q exists; use --force to overwrite", dest)
			}
		}

		stopKDF := showKDF()

		if dest == source || inPlace {
			err = cipherlock.ReKeyFile(source, "", oldPwd, newPwd, nil)
			stopKDF()
			if err != nil {
				if isAuthError(err) {
					return errors.New("rekey failed: wrong password or corrupted data")
				}
				return err
			}
		} else {
			srcFile, err := os.Open(source)
			if err != nil {
				stopKDF()
				return err
			}
			defer srcFile.Close()

			destFile, err := os.Create(dest)
			if err != nil {
				stopKDF()
				return err
			}
			defer destFile.Close()

			err = cipherlock.ReKey(destFile, srcFile, oldPwd, newPwd, nil)
			stopKDF()
			if err != nil {
				if isAuthError(err) {
					return errors.New("rekey failed: wrong password or corrupted data")
				}
				return err
			}
		}

		if saveKeychain {
			_ = keychainSet(getKeychainAccount(source), string(newPwd))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(rekeyCmd)
	rekeyCmd.Flags().StringVar(&rekeyKeyFile, "key-file", "", "read current password from file instead of prompting")
	rekeyCmd.Flags().StringVar(&newPwdFile, "new-key-file", "", "read new password from file instead of prompting")
	rekeyCmd.Flags().StringVarP(&rekeyOutput, "output", "o", "", "output file path")
	rekeyCmd.Flags().BoolVar(&rekeyForce, "force", false, "overwrite existing output file without prompting")
	rekeyCmd.Flags().BoolVar(&keychainFlag, "keychain", false, "read current password from system keychain")
	rekeyCmd.Flags().BoolVar(&saveKeychain, "save-keychain", false, "save new password to system keychain")
	rekeyCmd.Flags().StringVar(&rekeyPasswordEnv, "password-env", "", "read current password from environment variable")
	rekeyCmd.Flags().StringVar(&rekeyPasswordFD, "password-fd", "", "read current password from file descriptor number (e.g. 0 for stdin pipe)")
	rekeyCmd.Flags().StringVar(&rekeyNewPasswordEnv, "new-password-env", "", "read new password from environment variable")
	rekeyCmd.Flags().StringVar(&rekeyNewPasswordFD, "new-password-fd", "", "read new password from file descriptor number (e.g. 0 for stdin pipe)")
}
