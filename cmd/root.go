package cmd

import (
	"github.com/spf13/cobra"
)

var inPlace bool

var rootCmd = &cobra.Command{
	Use:   "cipherlock",
	Short: "AES-256-GCM file encryption with Argon2id key derivation",
	Long: `cipherlock encrypts and decrypts files using AES-256-GCM authenticated
encryption with Argon2id memory-hard key derivation.

It supports single files, entire directories, and stdin/stdout pipe mode.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&inPlace, "in-place", false, "overwrite the source file instead of creating a new one")
}
