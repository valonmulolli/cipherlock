package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	inPlace bool
	quiet   bool
)

// Version is set at build time via -ldflags.
// Example: go build -ldflags "-X github.com/valonmulolli/cipherlock/cmd.Version=v1.2.0" .
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "cipherlock",
	Short: "AES-256-GCM file encryption with Argon2id key derivation",
	Long: `cipherlock encrypts and decrypts files using AES-256-GCM authenticated
encryption with Argon2id memory-hard key derivation.

It supports single files, entire directories, and stdin/stdout pipe mode.`,
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintf(cmd.OutOrStdout(), "cipherlock %s\n", Version)
		return nil
	},
}

// Execute runs the cipherlock CLI, dispatching to the appropriate
// subcommand (encrypt, decrypt, rekey, completion, config, shred, info).
// It returns an error when the command fails; the root command itself is
// configured to suppress printing usage on errors via SilenceUsage.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&inPlace, "in-place", false, "overwrite the source file instead of creating a new one")
	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "suppress progress output")
	rootCmd.AddCommand(versionCmd)
}
