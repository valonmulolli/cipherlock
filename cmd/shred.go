package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var shredCmd = &cobra.Command{
	Use:   "shred [flags] <path> [<path>...]",
	Short: "Securely delete files",
	Long: `Overwrite files with random data and zeros, then remove them.

Each file is overwritten with one pass of cryptographically random
data followed by one pass of zeros, with fsync between passes. After
overwriting, the file is removed from the filesystem.

This makes the original contents unrecoverable even with forensic
tools on spinning disks. On SSDs, wear-leveling may leave remnants.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		for _, path := range args {
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("cannot shred directory: %s", path)
			}
			if err := cipherlock.Shred(path); err != nil {
				return fmt.Errorf("shred %s: %w", path, err)
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(shredCmd)
}
