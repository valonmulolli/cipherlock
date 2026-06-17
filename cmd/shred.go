package cmd

import (
	"fmt"
	"math"
	"os"
	"time"

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
			if err := shredFile(path, info.Size()); err != nil {
				return fmt.Errorf("shred %s: %w", path, err)
			}
			quietStatus("shredded", nil)
		}
		return nil
	},
}

func shredFile(path string, size int64) error {
	if quiet.Load() || size == 0 {
		return cipherlock.Shred(path)
	}

	s := &shredProgress{
		start: time.Now(),
		last:  time.Now(),
		size:  size,
		label: "shredding",
	}
	defer s.done()

	return cipherlock.ShredWith(path, s.update)
}

type shredProgress struct {
	start   time.Time
	last    time.Time
	pass    int
	written int64
	size    int64
	label   string
}

func (s *shredProgress) update(pass, totalPasses int, bytesWritten, fileSize int64) {
	s.pass = pass
	s.written = bytesWritten
	if time.Since(s.last) < 100*time.Millisecond && bytesWritten < fileSize {
		return
	}
	s.last = time.Now()
	s.render(totalPasses)
}

func (s *shredProgress) render(totalPasses int) {
	pct := float64(s.written) / float64(s.size)
	filled := int(math.Round(pct * float64(barWidth)))

	textColor := resolveColor(color2)
	filledColor := resolveColor(color4)
	emptyColor := resolveColor(color5)
	reset := ansiReset()

	bar := ""
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += filledColor + "▌"
		} else {
			bar += emptyColor + "░"
		}
	}

	pctDisplay := int(pct * 100)
	if pctDisplay > 100 {
		pctDisplay = 100
	}

	fmt.Fprintf(os.Stderr, "\r%s%s%s pass %d/%d  %s%s  %3d%%%s",
		textColor, s.label, reset, s.pass, totalPasses, bar, reset, pctDisplay, reset)
}

func (s *shredProgress) done() {
	fmt.Fprintln(os.Stderr)
}

func init() {
	rootCmd.AddCommand(shredCmd)
}
