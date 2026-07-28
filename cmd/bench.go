package cmd

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"

	"github.com/valonmulolli/cipherlock/cipherlock"
)

var (
	benchTarget time.Duration
	benchSave   string
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Benchmark Argon2id performance and recommend KDF parameters",
	Long: `Run Argon2id KDF benchmarks across a range of time and memory settings
to find the strongest parameters that complete within the target duration.

Results are shown in a table. The recommended profile can be saved with
--save and then used with: cipherlock encrypt --profile <name> ...`,
	Args: cobra.NoArgs,
	RunE: runBench,
}

type benchRow struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	Dur     time.Duration
}

func init() {
	rootCmd.AddCommand(benchCmd)
	benchCmd.Flags().DurationVar(&benchTarget, "target", time.Second, "target KDF duration (e.g. 1s, 3s, 500ms)")
	benchCmd.Flags().StringVar(&benchSave, "save", "", "save the recommended profile with this name")
}

func runBench(cmd *cobra.Command, _ []string) error {
	threads := uint8(runtime.NumCPU())
	if threads > 32 {
		threads = 32
	}
	if threads < 1 {
		threads = 1
	}

	memLevels := []uint32{32768, 65536, 131072, 262144} // 32, 64, 128, 256 MiB
	timeLevels := []uint32{1, 2, 3}

	password := []byte("bench-password-argon2id-tuning")
	salt := []byte("bench-salt-16b!")

	fmt.Fprintf(cmd.OutOrStdout(), "Benchmarking Argon2id on %d thread(s), target ≤ %s\n\n",
		threads, benchTarget)

	// Run all benchmarks
	var results []benchRow
	for _, mem := range memLevels {
		for _, t := range timeLevels {
			start := time.Now()
			_ = argon2.IDKey(password, salt, t, mem, threads, 32)
			dur := time.Since(start)
			results = append(results, benchRow{
				Time:    t,
				Memory:  mem,
				Threads: threads,
				Dur:     dur,
			})
		}
	}

	// Find the best result: highest memory (most important), then highest time
	// that fits within the target duration.
	var best *benchRow
	for i := range results {
		r := &results[i]
		if r.Dur > benchTarget {
			continue
		}
		if best == nil {
			best = r
			continue
		}
		// Higher memory wins; if memory equal, higher time wins
		if r.Memory > best.Memory || (r.Memory == best.Memory && r.Time > best.Time) {
			best = r
		}
	}

	// Check if every result (even the most expensive) is under target.
	// If the slowest is under target, the machine can handle even higher params.
	allUnderTarget := true
	for _, r := range results {
		if r.Dur >= benchTarget {
			allUnderTarget = false
			break
		}
	}

	// Re-run the recommended combination for an accurate final measurement.
	if best != nil {
		start := time.Now()
		_ = argon2.IDKey(password, salt, best.Time, best.Memory, best.Threads, 32)
		best.Dur = time.Since(start)
	}

	// Calculate column widths dynamically from the data.
	rows := make([][4]string, 0, len(memLevels))
	maxCol := [4]int{0, 0, 0, 0}

	// Header
	headerLabel := "Memory"
	colLabels := []string{"Time=1", "Time=2", "Time=3"}
	maxCol[0] = maxInt(len(headerLabel), maxCol[0])
	for i, l := range colLabels {
		maxCol[i+1] = maxInt(len(l), maxCol[i+1])
	}

	// Build a lookup: time => memory => dur string + best marker
	type cell struct {
		dur  string
		best bool
	}
	table := make(map[uint32]map[uint32]*cell)
	for _, r := range results {
		if table[r.Time] == nil {
			table[r.Time] = make(map[uint32]*cell)
		}
		durStr := formatDur(r.Dur)
		isBest := best != nil && best.Time == r.Time && best.Memory == r.Memory
		table[r.Time][r.Memory] = &cell{dur: durStr, best: isBest}
	}

	for _, mem := range memLevels {
		memStr := fmt.Sprintf("%d MB", mem/1024)
		maxCol[0] = maxInt(len(memStr), maxCol[0])
		var row [4]string
		row[0] = memStr
		for ci, t := range timeLevels {
			c := table[t][mem]
			v := ""
			if c != nil {
				v = c.dur
				if c.best {
					v += " ← ⭐"
				}
			}
			row[ci+1] = v
			maxCol[ci+1] = maxInt(len(v), maxCol[ci+1])
		}
		rows = append(rows, row)
	}

	// Separator line width: leading "  " + col+gap for each
	sepWidth := 2 + maxCol[0] // leading "  " + Memory column width
	for i := 1; i <= 3; i++ {
		sepWidth += 2 + maxCol[i] // " " + column width
	}
	sep := strings.Repeat("─", sepWidth)

	// Print table with explicit gaps between columns
	fmt.Fprintln(cmd.OutOrStdout(), sep)
	fmt.Fprintf(cmd.OutOrStdout(), "  %-*s", maxCol[0], headerLabel)
	for ci, l := range colLabels {
		fmt.Fprintf(cmd.OutOrStdout(), "  %-*s", maxCol[ci+1], l)
	}
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), sep)

	for _, row := range rows {
		fmt.Fprintf(cmd.OutOrStdout(), "  %-*s", maxCol[0], row[0])
		for ci := 1; ci <= 3; ci++ {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-*s", maxCol[ci], row[ci])
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}
	fmt.Fprintln(cmd.OutOrStdout(), sep)

	// Recommendation
	fmt.Fprintln(cmd.OutOrStdout())
	if best == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "⚠  No combination fits within %s.\n", benchTarget)
		fmt.Fprintf(cmd.OutOrStdout(), "   Try: cipherlock bench --target %s\n",
			formatDur(time.Duration(float64(results[0].Dur.Nanoseconds()) * 1.5)))
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "⭐ Recommended (≈%s on %d threads):\n",
		formatDur(best.Dur), best.Threads)
	fmt.Fprintf(cmd.OutOrStdout(), "   cipherlock config set-profile bench-tuned \\\n")
	fmt.Fprintf(cmd.OutOrStdout(), "     --memory %d --time %d --threads %d --checksum\n",
		best.Memory, best.Time, best.Threads)
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
	fmt.Fprintf(cmd.OutOrStdout(), "   Then: cipherlock encrypt --profile bench-tuned document.pdf\n")

	if allUnderTarget {
		fmt.Fprintf(cmd.OutOrStdout(), "\n")
		fmt.Fprintf(cmd.OutOrStdout(), "   💡 All tested parameters are under %s.\n", benchTarget)
		fmt.Fprintf(cmd.OutOrStdout(), "      Try a longer target for stronger KDF: cipherlock bench --target %s\n",
			formatDur(benchTarget*3))
	}

	// Optional: save the profile
	if benchSave != "" {
		profiles, err := cipherlock.LoadProfiles()
		if err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}
		profiles[benchSave] = cipherlock.Profile{
			Time:     best.Time,
			Memory:   best.Memory,
			Threads:  best.Threads,
			Checksum: true,
		}
		if err := cipherlock.SaveProfiles(profiles); err != nil {
			return fmt.Errorf("saving profiles: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n✅ Profile %q saved.\n", benchSave)
	}

	return nil
}

func formatDur(d time.Duration) string {
	if d < time.Second {
		ms := d.Milliseconds()
		if ms < 10 {
			return fmt.Sprintf("%d ms", ms)
		}
		return fmt.Sprintf("%d ms", ms)
	}
	s := d.Seconds()
	if s < 10 {
		return fmt.Sprintf("%.1f s", s)
	}
	return fmt.Sprintf("%.0f s", s)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

