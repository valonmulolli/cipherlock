package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
)

func showKDF() func() {
	if quiet {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		fmt.Fprint(os.Stderr, "Deriving key")
		for {
			select {
			case <-ticker.C:
				fmt.Fprint(os.Stderr, ".")
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		fmt.Fprintln(os.Stderr)
	}
}

func progressReader(r io.Reader, size int64, label string) io.Reader {
	if quiet || size == 0 {
		return r
	}
	bar := progressbar.NewOptions64(
		size,
		progressbar.OptionSetDescription(label),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(40),
		progressbar.OptionThrottle(100),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
	)
	r2 := progressbar.NewReader(r, bar)
	return &r2
}
