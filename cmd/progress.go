package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/schollz/progressbar/v3"
)

func showKDF() func() {
	fmt.Fprint(os.Stderr, "Deriving key... ")
	return func() {}
}

func progressReader(r io.Reader, size int64, label string) io.Reader {
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


