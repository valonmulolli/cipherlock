package cmd

import (
	"fmt"
	"io"
	"math"
	"os"
	"time"
	"unicode/utf8"
)

const scrambleChars = "0123456789abcdefABCDEF~!@#$£€%^&*()+=_"

func showKDF() func() {
	if quiet.Load() {
		return func() {}
	}

	textColor := resolveColor(color2)
	spinnerColor := resolveColor(color3)
	reset := ansiReset()
	nChars := utf8.RuneCountInString(scrambleChars)

	firstChar := string([]rune(scrambleChars)[0])
	fmt.Fprintf(os.Stderr, "%sDeriving key %s%s%s", textColor, spinnerColor, firstChar, reset)

	s := &kdfSpinner{
		stopCh:       make(chan struct{}),
		done:         make(chan struct{}),
		pos:          1,
		textColor:    textColor,
		spinnerColor: spinnerColor,
		reset:        reset,
		nChars:       nChars,
	}
	go s.run()
	return func() {
		close(s.stopCh)
		<-s.done
	}
}

type kdfSpinner struct {
	stopCh       chan struct{}
	done         chan struct{}
	pos          int
	ellipsisIdx  int
	frame        int
	textColor    string
	spinnerColor string
	reset        string
	nChars       int
}

func (s *kdfSpinner) run() {
	defer close(s.done)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	ellipsisStates := []string{"", ".", "..", "..."}

	for {
		select {
		case <-ticker.C:
			ch := string([]rune(scrambleChars)[s.pos%s.nChars])
			ellipsis := ellipsisStates[s.ellipsisIdx]
			fmt.Fprintf(os.Stderr, "\r%sDeriving key%s %s%s%s", s.textColor, ellipsis, s.spinnerColor, ch, s.reset)
			s.pos++
			s.frame++
			if s.frame%4 == 0 {
				s.ellipsisIdx = (s.ellipsisIdx + 1) % len(ellipsisStates)
			}
		case <-s.stopCh:
			fmt.Fprint(os.Stderr, s.reset, "\nDeriving key done   \n")
			return
		}
	}
}

type progressBarReader struct {
	r           io.Reader
	total       int64
	read        int64
	label       string
	start       time.Time
	last        time.Time
	barWidth    int
	done        bool
	firstRender bool
}

func progressReader(r io.Reader, size int64, label string) io.Reader {
	if quiet.Load() || size == 0 {
		return r
	}
	return &progressBarReader{
		r:           r,
		total:       size,
		label:       label,
		start:       time.Now(),
		last:        time.Now(),
		barWidth:    30,
		firstRender: true,
	}
}

func (p *progressBarReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	if n > 0 {
		p.read += int64(n)
	}
	if !quiet.Load() && (time.Since(p.last) >= 100*time.Millisecond || err != nil) {
		p.render()
		p.last = time.Now()
	}
	return n, err
}

func (p *progressBarReader) render() {
	elapsed := time.Since(p.start).Seconds()
	if elapsed == 0 {
		elapsed = 0.01
	}
	pct := float64(p.read) / float64(p.total)
	filled := int(math.Round(pct * float64(p.barWidth)))

	textColor := resolveColor(color2)
	filledColor := resolveColor(color4)
	emptyColor := resolveColor(color5)
	reset := ansiReset()

	bar := ""
	for i := 0; i < p.barWidth; i++ {
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

	speed := float64(p.read) / elapsed
	var eta time.Duration
	if speed > 0 {
		remaining := float64(p.total - p.read)
		eta = time.Duration(remaining/speed) * time.Second
	}

	pctStr := fmt.Sprintf(" %3d%%", pctDisplay)

	readStr := formatBytes(p.read)
	totalStr := formatBytes(p.total)
	bytesStr := fmt.Sprintf("  %s/%s", readStr, totalStr)

	speedStr := formatSpeed(speed)

	etaStr := ""
	if eta > 0 {
		etaMinutes := int(eta.Minutes())
		etaSeconds := int(eta.Seconds()) % 60
		etaStr = fmt.Sprintf("  ETA %d:%02d", etaMinutes, etaSeconds)
	}

	prefix := "\r"
	if p.firstRender {
		prefix = "\n"
		p.firstRender = false
	}
	fmt.Fprintf(os.Stderr, "%s%s%s  %s%s%s%s%s%s", prefix, textColor, p.label, bar, reset, pctStr, bytesStr, speedStr, etaStr)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.0f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatSpeed(speed float64) string {
	switch {
	case speed >= 1<<30:
		return fmt.Sprintf("  %.0f GB/s", speed/(1<<30))
	case speed >= 1<<20:
		return fmt.Sprintf("  %.0f MB/s", speed/(1<<20))
	case speed >= 1<<10:
		return fmt.Sprintf("  %.0f KB/s", speed/(1<<10))
	default:
		return fmt.Sprintf("  %.0f B/s", speed)
	}
}
