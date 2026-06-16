package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type rgb struct {
	r, g, b uint8
}

func hexToRGB(s string) (rgb, error) {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return rgb{}, fmt.Errorf("invalid hex color: %s", s)
	}
	r, err := strconv.ParseUint(s[0:2], 16, 8)
	if err != nil {
		return rgb{}, fmt.Errorf("invalid hex color: %s", s)
	}
	g, err := strconv.ParseUint(s[2:4], 16, 8)
	if err != nil {
		return rgb{}, fmt.Errorf("invalid hex color: %s", s)
	}
	b, err := strconv.ParseUint(s[4:6], 16, 8)
	if err != nil {
		return rgb{}, fmt.Errorf("invalid hex color: %s", s)
	}
	return rgb{uint8(r), uint8(g), uint8(b)}, nil
}

func ansiFg(c rgb) string {
	return fmt.Sprintf("\033[38;2;%d;%d;%dm", c.r, c.g, c.b)
}

func ansiReset() string {
	return "\033[0m"
}

func disabledColor() bool {
	_, ok := os.LookupEnv("NO_COLOR")
	return ok
}

func resolveColor(hex string) string {
	if disabledColor() {
		return ""
	}
	c, err := hexToRGB(hex)
	if err != nil {
		return ""
	}
	return ansiFg(c)
}
