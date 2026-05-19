package cmd

import (
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"
)

type strength int

const (
	veryWeak strength = iota
	weak
	medium
	strong
	veryStrong
)

func (s strength) String() string {
	switch s {
	case veryWeak:
		return "very weak"
	case weak:
		return "weak"
	case medium:
		return "medium"
	case strong:
		return "strong"
	case veryStrong:
		return "very strong"
	default:
		return "unknown"
	}
}

var commonPasswords = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true,
	"abc123": true, "monkey": true, "letmein": true, "dragon": true,
	"111111": true, "baseball": true, "iloveyou": true, "trustno1": true,
	"sunshine": true, "master": true, "welcome": true, "shadow": true,
	"ashley": true, "football": true, "jesus": true, "michael": true,
	"ninja": true, "mustang": true, "password1": true, "p@ssword": true,
}

func estimateStrength(pwd []byte) strength {
	s := strings.ToLower(string(pwd))

	if commonPasswords[s] {
		return veryWeak
	}
	if len(pwd) < 6 {
		return veryWeak
	}

	var hasLower, hasUpper, hasDigit, hasSpecial, hasSpace bool
	for _, c := range s {
		switch {
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsSpace(c):
			hasSpace = true
		default:
			hasSpecial = true
		}
	}

	charsetSize := 0
	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigit {
		charsetSize += 10
	}
	if hasSpecial {
		charsetSize += 32
	}
	if hasSpace {
		charsetSize += 1
	}

	entropy := float64(len(pwd)) * math.Log2(float64(charsetSize))

	penalty := 1.0
	hasRepeats := false
	for i := 2; i < len(pwd); i++ {
		if pwd[i] == pwd[i-1] && pwd[i] == pwd[i-2] {
			hasRepeats = true
			break
		}
	}
	if hasRepeats {
		penalty *= 0.7
	}

	hasSeq := false
	for i := 2; i < len(pwd); i++ {
		if pwd[i]-pwd[i-1] == 1 && pwd[i-1]-pwd[i-2] == 1 {
			hasSeq = true
			break
		}
		if pwd[i-2]-pwd[i-1] == 1 && pwd[i-1]-pwd[i] == 1 {
			hasSeq = true
			break
		}
	}
	if hasSeq {
		penalty *= 0.7
	}

	entropy *= penalty

	switch {
	case entropy < 30:
		return veryWeak
	case entropy < 45:
		return weak
	case entropy < 65:
		return medium
	case entropy < 85:
		return strong
	default:
		return veryStrong
	}
}

func showStrength(pwd []byte) {
	s := estimateStrength(pwd)
	fmt.Fprintf(os.Stderr, "Password strength: %s\n", s)
}
