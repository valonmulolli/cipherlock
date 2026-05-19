package cmd

import (
	"testing"
)

func TestEstimateStrengthCommon(t *testing.T) {
	tests := []struct {
		pwd  string
		want strength
	}{
		{"password", veryWeak},
		{"123456", veryWeak},
		{"qwerty", veryWeak},
		{"abc123", veryWeak},
		{"password1", veryWeak},
		{"1234", veryWeak},
		{"a", veryWeak},
		{"abcdef", veryWeak},
		{"aaabbb", veryWeak},
		{"abcabc", veryWeak},
		{"Password1", veryWeak},
		{"p@ssword", veryWeak},
		{"P@ssw0rd!", medium},
		{"Password!!", medium},
		{"Tr0ub4dor&3", strong},
		{"k9#mP2$xL7@qR!", veryStrong},
		{"correct-horse-battery-staple", veryStrong},
	}
	for _, tt := range tests {
		got := estimateStrength([]byte(tt.pwd))
		if got != tt.want {
			t.Errorf("estimateStrength(%q) = %v, want %v", tt.pwd, got, tt.want)
		}
	}
}

func TestEstimateStrengthEdgeCases(t *testing.T) {
	if got := estimateStrength(nil); got != veryWeak {
		t.Errorf("nil password = %v, want veryWeak", got)
	}
	if got := estimateStrength([]byte{}); got != veryWeak {
		t.Errorf("empty password = %v, want veryWeak", got)
	}
}

func TestEstimateStrengthPenalties(t *testing.T) {
	repeating := estimateStrength([]byte("aaaabbbbcccc"))
	sequential := estimateStrength([]byte("abc123def456"))
	diverse := estimateStrength([]byte("abC1defG2hIj3"))

	if repeating > medium {
		t.Errorf("repeating pattern should be <= medium, got %v", repeating)
	}
	if sequential > weak {
		t.Errorf("sequential pattern should be <= weak, got %v", sequential)
	}
	if diverse < weak {
		t.Errorf("diverse 13-char password should be >= weak, got %v", diverse)
	}
}

func TestStrengthString(t *testing.T) {
	tests := map[strength]string{
		veryWeak:   "very weak",
		weak:       "weak",
		medium:     "medium",
		strong:     "strong",
		veryStrong: "very strong",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", s, got, want)
		}
	}
}
