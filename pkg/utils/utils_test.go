package utils

import (
	"strings"
	"testing"
)

func TestGenerateCaseVariantsRespectsLimit(t *testing.T) {
	variants := GenerateCaseVariants(strings.Repeat("path", 16), 20)

	if len(variants) != 20 {
		t.Fatalf("expected 20 variants, got %d", len(variants))
	}

	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		if _, ok := seen[variant]; ok {
			t.Fatalf("duplicate variant generated: %q", variant)
		}
		seen[variant] = struct{}{}
	}
}

func TestGenerateCaseVariantsWithoutLetters(t *testing.T) {
	variants := GenerateCaseVariants("12345-_/.", 20)

	if len(variants) != 1 {
		t.Fatalf("expected 1 variant, got %d", len(variants))
	}

	if variants[0] != "12345-_/." {
		t.Fatalf("unexpected variant: %q", variants[0])
	}
}
