package cors

import (
	"strings"
	"testing"
)

func TestGeneratePayloadsUsesOriginOnly(t *testing.T) {
	scanner := &Scanner{
		origin: "https://evil.com",
	}

	payloads := scanner.generatePayloads("https://example.com/admin?debug=1")

	seen := make(map[string]struct{}, len(payloads))
	for _, payload := range payloads {
		seen[payload.value] = struct{}{}
	}

	if _, ok := seen["https://example.com/admin?debug=1"]; ok {
		t.Fatalf("unexpected full target URL in generated origins")
	}

	for _, expected := range []string{
		"https://example.com",
		"https://fiddle.jshell.net",
		"https://s.codepen.io",
		"https://notexample.com",
	} {
		if _, ok := seen[expected]; !ok {
			t.Fatalf("expected generated origin %q", expected)
		}
	}
}

func TestEvaluateResponseDeveloperBackdoor(t *testing.T) {
	vulnerable, details := evaluateResponse(originPayload{
		value:    "https://fiddle.jshell.net",
		category: "developer-backdoor",
	}, "https://fiddle.jshell.net", "true", "")

	if !vulnerable {
		t.Fatalf("expected vulnerable result")
	}

	if !containsDetail(details, "Developer backdoor") {
		t.Fatalf("expected developer backdoor detail, got %v", details)
	}
}

func TestEvaluateResponsePreDomainWildcard(t *testing.T) {
	vulnerable, details := evaluateResponse(originPayload{
		value:    "https://notexample.com",
		category: "predomain",
	}, "https://notexample.com", "false", "")

	if !vulnerable {
		t.Fatalf("expected vulnerable result")
	}

	if !containsDetail(details, "Pre-domain wildcard") {
		t.Fatalf("expected pre-domain detail, got %v", details)
	}
}

func containsDetail(details []string, want string) bool {
	for _, detail := range details {
		if strings.Contains(detail, want) {
			return true
		}
	}
	return false
}
