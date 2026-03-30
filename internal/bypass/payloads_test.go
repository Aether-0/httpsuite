package bypass

import "testing"

func TestBuildHeaderPayloadsUsesCustomBypassIP(t *testing.T) {
	payloads := BuildHeaderPayloads("https://example.com/admin", "/admin", "example.com", "https", "8.8.8.8")

	var foundOverride bool
	for _, payload := range payloads {
		if payload.Key == "X-Forwarded-For" && payload.Value == "8.8.8.8" {
			foundOverride = true
		}
		if payload.Key == "X-Forwarded-For" && payload.Value == "127.0.0.1" {
			t.Fatalf("unexpected default IP payload when override is set")
		}
	}

	if !foundOverride {
		t.Fatalf("expected override IP payload to be generated")
	}
}
