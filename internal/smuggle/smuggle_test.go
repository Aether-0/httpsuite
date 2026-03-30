package smuggle

import "testing"

func TestParsePayloadLineReplacesHostnameAndEscapes(t *testing.T) {
	payload := parsePayloadLine(":authority; [HOSTNAME]\\r\\n\\r\\n99\\r\\n", "example.com")
	if payload == nil {
		t.Fatalf("expected payload")
	}

	if payload.HeaderName != ":authority" {
		t.Fatalf("unexpected header name: %q", payload.HeaderName)
	}

	if payload.HeaderValue != "example.com\r\n\r\n99\r\n" {
		t.Fatalf("unexpected header value: %q", payload.HeaderValue)
	}
}

func TestParsePayloadLineDecodesPercentEscapes(t *testing.T) {
	payload := parsePayloadLine("transfer-encoding%0A; chunked%20", "example.com")
	if payload == nil {
		t.Fatalf("expected payload")
	}

	if payload.HeaderName != "transfer-encoding\n" {
		t.Fatalf("unexpected decoded header name: %q", payload.HeaderName)
	}

	if payload.HeaderValue != "chunked " {
		t.Fatalf("unexpected decoded header value: %q", payload.HeaderValue)
	}
}
