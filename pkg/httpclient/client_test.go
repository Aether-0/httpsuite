package httpclient

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSimpleRequestReturnsContentLength(t *testing.T) {
	body := strings.Repeat("a", 1<<20)
	client := newTestClient(body, http.Header{}, http.StatusAccepted)

	statusCode, contentLength, err := client.SimpleRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("SimpleRequest returned error: %v", err)
	}

	if statusCode != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
	}

	if contentLength != len(body) {
		t.Fatalf("expected content length %d, got %d", len(body), contentLength)
	}
}

func TestInspectRequestBuildsHTMLFingerprint(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Directory access is forbidden.</p></body></html>`
	client := newTestClient(body, http.Header{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}, http.StatusForbidden)

	summary, err := client.InspectRequest(http.MethodGet, "https://example.com/admin", nil)
	if err != nil {
		t.Fatalf("InspectRequest returned error: %v", err)
	}

	if !summary.IsHTML {
		t.Fatalf("expected HTML summary")
	}

	if summary.Title != "403 Forbidden" {
		t.Fatalf("unexpected title: %q", summary.Title)
	}

	if !strings.Contains(summary.TextSignature, "directory access is forbidden") {
		t.Fatalf("unexpected text signature: %q", summary.TextSignature)
	}

	if summary.NormalizedHash == "" {
		t.Fatalf("expected normalized hash to be set")
	}
}

func newTestClient(body string, headers http.Header, statusCode int) *Client {
	return &Client{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				headerCopy := make(http.Header, len(headers))
				for key, values := range headers {
					headerCopy[key] = append([]string(nil), values...)
				}

				return &http.Response{
					StatusCode: statusCode,
					Header:     headerCopy,
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			}),
		},
		userAgent: "httpsuite/1.0",
		retries:   1,
	}
}
