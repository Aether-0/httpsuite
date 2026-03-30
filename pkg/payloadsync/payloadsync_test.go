package payloadsync

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConstants = `package lib

const DefaultGadgetList = ` + "`" + `first; value
second; value` + "`" + `

const ExtendedGadgetList = DefaultGadgetList + ` + "`" + `
third; value` + "`"

const sampleDirectExtendedConstants = `package lib

const DefaultGadgetList = ` + "`" + `first; value
second; value` + "`" + `

const ExtendedGadgetList = ` + "`" + `first; value
second; value
third; value` + "`"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestExtractDefaultGadgets(t *testing.T) {
	got, err := extractDefaultGadgets([]byte(sampleConstants))
	if err != nil {
		t.Fatalf("extractDefaultGadgets returned error: %v", err)
	}

	if string(got) != "first; value\nsecond; value" {
		t.Fatalf("unexpected default gadget list: %q", string(got))
	}
}

func TestExtractExtendedGadgets(t *testing.T) {
	got, err := extractExtendedGadgets([]byte(sampleConstants))
	if err != nil {
		t.Fatalf("extractExtendedGadgets returned error: %v", err)
	}

	want := "first; value\nsecond; value\nthird; value"
	if string(got) != want {
		t.Fatalf("unexpected extended gadget list: %q", string(got))
	}
}

func TestExtractExtendedGadgetsDirectAssignment(t *testing.T) {
	got, err := extractExtendedGadgets([]byte(sampleDirectExtendedConstants))
	if err != nil {
		t.Fatalf("extractExtendedGadgets returned error: %v", err)
	}

	want := "first; value\nsecond; value\nthird; value"
	if string(got) != want {
		t.Fatalf("unexpected direct extended gadget list: %q", string(got))
	}
}

func TestSyncWritesFiles(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var body string
			status := http.StatusOK

			switch req.URL.Path {
			case "/payloads/httpmethods":
				body = "GET\nPOST"
			case "/constants.go":
				body = sampleConstants
			default:
				status = http.StatusNotFound
				body = "not found"
			}

			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	syncer := NewWithSources(client, []Source{
		{URL: "https://example.invalid/payloads/httpmethods", Destination: filepath.Join("bypass", "httpmethods")},
		{URL: "https://example.invalid/constants.go", Destination: filepath.Join("smuggle", "default.txt"), Transform: extractDefaultGadgets},
	})

	dir := t.TempDir()
	files, err := syncer.Sync(dir)
	if err != nil {
		t.Fatalf("Sync returned error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 updated files, got %d", len(files))
	}

	methodsData, err := os.ReadFile(filepath.Join(dir, "bypass", "httpmethods"))
	if err != nil {
		t.Fatalf("failed reading synced method file: %v", err)
	}
	if strings.TrimSpace(string(methodsData)) != "GET\nPOST" {
		t.Fatalf("unexpected synced methods content: %q", string(methodsData))
	}

	gadgetsData, err := os.ReadFile(filepath.Join(dir, "smuggle", "default.txt"))
	if err != nil {
		t.Fatalf("failed reading synced gadget file: %v", err)
	}
	if strings.TrimSpace(string(gadgetsData)) != "first; value\nsecond; value" {
		t.Fatalf("unexpected synced gadget content: %q", string(gadgetsData))
	}
}
