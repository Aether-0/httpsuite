package payloadsync

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	defaultGadgetPattern        = regexp.MustCompile("(?s)DefaultGadgetList\\s*=\\s*`(.*?)`")
	extendedGadgetPattern       = regexp.MustCompile("(?s)ExtendedGadgetList\\s*=\\s*`(.*?)`")
	extendedGadgetSuffixPattern = regexp.MustCompile("(?s)ExtendedGadgetList\\s*=\\s*DefaultGadgetList\\s*\\+\\s*`(.*?)`")
)

// Source describes a remote payload file and its local destination.
type Source struct {
	URL         string
	Destination string
	Transform   func([]byte) ([]byte, error)
}

// Syncer downloads current payload files and writes them to disk.
type Syncer struct {
	client  *http.Client
	sources []Source
}

// New creates a syncer with the default upstream payload sources.
func New(timeout time.Duration) *Syncer {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	return &Syncer{
		client:  &http.Client{Timeout: timeout},
		sources: defaultSources(),
	}
}

// NewWithSources creates a syncer with custom sources. Useful for tests.
func NewWithSources(client *http.Client, sources []Source) *Syncer {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	return &Syncer{
		client:  client,
		sources: append([]Source(nil), sources...),
	}
}

// Sync downloads all configured sources into dir and returns the updated file paths.
func (s *Syncer) Sync(dir string) ([]string, error) {
	if dir == "" {
		dir = "payloads"
	}

	updated := make([]string, 0, len(s.sources))
	for _, source := range s.sources {
		data, err := s.fetch(source.URL)
		if err != nil {
			return updated, fmt.Errorf("fetch %s: %w", source.URL, err)
		}

		if source.Transform != nil {
			data, err = source.Transform(data)
			if err != nil {
				return updated, fmt.Errorf("transform %s: %w", source.Destination, err)
			}
		}

		if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
			data = append(data, '\n')
		}

		path := filepath.Join(dir, source.Destination)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return updated, fmt.Errorf("create directory for %s: %w", path, err)
		}

		if err := os.WriteFile(path, data, 0o644); err != nil {
			return updated, fmt.Errorf("write %s: %w", path, err)
		}

		updated = append(updated, path)
	}

	return updated, nil
}

func (s *Syncer) fetch(target string) ([]byte, error) {
	resp, err := s.client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func defaultSources() []Source {
	const (
		noMore403Base = "https://raw.githubusercontent.com/devploit/nomore403/main/payloads/"
		smuggleBase   = "https://raw.githubusercontent.com/Moopinger/smugglefuzz/main/lib/constants.go"
	)

	return []Source{
		{URL: noMore403Base + "httpmethods", Destination: filepath.Join("bypass", "httpmethods")},
		{URL: noMore403Base + "endpaths", Destination: filepath.Join("bypass", "endpaths")},
		{URL: noMore403Base + "midpaths", Destination: filepath.Join("bypass", "midpaths")},
		{URL: noMore403Base + "headers", Destination: filepath.Join("bypass", "headers")},
		{URL: noMore403Base + "ips", Destination: filepath.Join("bypass", "ips")},
		{URL: noMore403Base + "simpleheaders", Destination: filepath.Join("bypass", "simpleheaders")},
		{URL: smuggleBase, Destination: filepath.Join("smuggle", "default.txt"), Transform: extractDefaultGadgets},
		{URL: smuggleBase, Destination: filepath.Join("smuggle", "extended.txt"), Transform: extractExtendedGadgets},
	}
}

func extractDefaultGadgets(data []byte) ([]byte, error) {
	match := defaultGadgetPattern.FindSubmatch(data)
	if len(match) != 2 {
		return nil, fmt.Errorf("DefaultGadgetList not found")
	}

	return bytesTrimLeadingNewline(match[1]), nil
}

func extractExtendedGadgets(data []byte) ([]byte, error) {
	match := extendedGadgetPattern.FindSubmatch(data)
	if len(match) == 2 {
		return bytesTrimLeadingNewline(match[1]), nil
	}

	defaultList, err := extractDefaultGadgets(data)
	if err != nil {
		return nil, err
	}

	match = extendedGadgetSuffixPattern.FindSubmatch(data)
	if len(match) != 2 {
		return defaultList, nil
	}

	suffix := bytesTrimLeadingNewline(match[1])
	if len(defaultList) == 0 {
		return suffix, nil
	}
	if len(suffix) == 0 {
		return defaultList, nil
	}

	combined := append([]byte{}, defaultList...)
	if !strings.HasSuffix(string(combined), "\n") {
		combined = append(combined, '\n')
	}
	combined = append(combined, suffix...)
	return combined, nil
}

func bytesTrimLeadingNewline(data []byte) []byte {
	return []byte(strings.TrimPrefix(string(data), "\n"))
}
