package utils

import (
	"bufio"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// NormalizeURL ensures URL has a scheme prefix
func NormalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "https://" + rawURL
	}
	return rawURL
}

// ReadLines reads lines from a file, trimming whitespace and skipping empty lines
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// ReadURLsFromStdin reads URLs from stdin
func ReadURLsFromStdin() []string {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, NormalizeURL(line))
		}
	}
	return urls
}

// HasStdin checks if there's data available on stdin
func HasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

// ParseURL parses a URL and returns components
func ParseURL(rawURL string) (scheme, host, path string, err error) {
	u, err := url.Parse(NormalizeURL(rawURL))
	if err != nil {
		return "", "", "", err
	}
	return u.Scheme, u.Host, u.Path, nil
}

// GetBaseURL returns scheme://host from a URL
func GetBaseURL(rawURL string) string {
	u, err := url.Parse(NormalizeURL(rawURL))
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// GetPath returns the path component of a URL
func GetPath(rawURL string) string {
	u, err := url.Parse(NormalizeURL(rawURL))
	if err != nil {
		return ""
	}
	return u.Path
}

// RandomString generates a random alphanumeric string of given length
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// GenerateCaseVariants returns up to limit randomized case variants without materializing 2^n combinations.
func GenerateCaseVariants(s string, limit int) []string {
	if limit <= 0 {
		return nil
	}

	base := []rune(s)
	letterIdx := make([]int, 0, len(base))

	for i, r := range base {
		if unicode.IsLetter(r) {
			base[i] = unicode.ToLower(r)
			letterIdx = append(letterIdx, i)
		}
	}

	if len(letterIdx) == 0 {
		return []string{s}
	}

	variants := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)

	addVariant := func(candidate []rune) {
		variant := string(candidate)
		if _, ok := seen[variant]; ok {
			return
		}
		seen[variant] = struct{}{}
		variants = append(variants, variant)
	}

	addVariant(append([]rune(nil), base...))
	if len(variants) == limit {
		return variants
	}

	allUpper := append([]rune(nil), base...)
	for _, idx := range letterIdx {
		allUpper[idx] = unicode.ToUpper(allUpper[idx])
	}
	addVariant(allUpper)
	if len(variants) == limit {
		return variants
	}

	maxAttempts := limit * 32
	if maxAttempts < len(letterIdx)*4 {
		maxAttempts = len(letterIdx) * 4
	}

	for attempts := 0; len(variants) < limit && attempts < maxAttempts; attempts++ {
		candidate := append([]rune(nil), base...)
		for _, idx := range letterIdx {
			if rand.Intn(2) == 1 {
				candidate[idx] = unicode.ToUpper(candidate[idx])
			}
		}
		addVariant(candidate)
	}

	for _, idx := range letterIdx {
		if len(variants) == limit {
			break
		}
		candidate := append([]rune(nil), base...)
		candidate[idx] = unicode.ToUpper(candidate[idx])
		addVariant(candidate)
	}

	return variants
}

// UniqueStrings removes duplicates while preserving the original order.
func UniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(items))
	unique := make([]string, 0, len(items))

	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		unique = append(unique, item)
	}

	return unique
}

// PathExists reports whether a filesystem path exists.
func PathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// URLEncode double-encodes a string
func DoubleURLEncode(s string) string {
	first := url.PathEscape(s)
	return url.PathEscape(first)
}

// JoinURL safely joins base URL and path
func JoinURL(base, path string) string {
	if !strings.HasSuffix(base, "/") && !strings.HasPrefix(path, "/") {
		return base + "/" + path
	}
	if strings.HasSuffix(base, "/") && strings.HasPrefix(path, "/") {
		return base + path[1:]
	}
	return base + path
}

// RandomUserAgent returns a random user agent string
func RandomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	}
	return agents[rand.Intn(len(agents))]
}
