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

// GenerateCaseCombinations generates case combinations for a string
func GenerateCaseCombinations(s string) []string {
	if len(s) == 0 {
		return []string{""}
	}

	first := []string{
		string(unicode.ToLower(rune(s[0]))),
		string(unicode.ToUpper(rune(s[0]))),
	}
	sub := GenerateCaseCombinations(s[1:])

	var combos []string
	for _, c := range first {
		for _, rest := range sub {
			combos = append(combos, c+rest)
		}
	}
	return combos
}

// SelectRandom selects up to n random elements from a slice
func SelectRandom(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	shuffled := make([]string, len(items))
	copy(shuffled, items)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:n]
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
