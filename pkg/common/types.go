package common

import (
	"net/url"
	"time"
)

// ScanResult represents the result of any scan module
type ScanResult struct {
	URL           string `json:"url"`
	Method        string `json:"method,omitempty"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	Detail        string `json:"detail,omitempty"`
	Module        string `json:"module"`
	Vulnerable    bool   `json:"vulnerable"`
}

// Target represents a scan target
type Target struct {
	URL     string
	Headers map[string]string
	Method  string
}

// Config holds global configuration shared across modules
type Config struct {
	URL         string
	URLs        []string
	Method      string
	Concurrency int
	Timeout     time.Duration
	Retries     int
	Proxy       *url.URL
	ProxyStr    string
	Headers     map[string]string
	UserAgent   string
	RandomAgent bool
	Silent      bool
	Verbose     bool
	NoColor     bool
	OutputFile  string
	JSONOutput  bool
	Redirect    bool
}

// DefaultConfig returns a config with sane defaults
func DefaultConfig() *Config {
	return &Config{
		Method:      "GET",
		Concurrency: 10,
		Timeout:     10 * time.Second,
		Retries:     1,
		UserAgent:   "httpsuite/1.0",
		Headers:     make(map[string]string),
	}
}
