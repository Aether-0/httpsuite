package httpclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client wraps the standard http.Client with convenience methods
type Client struct {
	client    *http.Client
	userAgent string
	headers   map[string]string
	retries   int
	redirect  bool
}

// Options for creating a new Client
type Options struct {
	Timeout   time.Duration
	Proxy     *url.URL
	UserAgent string
	Headers   map[string]string
	Retries   int
	Redirect  bool
	Insecure  bool
}

// New creates a new HTTP client with the given options
func New(opts Options) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if opts.Proxy != nil {
		transport.Proxy = http.ProxyURL(opts.Proxy)
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !opts.Redirect {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	retries := opts.Retries
	if retries <= 0 {
		retries = 1
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = "httpsuite/1.0"
	}

	return &Client{
		client: &http.Client{
			Timeout:       timeout,
			Transport:     transport,
			CheckRedirect: checkRedirect,
		},
		userAgent: ua,
		headers:   opts.Headers,
		retries:   retries,
		redirect:  opts.Redirect,
	}
}

// Do executes an HTTP request with retries
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Set default headers
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for k, v := range c.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	var lastErr error
	for i := 0; i < c.retries; i++ {
		resp, err := c.client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if i < c.retries-1 {
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("request failed after %d retries: %w", c.retries, lastErr)
}

// SimpleRequest makes a simple HTTP request and returns status code and body
func (c *Client) SimpleRequest(method, targetURL string, extraHeaders map[string]string) (int, []byte, error) {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("error creating request: %w", err)
	}

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if readErr != nil {
			break
		}
	}

	return resp.StatusCode, body, nil
}

// GetTransport returns the underlying transport for advanced use
func (c *Client) GetTransport() *http.Transport {
	return c.client.Transport.(*http.Transport)
}
