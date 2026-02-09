package smuggle

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/output"
)

// HTTP/2 frame types
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	frameSettings     = 0x4
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8

	flagEndStream  = 0x1
	flagEndHeaders = 0x4

	http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// Payload represents a smuggling gadget
type Payload struct {
	HeaderName  string
	HeaderValue string
	Name        string
}

// Scanner performs HTTP request smuggling testing via H2 downgrade
type Scanner struct {
	config        *common.Config
	printer       *output.Printer
	extended      bool
	gadgetFile    string
	detectTimeout int
}

// NewScanner creates a new smuggle scanner
func NewScanner(cfg *common.Config, printer *output.Printer, extended bool, gadgetFile string, detectTimeout int) *Scanner {
	return &Scanner{
		config:        cfg,
		printer:       printer,
		extended:      extended,
		gadgetFile:    gadgetFile,
		detectTimeout: detectTimeout,
	}
}

// Run executes the smuggling scan
func (s *Scanner) Run() {
	s.printer.Info("Starting HTTP smuggling scan for %d target(s)", len(s.config.URLs))

	payloads := s.loadPayloads()
	if len(payloads) == 0 {
		s.printer.Error("No smuggling payloads loaded")
		return
	}
	s.printer.Info("Loaded %d smuggling gadgets", len(payloads))

	for _, targetURL := range s.config.URLs {
		s.scanTarget(targetURL, payloads)
	}
}

func (s *Scanner) scanTarget(targetURL string, payloads []Payload) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		s.printer.Error("Error parsing URL %s: %v", targetURL, err)
		return
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	s.printer.Info("Scanning %s for HTTP smuggling vulnerabilities", targetURL)

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(p Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			result := s.testPayload(host, port, parsedURL.Path, parsedURL.RawQuery, p)

			vulnerable := false
			detail := p.Name + " → " + result

			if strings.Contains(result, "TIMEOUT") {
				vulnerable = true
				detail = p.Name + " → TIMEOUT (potential smuggling)"
			} else if strings.Contains(result, "GOAWAY") {
				detail = p.Name + " → GOAWAY"
			} else if strings.Contains(result, "RST") {
				detail = p.Name + " → RST_STREAM"
			}

			s.printer.Result(common.ScanResult{
				URL:        targetURL,
				Method:     "POST",
				Module:     "smuggle",
				Detail:     detail,
				Vulnerable: vulnerable,
			})
		}(payload)
	}
	wg.Wait()
}

func (s *Scanner) testPayload(host, port, path, query string, payload Payload) string {
	addr := net.JoinHostPort(host, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Duration(s.config.Timeout.Seconds()) * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	)
	if err != nil {
		return fmt.Sprintf("connection error: %v", err)
	}
	defer conn.Close()

	// Check if h2 was negotiated
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return "h2 not supported"
	}

	// Send HTTP/2 preface
	_, err = conn.Write([]byte(http2Preface))
	if err != nil {
		return fmt.Sprintf("preface error: %v", err)
	}

	// Send empty SETTINGS frame
	err = writeFrame(conn, frameSettings, 0, 0, nil)
	if err != nil {
		return fmt.Sprintf("settings error: %v", err)
	}

	// Read server settings
	_, err = readFrame(conn)
	if err != nil {
		return fmt.Sprintf("read settings error: %v", err)
	}

	// Send SETTINGS ACK
	err = writeFrame(conn, frameSettings, 0x1, 0, nil)
	if err != nil {
		return fmt.Sprintf("settings ack error: %v", err)
	}

	// Build target path
	targetPath := path
	if targetPath == "" {
		targetPath = "/"
	}
	if query != "" {
		targetPath += "?" + query
	}

	// Build HEADERS frame with smuggling payload
	headers := buildHPACKHeaders(host, targetPath, payload)

	// Send HEADERS frame (stream 1)
	err = writeFrame(conn, frameHeaders, flagEndHeaders, 1, headers)
	if err != nil {
		return fmt.Sprintf("headers error: %v", err)
	}

	// Send DATA frame with payload body
	dataBody := []byte("99\r\n")
	err = writeFrame(conn, frameData, flagEndStream, 1, dataBody)
	if err != nil {
		return fmt.Sprintf("data error: %v", err)
	}

	// Wait for response with timeout
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.detectTimeout) * time.Second))

	frame, err := readFrame(conn)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "*TIMEOUT"
		}
		return fmt.Sprintf("read error: %v", err)
	}

	switch frame.Type {
	case frameHeaders:
		return fmt.Sprintf("response received (stream %d)", frame.StreamID)
	case frameGoAway:
		return "GOAWAY"
	default:
		return fmt.Sprintf("frame type %d", frame.Type)
	}
}

// Frame represents a basic HTTP/2 frame
type Frame struct {
	Length   uint32
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
}

func writeFrame(w io.Writer, frameType byte, flags byte, streamID uint32, payload []byte) error {
	header := make([]byte, 9)
	length := len(payload)
	header[0] = byte(length >> 16)
	header[1] = byte(length >> 8)
	header[2] = byte(length)
	header[3] = frameType
	header[4] = flags
	binary.BigEndian.PutUint32(header[5:9], streamID&0x7fffffff)

	_, err := w.Write(header)
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err = w.Write(payload)
	}
	return err
}

func readFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, 9)
	_, err := io.ReadFull(r, header)
	if err != nil {
		return nil, err
	}

	length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	frame := &Frame{
		Length:   length,
		Type:     header[3],
		Flags:    header[4],
		StreamID: binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff,
	}

	if length > 0 {
		frame.Payload = make([]byte, length)
		_, err = io.ReadFull(r, frame.Payload)
		if err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// buildHPACKHeaders builds a simplified HPACK encoded headers block
func buildHPACKHeaders(host, path string, payload Payload) []byte {
	var buf []byte

	// :method = POST (indexed: 0x83)
	buf = append(buf, 0x83)
	// :scheme = https (indexed: 0x87)
	buf = append(buf, 0x87)
	// :path = <path> (literal with indexing, name index 4)
	buf = append(buf, 0x44)
	buf = append(buf, encodeHPACKString(path)...)
	// :authority = <host> (literal with indexing, name index 1)
	buf = append(buf, 0x41)
	buf = append(buf, encodeHPACKString(host)...)

	// user-agent header
	buf = append(buf, 0x00)
	buf = append(buf, encodeHPACKString("user-agent")...)
	buf = append(buf, encodeHPACKString("Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0")...)

	// The smuggling payload header - use literal without indexing (0x00)
	buf = append(buf, 0x00)
	buf = append(buf, encodeHPACKString(payload.HeaderName)...)
	buf = append(buf, encodeHPACKString(payload.HeaderValue)...)

	return buf
}

func encodeHPACKString(s string) []byte {
	length := len(s)
	if length < 127 {
		return append([]byte{byte(length)}, []byte(s)...)
	}
	// For longer strings, use multi-byte length encoding
	buf := []byte{127}
	remaining := length - 127
	for remaining >= 128 {
		buf = append(buf, byte(remaining%128+128))
		remaining /= 128
	}
	buf = append(buf, byte(remaining))
	return append(buf, []byte(s)...)
}

func (s *Scanner) loadPayloads() []Payload {
	var payloads []Payload

	if s.gadgetFile != "" {
		lines, err := readPayloadsFile(s.gadgetFile)
		if err != nil {
			s.printer.Error("Error reading gadget file: %v", err)
			return nil
		}
		for _, line := range lines {
			p := parsePayloadLine(line)
			if p != nil {
				payloads = append(payloads, *p)
			}
		}
		return payloads
	}

	gadgetList := DefaultGadgetList
	if s.extended {
		gadgetList = ExtendedGadgetList
	}

	lines := strings.Split(gadgetList, "\n")
	for _, line := range lines {
		p := parsePayloadLine(line)
		if p != nil {
			payloads = append(payloads, *p)
		}
	}

	return payloads
}

func parsePayloadLine(line string) *Payload {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	parts := strings.SplitN(line, "; ", 2)
	if len(parts) != 2 {
		return nil
	}

	headerName := parts[0]
	headerValue := parts[1]

	// Process escape sequences
	headerName = strings.ReplaceAll(headerName, "\\r", "\r")
	headerName = strings.ReplaceAll(headerName, "\\n", "\n")
	headerName = strings.ReplaceAll(headerName, "\\t", "\t")
	headerValue = strings.ReplaceAll(headerValue, "\\r", "\r")
	headerValue = strings.ReplaceAll(headerValue, "\\n", "\n")
	headerValue = strings.ReplaceAll(headerValue, "\\t", "\t")

	return &Payload{
		HeaderName:  headerName,
		HeaderValue: headerValue,
		Name:        line,
	}
}

func readPayloadsFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
