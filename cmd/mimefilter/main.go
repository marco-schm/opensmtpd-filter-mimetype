/*
Copyright 2025 Marco Schmitt

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Constants
const (
	ConfigPath = "/etc/opensmtp-filter-mimetype.yaml"
)

// Log Levels
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Global Configuration and State
var (
	config          AppConfig
	currentLogLevel int
	outputChannel   chan string
	allowedMimeMap  = make(map[string]bool)
	sessions        = make(map[string]*session)
	sessLock        sync.Mutex
)

// AppConfig maps the YAML configuration file to a struct.
type AppConfig struct {
	LogTag            string   `yaml:"log_tag"`
	LogLevel          string   `yaml:"log_level"`
	ScannerBufferMB   int      `yaml:"scanner_buffer_max_mb"`
	AllowedMimeTypes  []string `yaml:"allowed_mime_types"`
	MaxInspectBytes   int      `yaml:"max_inspect_bytes"`   
	HeaderInspectSize int      `yaml:"header_inspect_size"`
}

// session holds the email transaction state.
// 'message' stores the raw lines of the email body for later analysis.
type session struct {
	id      string
	message []string
}

// StringSliceReader is a memory-efficient helper that implements io.Reader.
// It reads directly from a []string slice, adding newlines on the fly.
// This avoids using strings.Join() which would duplicate the entire email in RAM.
type StringSliceReader struct {
	lines []string
	curr  int             // current line index
	r     *strings.Reader // reader for the current line
}

// Read implements the io.Reader interface for StringSliceReader.
func (r *StringSliceReader) Read(p []byte) (n int, err error) {
	for {
		if r.r == nil {
			if r.curr >= len(r.lines) {
				return 0, io.EOF
			}
			// OpenSMTPD strips newlines, so we must re-add them for the MIME parser
			r.r = strings.NewReader(r.lines[r.curr] + "\n")
			r.curr++
		}
		n, err = r.r.Read(p)
		if err == io.EOF {
			r.r = nil // Line finished, move to next
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

// main is the entry point. It sets up logging, config, and the main event loop
// that listens to OpenSMTPD on Stdin.
func main() {
	// 1. Load Configuration
	if err := loadConfig(ConfigPath); err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Syslog
	logger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_MAIL, config.LogTag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Syslog connection failed: %v\n", err)
	} else {
		log.SetOutput(logger)
		log.SetFlags(0)
	}
	if logger != nil {
		defer logger.Close()
	}

	LogInfo("Filter started. Tag: %s, Level: %s, Buffer: %dMB", config.LogTag, config.LogLevel, config.ScannerBufferMB)

	// 3. Start Output Routine (Async stdout writing)
	outputChannel = make(chan string, 100)
	go func() {
		for line := range outputChannel {
			fmt.Println(line)
		}
	}()

	// 4. Input Scanner Setup
	scanner := bufio.NewScanner(os.Stdin)
	// Set buffer size to handle large lines (e.g. huge Base64 blocks)
	bufferBytes := config.ScannerBufferMB * 1024 * 1024
	if bufferBytes < 1024*1024 {
		bufferBytes = 10 * 1024 * 1024 // Fallback to 10MB
		LogWarn("Configured buffer too small. Defaulting to 10MB.")
	}

	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)

	// Register Hooks
	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")

	// 5. Main Event Loop
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")

		if len(parts) < 3 {
			continue
		}

		eventType := parts[0]

		// Execute handling in a closure to use recover() for panic protection
		func() {
			defer func() {
				if r := recover(); r != nil {
					LogWarn("PANIC RECOVERED: %v", r)
				}
			}()

			if eventType == "report" && len(parts) >= 6 {
				if parts[4] == "link-disconnect" {
					handleDisconnect(parts[5])
				}
			} else if eventType == "filter" && len(parts) >= 6 {
				phase := parts[4]
				sid := parts[5]
				token := ""
				if len(parts) > 6 {
					token = parts[6]
				}

				if phase == "data-line" && len(parts) >= 8 {
					// Re-join content in case the line contained pipes
					content := strings.Join(parts[7:], "|")
					handleDataLine(sid, token, content)
				} else if phase == "commit" {
					handleCommit(sid, token)
				}
			}
		}()
	}
}

// loadConfig reads the YAML file and sets up the global configuration state.
func loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return err
	}

	// Set defaults for optional fields
	if config.HeaderInspectSize <= 0 {
		config.HeaderInspectSize = 512
	}
	if config.MaxInspectBytes <= 0 {
		config.MaxInspectBytes = 0 // 0 means only headerInspectSize
	}

	// Map string log levels to integers
	switch strings.ToLower(config.LogLevel) {
	case "debug":
		currentLogLevel = LevelDebug
	case "warn":
		currentLogLevel = LevelWarn
	case "error":
		currentLogLevel = LevelError
	default:
		currentLogLevel = LevelInfo
	}

	// Populate lookup map for O(1) access
	for _, mimeType := range config.AllowedMimeTypes {
		allowedMimeMap[strings.ToLower(mimeType)] = true
	}

	// Set defaults
	if config.ScannerBufferMB <= 0 {
		config.ScannerBufferMB = 10
	}
	if config.LogTag == "" {
		config.LogTag = "mx-generic-filter"
	}

	return nil
}

// --- Logging Helpers ---

func LogDebug(format string, v ...interface{}) {
	if currentLogLevel <= LevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func LogInfo(format string, v ...interface{}) {
	if currentLogLevel <= LevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

func LogWarn(format string, v ...interface{}) {
	if currentLogLevel <= LevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

// --- Protocol Handlers ---

// handleDisconnect removes the session from memory when the client disconnects.
func handleDisconnect(sid string) {
	sessLock.Lock()
	delete(sessions, sid)
	sessLock.Unlock()
	LogDebug("[%s] Session cleaned up.", sid)
}

// handleDataLine buffers the incoming email content and immediately echoes it back
// to OpenSMTPD to keep the connection alive (Pass-through).
func handleDataLine(sid, token, line string) {
	sessLock.Lock()
	s, exists := sessions[sid]
	if !exists {
		s = &session{id: sid, message: []string{}}
		sessions[sid] = s
	}

	// Buffer line (except the final dot)
	if line != "." {
		if strings.HasPrefix(line, "..") {
			s.message = append(s.message, line[1:])
		} else {
			s.message = append(s.message, line)
		}
	}
	sessLock.Unlock()

	produceOutput("filter-dataline", sid, token, "%s", line)
}

// handleCommit is triggered when the email data transfer is complete.
// It initiates the content check and decides whether to accept or reject the mail.
func handleCommit(sid, token string) {
	sessLock.Lock()
	s, exists := sessions[sid]
	sessLock.Unlock()

	if !exists {
		produceOutput("filter-result", sid, token, "proceed")
		return
	}

	rejectReason := checkMailContent(s.message)

	if rejectReason == "" {
		LogInfo("[%s] Mail accepted, forwarding DATA back to smtpd.", sid)

		for _, line := range s.message {
			produceOutput("filter-dataline", sid, token, "%s", line)
		}
		produceOutput("filter-dataline", sid, token, ".")
		produceOutput("filter-result", sid, token, "proceed")
	} else {
		LogWarn("[%s] REJECTING: %s", sid, rejectReason)
		produceOutput("filter-result", sid, token, "reject|550 Policy violation: %s", rejectReason)
	}

	// cleanup
	handleDisconnect(sid)
}


// checkMailContent parses the raw email lines using a zero-copy reader.
// It iterates through multipart attachments and verifies them using Magic Bytes.
// Returns a rejection reason string if a violation is found, otherwise empty string.
func checkMailContent(lines []string) string {
	// Use our custom reader to avoid joining strings (Memory Optimization)
	r := &StringSliceReader{lines: lines}

	msg, err := mail.ReadMessage(r)
	if err != nil {
		LogDebug("Failed to parse mail headers: %v", err)
		return ""
	}

	// Only process multipart messages
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return ""
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	wordDecoder := new(mime.WordDecoder)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			LogDebug("Multipart parsing error: %v", err)
			break
		}

		filename := part.FileName()
		if decoded, err := wordDecoder.DecodeHeader(filename); err == nil && decoded != "" {
			filename = decoded
		}

		// Determine content-transfer-encoding and set up a reader that yields decoded bytes
		encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		var decodedReader io.Reader = part

		switch encoding {
		case "base64":
			decodedReader = base64.NewDecoder(base64.StdEncoding, part)
		case "quoted-printable":
			decodedReader = quotedprintable.NewReader(part)
		default:
			// 7bit/8bit/binary or empty - part is raw binary/text
			decodedReader = part
		}

		// Read headerInspectSize bytes for magic detection
		headerSize := config.HeaderInspectSize
		if headerSize <= 0 {
			headerSize = 512
		}
		head := make([]byte, headerSize)
		n, readErr := io.ReadFull(decodedReader, head)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			// log debug and continue to next part (do not fail entire mail)
			LogDebug("Error reading part header: %v", readErr)
		}

		// If nothing read and no filename, skip
		if n == 0 && filename == "" {
			// consume/skip remainder of this part implicitly by moving on
			continue
		}

		// Detect mime type from the decoded header bytes
		detectedMime := http.DetectContentType(head[:n])
		realMime, _, _ := mime.ParseMediaType(detectedMime)
		if realMime == "" {
			realMime = detectedMime
		}

		// If attachment (has filename) or non-text, enforce whitelist
		if filename != "" || !strings.HasPrefix(realMime, "text/") {
			if !allowedMimeMap[strings.ToLower(realMime)] {
				safeFilename := cleanString(filename)
				safeMime := cleanString(realMime)
				return fmt.Sprintf("Forbidden MIME type: %s (File: %s)", safeMime, safeFilename)
			}
			LogDebug("Attachment allowed: %s (detected as %s)", filename, realMime)
		}

		if config.MaxInspectBytes > 0 {
			remaining := config.MaxInspectBytes
			remaining -= n
			if remaining > 0 {
				buf := make([]byte, 4096)
				for remaining > 0 {
					toRead := buf
					if remaining < len(buf) {
						toRead = buf[:remaining]
					}
					m, err := decodedReader.Read(toRead)
					if m > 0 {
						remaining -= m
					}
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						break
					}
					if err != nil {
						LogDebug("Error while chunk-scanning part: %v", err)
						break
					}
				}
			}
		}
	}
	return ""
}

// isAllowed checks if the provided mime string is in the whitelist.
func isAllowed(m string) bool {
	if strings.HasPrefix(m, "text/plain") || strings.HasPrefix(m, "text/html") {
		return true
	}
	return allowedMimeMap[strings.ToLower(m)]
}

// cleanString removes non-printable characters and protocol separators ('|')
// to prevent protocol injection attacks against OpenSMTPD.
func cleanString(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 32 && c <= 126 && c != '|' {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

// produceOutput formats the protocol message and sends it to the stdout channel.
func produceOutput(msgType, sessionId, token, format string, a ...interface{}) {
	payload := fmt.Sprintf(format, a...)
	out := fmt.Sprintf("%s|%s|%s|%s", msgType, sessionId, token, payload)
	// best-effort non-blocking send to avoid deadlocks on full channel
	select {
	case outputChannel <- out:
	default:
		// channel full: fallback to direct print (keeps SMTP workflow alive)
		fmt.Println(out)
	}
}
