
/*
Copyright (c) 2025 Marco Schmitt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3" 
)

const (
	ConfigPath = "/etc/opensmtp-filter-mimetype.yaml"
)

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

var config AppConfig
var currentLogLevel int

type AppConfig struct {
	LogTag           string   `yaml:"log_tag"`
	LogLevel         string   `yaml:"log_level"`
	ScannerBufferMB  int      `yaml:"scanner_buffer_max_mb"`
	AllowedMimeTypes []string `yaml:"allowed_mime_types"`
}

var (
	outputChannel  chan string
	allowedMimeMap = make(map[string]bool)
	sessions       = make(map[string]*session)
	sessLock       sync.Mutex
)

type session struct {
	id      string
	message []string
}

// produceOutput formats and sends the protocol message to stdout.
func produceOutput(msgType, sessionId, token, format string, a ...interface{}) {
	payload := fmt.Sprintf(format, a...)
	out := fmt.Sprintf("%s|%s|%s|%s", msgType, sessionId, token, payload)
	outputChannel <- out
}

func main() {
	// 1. Load Configuration first
	if err := loadConfig(ConfigPath); err != nil {
		// Fallback logging to stderr if config fails
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Syslog with configured Tag
	logger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_MAIL, config.LogTag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to connect to syslog: %v\n", err)
	} else {
		log.SetOutput(logger)
		log.SetFlags(0)
	}
	defer logger.Close()

	LogInfo("Filter started. Tag: %s, Level: %s, Buffer: %dMB", config.LogTag, config.LogLevel, config.ScannerBufferMB)

	// 3. Start Output Routine
	outputChannel = make(chan string)
	go func() {
		for line := range outputChannel {
			fmt.Println(line)
		}
	}()

	// 4. Input Scanner Setup
	scanner := bufio.NewScanner(os.Stdin)
	// Calculate buffer size in bytes (MB * 1024 * 1024)
	bufferBytes := config.ScannerBufferMB * 1024 * 1024
	
	// Use a default buffer size if the configured value is too low or 0
	if bufferBytes < 1024 * 1024 {
		bufferBytes = 10 * 1024 * 1024
		LogWarn("Configured buffer size too small. Defaulting to 10MB.")
	}

	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)

	// Register OpenSMTPD Hooks
	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")

	// 5. Main Loop
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")

		if len(parts) < 3 {
			continue
		}

		eventType := parts[0]

		// Event handling with Panic Recovery
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
					content := strings.Join(parts[7:], "|")
					handleDataLine(sid, token, content)
				} else if phase == "commit" {
					handleCommit(sid, token)
				}
			}
		}()
	}
}

// loadConfig reads the YAML file and initializes the global config.
func loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use YAML decoder
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return err
	}

	// Set Log Level Integer
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

	// Populate Map for O(1) lookups
	for _, mimeType := range config.AllowedMimeTypes {
		allowedMimeMap[strings.ToLower(mimeType)] = true
	}

	// Defaults and checks
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

// --- Handlers ---

func handleDisconnect(sid string) {
	sessLock.Lock()
	delete(sessions, sid)
	sessLock.Unlock()
	LogDebug("[%s] Session cleaned up.", sid)
}

func handleDataLine(sid, token, line string) {
	sessLock.Lock()
	s, exists := sessions[sid]
	if !exists {
		s = &session{id: sid, message: []string{}}
		sessions[sid] = s
	}

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

func handleCommit(sid, token string) {
	sessLock.Lock()
	s, exists := sessions[sid]
	sessLock.Unlock()

	if !exists {
		produceOutput("filter-result", sid, token, "proceed")
		return
	}

	rejectReason := checkMailContent(s.message)
	handleDisconnect(sid)

	if rejectReason != "" {
		LogWarn("[%s] REJECTING: %s", sid, rejectReason)
		produceOutput("filter-result", sid, token, "reject|550 Policy violation: %s", rejectReason)
	} else {
		LogInfo("[%s] Mail accepted.", sid)
		produceOutput("filter-result", sid, token, "proceed")
	}
}

// checkMailContent parses the email body and validates attachments against the whitelist.
func checkMailContent(lines []string) string {
	fullMsg := strings.Join(lines, "\n")
	reader := strings.NewReader(fullMsg)
	msg, err := mail.ReadMessage(reader)

	if err != nil {
		LogDebug("Failed to parse mail headers: %v", err)
		return ""
	}

	wordDecoder := new(mime.WordDecoder)
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))

	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				LogDebug("Multipart parsing error: %v", err)
				break
			}

			partType := p.Header.Get("Content-Type")
			mimeType, _, _ := mime.ParseMediaType(partType)

			rawFilename := p.FileName()
			decoded, dErr := wordDecoder.DecodeHeader(rawFilename)
			if dErr == nil {
				rawFilename = decoded
			}

			if mimeType == "" {
				if rawFilename != "" {
					mimeType = "application/octet-stream"
				} else {
					continue
				}
			}

			if rawFilename != "" || !strings.HasPrefix(mimeType, "text/") {
				if !isAllowed(mimeType) {
					safeFilename := cleanString(rawFilename)
					safeMime := cleanString(mimeType)
					return fmt.Sprintf("Forbidden MIME type: %s (File: %s)", safeMime, safeFilename)
				}
				LogDebug("Allowed attachment: %s (%s)", rawFilename, mimeType)
			}
		}
	}
	return ""
}

func isAllowed(m string) bool {
	if strings.HasPrefix(m, "text/plain") || strings.HasPrefix(m, "text/html") {
		return true
	}
	return allowedMimeMap[strings.ToLower(m)]
}

// cleanString removes non-printable characters and protocol separators ('|').
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
