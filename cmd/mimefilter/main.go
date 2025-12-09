package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
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

type AppConfig struct {
	LogTag            string   `yaml:"log_tag"`
	LogLevel          string   `yaml:"log_level"`
	ScannerBufferMB   int      `yaml:"scanner_buffer_max_mb"`
	AllowedMimeTypes  []string `yaml:"allowed_mime_types"`
	MaxInspectBytes   int      `yaml:"max_inspect_bytes"`
	HeaderInspectSize int      `yaml:"header_inspect_size"`
}

func LoadConfig(path string) (AppConfig, map[string]bool, int, error) {
	var cfg AppConfig

	file, err := os.Open(path)
	if err != nil {
		return cfg, nil, 0, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, nil, 0, err
	}

	if cfg.HeaderInspectSize <= 0 {
		cfg.HeaderInspectSize = 512
	}
	if cfg.ScannerBufferMB <= 0 {
		cfg.ScannerBufferMB = 10
	}
	if cfg.LogTag == "" {
		cfg.LogTag = "mime-filter"
	}

	level := 1
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = 0
	case "warn":
		level = 2
	case "error":
		level = 3
	}

	mimeMap := make(map[string]bool)
	for _, m := range cfg.AllowedMimeTypes {
		mimeMap[strings.ToLower(m)] = true
	}

	return cfg, mimeMap, level, nil
}

var currentLogLevel int

func SetLevel(level int) {
	currentLogLevel = level
}

func Debug(format string, v ...interface{}) {
	if currentLogLevel <= 0 {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func Info(format string, v ...interface{}) {
	if currentLogLevel <= 1 {
		log.Printf("[INFO] "+format, v...)
	}
}

func Warn(format string, v ...interface{}) {
	if currentLogLevel <= 2 {
		log.Printf("[WARN] "+format, v...)
	}
}

type Session struct {
	ID      string
	Message []string
}

type Manager struct {
	sessions map[string]*Session
	lock     sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

func (m *Manager) GetOrCreate(id string) *Session {
	m.lock.Lock()
	defer m.lock.Unlock()
	s, exists := m.sessions[id]
	if !exists {
		s = &Session{ID: id, Message: []string{}}
		m.sessions[id] = s
	}
	return s
}

func (m *Manager) Delete(id string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.sessions, id)
}

func CheckMailPart(lines []string, allowedMime map[string]bool, headerInspectSize int) string {
	rawMail := strings.Join(lines, "\n")
	if strings.TrimSpace(rawMail) == "" {
		return "Empty mail"
	}

	msg, err := mail.ReadMessage(strings.NewReader(rawMail))
	if err != nil {
		Debug("Failed to parse mail headers: %v", err)
		return "Malformed mail headers"
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		Debug("Content-Type not found or parse error: %v", err)
		mediaType = "text/plain"
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		head := make([]byte, headerInspectSize)
		n, _ := msg.Body.Read(head)
		detectedMime := http.DetectContentType(head[:n])
		if !allowedMime[strings.ToLower(detectedMime)] && !strings.HasPrefix(detectedMime, "text/") {
			return fmt.Sprintf("Forbidden MIME type: %s", CleanString(detectedMime))
		}
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
			Debug("Skipping malformed part: %v", err)
			continue
		}

		filename := part.FileName()
		if decoded, err := wordDecoder.DecodeHeader(filename); err == nil && decoded != "" {
			filename = decoded
		}

		encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		var reader io.Reader = part
		switch encoding {
		case "base64":
			reader = base64.NewDecoder(base64.StdEncoding, part)
		case "quoted-printable":
			reader = quotedprintable.NewReader(part)
		}

		head := make([]byte, headerInspectSize)
		n, _ := io.ReadFull(reader, head)
		if n == 0 && filename == "" {
			continue
		}

		detectedMime := http.DetectContentType(head[:n])
		realMime, _, _ := mime.ParseMediaType(detectedMime)
		if realMime == "" {
			realMime = detectedMime
		}

		if filename != "" || !strings.HasPrefix(realMime, "text/") {
			if !allowedMime[strings.ToLower(realMime)] {
				return fmt.Sprintf("Forbidden MIME type: %s (File: %s)", CleanString(realMime), CleanString(filename))
			}
		}
	}

	return ""
}

func CleanString(s string) string {
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

type ProtocolHandler struct {
	SessionManager *Manager
	AllowedMime    map[string]bool
	HeaderSize     int
	outputChan     chan string
	CheckFunc      func([]string, map[string]bool, int) string
}

func NewProtocolHandler(sessMgr *Manager, allowedMime map[string]bool, headerSize int, outputChan chan string) *ProtocolHandler {
	return &ProtocolHandler{
		SessionManager: sessMgr,
		AllowedMime:    allowedMime,
		HeaderSize:     headerSize,
		outputChan:     outputChan,
		CheckFunc:      CheckMailPart,
	}
}

func (p *ProtocolHandler) HandleDataLine(sid, token, line string) {
	s := p.SessionManager.GetOrCreate(sid)

	if line == "." {
		s.Message = append(s.Message, line)
		Debug("[%s] DATA-LINE: End of message (.)", sid)
	} else {
		if strings.HasPrefix(line, "..") {
			s.Message = append(s.Message, line[1:])
		} else {
			s.Message = append(s.Message, line)
		}
		Debug("[%s] DATA-LINE: %s", sid, line)
	}


	p.produceOutput("filter-dataline", sid, token, "%s", line)
}

func (p *ProtocolHandler) HandleCommit(sid, token string) {
	s := p.SessionManager.GetOrCreate(sid)

	// Prüfen, ob Mail Header hat
	hasHeader := false
	for _, l := range s.Message {
		if strings.Contains(l, ":") {
			hasHeader = true
			break
		}
	}

	if !hasHeader {
		Warn("[%s] REJECTING: No valid headers found", sid)
		p.produceOutput("filter-result", sid, token, "reject|550 Policy violation: No valid headers")
		p.SessionManager.Delete(sid)
		return
	}

	rejectReason := p.CheckFunc(s.Message, p.AllowedMime, p.HeaderSize)

	if rejectReason == "" {
		Info("[%s] Mail accepted.", sid)
		p.produceOutput("filter-result", sid, token, "proceed")
	} else {
		Warn("[%s] REJECTING: %s", sid, rejectReason)
		p.produceOutput("filter-result", sid, token, "reject|550 Policy violation: %s", rejectReason)
	}

	p.SessionManager.Delete(sid)
}


func (p *ProtocolHandler) HandleDisconnect(sid string) {
	p.SessionManager.Delete(sid)
	Debug("[%s] Session cleaned up.", sid)
}

func (p *ProtocolHandler) produceOutput(msgType, sid, token, format string, a ...interface{}) {
	payload := fmt.Sprintf(format, a...)
	out := fmt.Sprintf("%s|%s|%s|%s", msgType, sid, token, payload)
	Debug("Output: %s", out)
	select {
	case p.outputChan <- out:
	default:
		fmt.Println(out)
	}
}

const ConfigPath = "/etc/opensmtpd-filter-mimetype.yaml"

func main() {
	cfg, allowedMime, logLevel, err := LoadConfig(ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	SetLevel(logLevel)
	Info("Filter started. Tag: %s, Level: %s, Buffer: %dMB", cfg.LogTag, cfg.LogLevel, cfg.ScannerBufferMB)

	outputChan := make(chan string, 100)
	go func() {
		for line := range outputChan {
			fmt.Println(line)
		}
	}()

	sessMgr := NewManager()
	handler := NewProtocolHandler(sessMgr, allowedMime, cfg.HeaderInspectSize, outputChan)

	scanner := bufio.NewScanner(os.Stdin)
	bufferBytes := cfg.ScannerBufferMB * 1024 * 1024
	if bufferBytes < 1024*1024 {
		bufferBytes = 10 * 1024 * 1024
		Warn("Configured buffer too small. Defaulting to 10MB.")
	}
	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)

	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")

for scanner.Scan() {
	line := scanner.Text()
	Debug("RAW LINE: %s", line)

	// Data-Line hat 8 Teile: filter|version|timestamp|smtp-in|data-line|sessionID|token|content
	parts := strings.SplitN(line, "|", 8)
	if len(parts) < 3 {
		continue
	}

	eventType := parts[0]
	phase := ""
	sid := ""
	token := ""
	content := ""

	if len(parts) >= 5 {
		phase = parts[4]
	}
	if len(parts) >= 6 {
		sid = parts[5]
	}
	if len(parts) >= 7 {
		token = parts[6]
	}
	if len(parts) == 8 {
		content = parts[7]
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				Warn("PANIC RECOVERED: %v", r)
			}
		}()

		switch eventType {
		case "report":
			if phase == "link-disconnect" {
				handler.HandleDisconnect(sid)
			}
		case "filter":
			if phase == "data-line" {
				// Wenn die Zeile nur Token + Punkt ist
				if content == "." || content == token+"|"+"." {
					content = "."
				} else if strings.HasPrefix(content, token+"|") {
					content = strings.TrimPrefix(content, token+"|")
				}
				handler.HandleDataLine(sid, token, content)
			} else if phase == "commit" {
				handler.HandleCommit(sid, token)
			}
		}
	}()
}


}