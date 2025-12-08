/*
Copyright 2025 Marco Schmitt

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const ConfigPath = "/etc/opensmtp-filter-mimetype.yaml"

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	config         AppConfig
	currentLogLevel int
	outputChannel  chan string
	allowedMimeMap = make(map[string]bool)
	sessions       = make(map[string]*session)
	sessLock       sync.Mutex
)

type AppConfig struct {
	LogTag           string   `yaml:"log_tag"`
	LogLevel         string   `yaml:"log_level"`
	ScannerBufferMB  int      `yaml:"scanner_buffer_max_mb"`
	AllowedMimeTypes []string `yaml:"allowed_mime_types"`
}

type session struct {
	id      string
	message []string
}

func main() {
	if err := loadConfig(ConfigPath); err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_MAIL, config.LogTag)
	if err == nil {
		log.SetOutput(logger)
		log.SetFlags(0)
		defer logger.Close()
	}

	LogInfo("Filter started. Tag=%s Level=%s Buffer=%dMB", config.LogTag, config.LogLevel, config.ScannerBufferMB)

	outputChannel = make(chan string)
	go func() { for l := range outputChannel { fmt.Println(l) } }()

	scanner := bufio.NewScanner(os.Stdin)
	bufferBytes := config.ScannerBufferMB * 1024 * 1024
	if bufferBytes < 1_000_000 {
		bufferBytes = 10_000_000
		LogWarn("Buffer too small, using fallback 10MB")
	}
	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)

	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) < 3 { continue }

		eventType := parts[0]
		func() {
			defer func() { if r := recover(); r != nil { LogWarn("PANIC: %v", r) } }()

			if eventType == "report" && len(parts) >= 6 && parts[4] == "link-disconnect" {
				handleDisconnect(parts[5]); return }
			if eventType == "filter" && len(parts) >= 6 {
				sid, token := parts[5], ""
				if len(parts) > 6 { token = parts[6] }

				if parts[4] == "data-line" && len(parts) >= 8 {
					handleDataLine(sid, token, strings.Join(parts[7:], "|"))
				} else if parts[4] == "commit" { handleCommit(sid, token) }
			}
		}()
	}
}

func loadConfig(path string) error {
	f, err := os.Open(path); if err != nil { return err }
	defer f.Close()

	if err := yaml.NewDecoder(f).Decode(&config); err != nil { return err }
	switch strings.ToLower(config.LogLevel) {
	case "debug": currentLogLevel = LevelDebug
	case "warn":  currentLogLevel = LevelWarn
	case "error": currentLogLevel = LevelError
	default:      currentLogLevel = LevelInfo
	}
	for _, t := range config.AllowedMimeTypes {
		allowedMimeMap[strings.ToLower(t)] = true
	}
	if config.ScannerBufferMB <= 0 { config.ScannerBufferMB = 10 }
	if config.LogTag == "" { config.LogTag = "mimefilter" }
	return nil
}


func LogDebug(fmt string, v ...interface{}) { if currentLogLevel <= LevelDebug { log.Printf("[DEBUG] "+fmt, v...) } }
func LogInfo(fmt string, v ...interface{})  { if currentLogLevel <= LevelInfo  { log.Printf("[INFO] "+fmt, v...) } }
func LogWarn(fmt string, v ...interface{})  { if currentLogLevel <= LevelWarn  { log.Printf("[WARN] "+fmt, v...) } }


func handleDisconnect(sid string) {
	sessLock.Lock(); delete(sessions, sid); sessLock.Unlock()
	LogDebug("[%s] session cleaned", sid)
}

func handleDataLine(sid, token, line string) {
	sessLock.Lock()
	s, ok := sessions[sid]
	if !ok { s = &session{id: sid}; sessions[sid] = s }
	if line != "." { 
		if strings.HasPrefix(line,".."){ line=line[1:] }
		s.message = append(s.message,line)
	}
	sessLock.Unlock()

	produceOutput("filter-dataline", sid, token, "%s", line)
}

func handleCommit(sid, token string) {
	sessLock.Lock(); s, ok := sessions[sid]; sessLock.Unlock()
	if !ok { produceOutput("filter-result", sid, token, "proceed"); return }
	reason := checkMailContent(s.message); handleDisconnect(sid)

	if reason != "" {
		LogWarn("[%s] BLOCK %s", sid, reason)
		produceOutput("filter-result", sid, token, "reject|550 Policy violation: %s", reason)
		return
	}
	LogInfo("[%s] Mail accepted",sid)
	produceOutput("filter-result", sid, token,"proceed")
}

func checkMailContent(lines []string) string {
	msg, _ := mail.ReadMessage(strings.NewReader(strings.Join(lines,"\n")))
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType,"multipart/") { return "" }

	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part,err := mr.NextPart(); if err==io.EOF { break }
		if err != nil { return "" }

		filename := part.FileName()
		if decoded,_:= new(mime.WordDecoder).DecodeHeader(filename); decoded!="" { filename=decoded }

		body,_ := io.ReadAll(part)
		realMime := http.DetectContentType(body)

		if !allowedMimeMap[strings.ToLower(realMime)] {
			return fmt.Sprintf("Forbidden MIME (real=%s file=%s)", realMime, clean(filename))
		}
		LogDebug("Attachment allowed: %s (%s)", filename, realMime)
	}
	return ""
}

func clean(s string) string {
	b:=make([]byte,0,len(s))
	for _,c:=range []byte(s){
		if c>=32 && c<=126 && c!='|' { b=append(b,c) } else { b=append(b,'?') }
	}
	return string(b)
}

func produceOutput(typ,sid,token,fmtStr string,a...interface{}) {
	outputChannel <- fmt.Sprintf("%s|%s|%s|%s", typ, sid, token, fmt.Sprintf(fmtStr,a...))
}
