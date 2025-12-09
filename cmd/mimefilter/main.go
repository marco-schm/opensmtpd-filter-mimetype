package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/config"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/log"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/mimecheck"
)

const ConfigPath = "/etc/opensmtpd-filter-mimetype.yaml"

func main() {
	cfg, allowedMime, logLevel, err := config.LoadConfig(ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	log.SetLevel(logLevel)
	log.Info("Filter started. Tag: %s, Level: %s, Buffer: %dMB", cfg.LogTag, cfg.LogLevel, cfg.ScannerBufferMB)

	outputChan := make(chan string, 100)
	go consumeOutput(outputChan)

	sessionMgr := log.NewManager()
	handler := log.NewProtocolHandler(sessionMgr, allowedMime, cfg.HeaderInspectSize, outputChan, mimecheck.CheckMail)

	scanner := newScanner(cfg.ScannerBufferMB)
	registerFilter()

	runEventLoop(scanner, handler)
}

func newScanner(bufferMB int) *bufio.Scanner {
	scanner := bufio.NewScanner(os.Stdin)
	bufferBytes := bufferMB * 1024 * 1024
	if bufferBytes < 1024*1024 {
		bufferBytes = 10 * 1024 * 1024
		log.Warn("Configured buffer too small. Defaulting to 10MB.")
	}
	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)
	return scanner
}

func registerFilter() {
	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")
}

func consumeOutput(outputChan chan string) {
	for line := range outputChan {
		fmt.Println(line)
	}
}

func runEventLoop(scanner *bufio.Scanner, handler *log.ProtocolHandler) {
	for scanner.Scan() {
		line := scanner.Text()
		log.Debug("RAW LINE: %s", line)

		event, phase, sid, token, content := parseLine(line)
		handleEvent(event, phase, sid, token, content, handler)
	}
}

func parseLine(line string) (event, phase, sid, token, content string) {
	parts := strings.SplitN(line, "|", 8)

	if len(parts) > 0 {
		event = parts[0]
	}
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

	if event == "filter" && phase == "data-line" {
		if content == "." || content == token+"|"+"." {
			content = "."
		} else if strings.HasPrefix(content, token+"|") {
			content = strings.TrimPrefix(content, token+"|")
		}
	}
	return
}

func handleEvent(event, phase, sid, token, content string, handler *log.ProtocolHandler) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("PANIC RECOVERED: %v", r)
		}
	}()

	switch event {
	case "report":
		if phase == "link-disconnect" {
			handler.HandleDisconnect(sid)
		}
	case "filter":
		switch phase {
		case "data-line":
			handler.HandleDataLine(sid, token, content)
		case "commit":
			handler.HandleCommit(sid, token)
		}
	}
}
