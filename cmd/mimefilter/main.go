package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"opensmtpd-filter-mimetype/internal/config"
	"opensmtpd-filter-mimetype/internal/log"
	"opensmtpd-filter-mimetype/internal/protocol"
	"opensmtpd-filter-mimetype/internal/session"
	"log/syslog"
)

const ConfigPath = "/etc/opensmtpd-filter-mimetype.yaml"

func main() {
	// Load configuration
	cfg, allowedMime, logLevel, err := config.LoadConfig(ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize syslog
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_MAIL, cfg.LogTag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Syslog connection failed: %v\n", err)
	} else {
		defer sysLogger.Close()
		log.SetLevel(logLevel)
	}

	log.Info("Filter started. Tag: %s, Level: %s, Buffer: %dMB", cfg.LogTag, cfg.LogLevel, cfg.ScannerBufferMB)

	// Output channel
	outputChan := make(chan string, 100)
	go func() {
		for line := range outputChan {
			fmt.Println(line)
		}
	}()

	// Session manager
	sessMgr := session.NewManager()
	headerSize := cfg.HeaderInspectSize
	handler := protocol.NewProtocolHandler(sessMgr, allowedMime, headerSize, outputChan)

	// Input scanner with buffer
	scanner := bufio.NewScanner(os.Stdin)
	bufferBytes := cfg.ScannerBufferMB * 1024 * 1024
	if bufferBytes < 1024*1024 {
		bufferBytes = 10 * 1024 * 1024
		log.Warn("Configured buffer too small. Defaulting to 10MB.")
	}
	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)

	// Register hooks with OpenSMTPD
	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")

	// Main loop
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		eventType := parts[0]

		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Warn("PANIC RECOVERED: %v", r)
				}
			}()

			if eventType == "report" && len(parts) >= 6 && parts[4] == "link-disconnect" {
				handler.HandleDisconnect(parts[5])
			} else if eventType == "filter" && len(parts) >= 6 {
				phase := parts[4]
				sid := parts[5]
				token := ""
				if len(parts) > 6 {
					token = parts[6]
				}

				if phase == "data-line" && len(parts) >= 8 {
					content := strings.Join(parts[7:], "|")
					handler.HandleDataLine(sid, token, content)
				} else if phase == "commit" {
					handler.HandleCommit(sid, token)
				}
			}
		}()
	}
}
