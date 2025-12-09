package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/config"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/logging"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/protocol"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/session"
)

const ConfigPath = "/etc/opensmtpd-filter-mimetype.yaml"

func main() {
	cfg, allowedMime, logLevel, err := config.LoadConfig(ConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRITICAL: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logging.SetLevel(logLevel)
	logging.Info("Filter started. Tag: %s Level: %s Buffer=%dMB", cfg.LogTag, cfg.LogLevel, cfg.ScannerBufferMB)

	outputChan := make(chan string, 200)
	go func() {
		for line := range outputChan {
			fmt.Println(line)
		}
	}()

	manager := session.NewManager()
	handler := protocol.NewProtocolHandler(manager, allowedMime, cfg.HeaderInspectSize, outputChan)

	scanner := bufio.NewScanner(os.Stdin)
	bufferBytes := cfg.ScannerBufferMB * 1024 * 1024
	buf := make([]byte, 0, bufferBytes)
	scanner.Buffer(buf, bufferBytes)

	fmt.Println("register|filter|smtp-in|data-line")
	fmt.Println("register|filter|smtp-in|commit")
	fmt.Println("register|report|smtp-in|link-disconnect")
	fmt.Println("register|ready")

	for scanner.Scan() {
		line := scanner.Text()
		logging.Debug("RAW LINE: %s", line)

		parts := strings.SplitN(line, "|", 8)
		if len(parts) < 3 {
			continue
		}

		event := parts[0]
		phase := safe(parts, 4)
		sid := safe(parts, 5)
		token := safe(parts, 6)
		data := safe(parts, 7)

		func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Warn("PANIC RECOVERED: %v", r)
				}
			}()

			switch event {
			case "report":
				if phase == "link-disconnect" {
					handler.HandleDisconnect(sid)
				}
			case "filter":
				if phase == "data-line" {
					handler.HandleDataLine(sid, token, data)
				} else if phase == "commit" {
					handler.HandleCommit(sid, token)
				}
			}
		}()
	}
}

func safe(a []string, i int) string {
	if len(a) > i {
		return a[i]
	}
	return ""
}
