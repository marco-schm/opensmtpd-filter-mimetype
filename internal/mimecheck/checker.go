package mimecheck

import (
	"io"
	"net/mail"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/log"
)

func CheckMail(lines []string, allowedMime map[string]bool, headerInspectSize int, logger *log.Logger) string {
	rawMail := joinLines(lines)
	if rawMail == "" {
		return "Empty mail"
	}

	msg, err := mail.ReadMessage(strings.NewReader(rawMail))
	if err != nil {
		logger.Debug("Failed to parse mail headers: %v", err)
		return "Malformed mail headers"
	}

	return checkMessage(msg, allowedMime, headerInspectSize, logger)
}
