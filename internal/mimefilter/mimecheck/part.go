package mimecheck

import (
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/log"
)

// Prüft einen einzelnen Part (kein multipart)
func CheckSinglePart(body io.Reader, allowedMime map[string]bool, headerSize int, logger *log.Logger) string {
	head := make([]byte, headerSize)
	n, _ := body.Read(head)
	detected := http.DetectContentType(head[:n])
	if !allowedMime[strings.ToLower(detected)] && !strings.HasPrefix(detected, "text/") {
		return "Forbidden MIME type: " + cleanString(detected)
	}
	return ""
}
