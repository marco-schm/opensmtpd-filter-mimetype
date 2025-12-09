package mimecheck

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/log"
)

func CheckMultipart(body io.Reader, boundary string, allowedMime map[string]bool, headerSize int, logger *log.Logger) string {
	mr := multipart.NewReader(body, boundary)
	wordDecoder := new(mime.WordDecoder)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Debug("Skipping malformed part: %v", err)
			continue
		}

		filename := decodeFilename(part.FileName(), wordDecoder)
		reader := wrapEncoding(part, part.Header.Get("Content-Transfer-Encoding"))

		head := make([]byte, headerSize)
		n, _ := io.ReadFull(reader, head)
		if n == 0 && filename == "" {
			continue
		}

		detected := http.DetectContentType(head[:n])
		if !strings.HasPrefix(detected, "text/") && !allowedMime[strings.ToLower(detected)] {
			return "Forbidden MIME type: " + cleanString(detected) + " (File: " + cleanString(filename) + ")"
		}
	}
	return ""
}

func decodeFilename(name string, decoder *mime.WordDecoder) string {
	if decoded, err := decoder.DecodeHeader(name); err == nil && decoded != "" {
		return decoded
	}
	return name
}
