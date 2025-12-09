package mail

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/logging"
)

func CheckMailPart(lines []string, allowed map[string]bool, headerInspectSize int) string {
	rawMail := strings.Join(lines, "\n")
	if strings.TrimSpace(rawMail) == "" {
		return "Empty mail"
	}

	msg, err := mail.ReadMessage(strings.NewReader(rawMail))
	if err != nil {
		logging.Debug("Failed to parse mail headers: %v", err)
		return "Malformed mail headers"
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		logging.Debug("Content-Type not found or parse error: %v", err)
		mediaType = "text/plain"
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		head := make([]byte, headerInspectSize)
		n, _ := msg.Body.Read(head)
		detectedMime := http.DetectContentType(head[:n])
		if !allowed[strings.ToLower(detectedMime)] && !strings.HasPrefix(detectedMime, "text/") {
			return "Forbidden MIME type: " + CleanString(detectedMime)
		}
		return ""
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	decoder := new(mime.WordDecoder)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			logging.Debug("Skipping malformed part: %v", err)
			continue
		}

		filename := part.FileName()
		if decoded, err := decoder.DecodeHeader(filename); err == nil && decoded != "" {
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
		detectedMime := http.DetectContentType(head[:n])
		realMime, _, _ := mime.ParseMediaType(detectedMime)
		if realMime == "" {
			realMime = detectedMime
		}

		if filename != "" || !strings.HasPrefix(realMime, "text/") {
			if !allowed[strings.ToLower(realMime)] {
				return "Forbidden MIME type: " + CleanString(realMime) + " (File: " + CleanString(filename) + ")"
			}
		}
	}

	return ""
}
