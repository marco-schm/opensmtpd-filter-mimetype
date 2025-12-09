package mimecheck

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"strings"
)

// CheckMailPart scans only relevant parts of a multipart email (attachments or non-text)
// lines: raw email lines collected so far
// allowedMime: map of allowed MIME types (lowercase)
// headerInspectSize: bytes to read for MIME detection
// Returns a rejection reason string if disallowed content is found, empty otherwise.
func CheckMailPart(lines []string, allowedMime map[string]bool, headerInspectSize int) string {
	
	// Join only enough lines to parse headers
	msg, err := mail.ReadMessage(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		// Failed parsing headers: ignore
		return ""
	}

	// Check if Content-Type is multipart
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return "" // Nothing to check if not multipart
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	wordDecoder := new(mime.WordDecoder)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed parts
		}

		// Decode filename if MIME-encoded
		filename := part.FileName()
		if decoded, err := wordDecoder.DecodeHeader(filename); err == nil && decoded != "" {
			filename = decoded
		}

		// Determine content transfer encoding
		encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		var reader io.Reader = part
		switch encoding {
		case "base64":
			reader = base64.NewDecoder(base64.StdEncoding, part)
		case "quoted-printable":
			reader = quotedprintable.NewReader(part)
		}

		// Read only the first few bytes for MIME detection
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

		// Only enforce whitelist for attachments or non-text content
		if filename != "" || !strings.HasPrefix(realMime, "text/") {
			if !allowedMime[strings.ToLower(realMime)] {
				return fmt.Sprintf(
					"Forbidden MIME type: %s (File: %s)",
					CleanString(realMime),
					CleanString(filename),
				)
			}
		}
	}

	return "" // All relevant parts are allowed
}

// CleanString replaces non-printable or dangerous characters for safe logging/output
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
