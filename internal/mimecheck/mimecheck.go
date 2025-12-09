package mimecheck

import (
	"bufio"
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

type StringSliceReader struct {
	lines []string
	curr  int
	r     *strings.Reader
}

func NewStringSliceReader(lines []string) *StringSliceReader {
	return &StringSliceReader{lines: lines}
}

func (r *StringSliceReader) Read(p []byte) (n int, err error) {
	for {
		if r.r == nil {
			if r.curr >= len(r.lines) {
				return 0, io.EOF
			}
			r.r = strings.NewReader(r.lines[r.curr] + "\n")
			r.curr++
		}
		n, err = r.r.Read(p)
		if err == io.EOF {
			r.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func CheckMailContent(lines []string, allowedMime map[string]bool, headerInspectSize, maxInspectBytes int) string {
	r := NewStringSliceReader(lines)

	msg, err := mail.ReadMessage(r)
	if err != nil {
		return ""
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
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
			continue
		}

		filename := part.FileName()
		if decoded, err := wordDecoder.DecodeHeader(filename); err == nil && decoded != "" {
			filename = decoded
		}

		encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		var decodedReader io.Reader = part

		switch encoding {
		case "base64":
			decodedReader = base64.NewDecoder(base64.StdEncoding, part)
		case "quoted-printable":
			decodedReader = quotedprintable.NewReader(part)
		}

		head := make([]byte, headerInspectSize)
		n, _ := io.ReadFull(decodedReader, head)
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

		if maxInspectBytes > 0 {
			remaining := maxInspectBytes - n
			if remaining > 0 {
				buf := make([]byte, 4096)
				for remaining > 0 {
					toRead := buf
					if remaining < len(buf) {
						toRead = buf[:remaining]
					}
					m, err := decodedReader.Read(toRead)
					if m > 0 {
						remaining -= m
					}
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						break
					}
					if err != nil {
						break
					}
				}
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
