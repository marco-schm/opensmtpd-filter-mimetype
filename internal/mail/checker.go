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

// maxMultipartDepth bounds recursion into nested multipart containers and
// attached rfc822 messages. Anything nested deeper is rejected rather than
// skipped, so the limit cannot be used to smuggle attachments past the filter.
const maxMultipartDepth = 5

// whitespaceStripper wraps an io.Reader and strips CR, LF, space, and tab
// characters from the stream, so base64 decoding also works for parts whose
// lines contain whitespace the standard decoder would choke on.
type whitespaceStripper struct {
	r io.Reader
}

func (w *whitespaceStripper) Read(p []byte) (int, error) {
	for {
		n, err := w.r.Read(p)
		j := 0
		for i := 0; i < n; i++ {
			if p[i] != '\r' && p[i] != '\n' && p[i] != ' ' && p[i] != '\t' {
				p[j] = p[i]
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}

func CheckMail(rawMail string, allowed map[string]bool, headerInspectSize int) string {
	if strings.TrimSpace(rawMail) == "" {
		return "Empty mail"
	}

	msg, err := mail.ReadMessage(strings.NewReader(rawMail))
	if err != nil {
		logging.Debug("Failed to parse mail headers: %v", err)
		return "Malformed mail headers"
	}

	return checkEntity(msg.Header.Get("Content-Type"), msg.Body, allowed, headerInspectSize, 0)
}

// checkEntity inspects a single MIME entity and recurses into nested
// multipart containers and attached rfc822 messages.
func checkEntity(contentType string, body io.Reader, allowed map[string]bool, headerInspectSize, depth int) string {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		logging.Debug("Content-Type not found or parse error: %v", err)
		mediaType = "text/plain"
	}

	if mediaType == "message/rfc822" {
		if depth >= maxMultipartDepth {
			return "Multipart nesting too deep"
		}
		inner, err := mail.ReadMessage(body)
		if err != nil {
			logging.Debug("Failed to parse attached message: %v", err)
			return "Malformed attached message"
		}
		return checkEntity(inner.Header.Get("Content-Type"), inner.Body, allowed, headerInspectSize, depth+1)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		head := make([]byte, headerInspectSize)
		n, _ := io.ReadFull(body, head)
		detectedMime := http.DetectContentType(head[:n])
		realMime, _, _ := mime.ParseMediaType(detectedMime)
		if realMime == "" {
			realMime = detectedMime
		}
		if !allowed[strings.ToLower(realMime)] && !strings.HasPrefix(realMime, "text/") {
			return "Forbidden MIME type: " + CleanString(realMime)
		}
		return ""
	}

	if depth >= maxMultipartDepth {
		return "Multipart nesting too deep"
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "Malformed multipart message: missing boundary"
	}

	mr := multipart.NewReader(body, boundary)
	decoder := new(mime.WordDecoder)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// NextPart can return the same non-EOF error on every call
			// (e.g. truncated input) — retrying would spin forever.
			logging.Debug("Stopping multipart scan on error: %v", err)
			break
		}

		filename := part.FileName()
		if decoded, err := decoder.DecodeHeader(filename); err == nil && decoded != "" {
			filename = decoded
		}

		encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		var reader io.Reader = part
		switch encoding {
		case "base64":
			reader = base64.NewDecoder(base64.StdEncoding, &whitespaceStripper{r: part})
		case "quoted-printable":
			reader = quotedprintable.NewReader(part)
		}

		partType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if strings.HasPrefix(partType, "multipart/") || partType == "message/rfc822" {
			if reason := checkEntity(part.Header.Get("Content-Type"), reader, allowed, headerInspectSize, depth+1); reason != "" {
				return reason
			}
			continue
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
