package mail

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"path"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/logging"
)

// maxMultipartDepth bounds recursion into nested multipart containers and
// attached rfc822 messages. Anything nested deeper is rejected rather than
// skipped, so the limit cannot be used to smuggle attachments past the filter.
const maxMultipartDepth = 5

// Limits for ZIP inspection. Nested archives are decompressed in memory, so
// both their size and the nesting depth are bounded (zip bombs).
const (
	maxArchiveDepth       = 3
	maxArchiveEntries     = 10000
	maxNestedArchiveBytes = 50 << 20
)

// DefaultBlockedExtensions lists file extensions that are rejected regardless
// of the sniffed content type: executables, scripts (which sniff as
// text/plain), shortcuts, disk images and macro-enabled Office formats.
var DefaultBlockedExtensions = []string{
	"exe", "com", "scr", "pif", "cpl", "msi", "msp", "mst", "msc", "dll", "ocx", "sys", "drv",
	"bat", "cmd", "ps1", "psm1", "psd1", "ps1xml", "psc1", "vb", "vbs", "vbe", "js", "jse",
	"wsf", "wsh", "wsc", "sct", "hta", "jar", "lnk", "url", "scf", "reg", "inf",
	"iso", "img", "vhd", "vhdx", "udf", "appx", "appxbundle", "msix", "msixbundle",
	"application", "appref-ms", "gadget", "chm", "hlp", "xll", "xla", "xlam", "docm", "dotm",
	"xlsm", "xltm", "pptm", "potm", "ppam", "ppsm", "sldm", "one", "onepkg", "ade", "adp",
	"mde", "accde", "settingcontent-ms", "library-ms", "search-ms", "apk", "dmg", "pkg",
	"htm", "html", "xhtml", "shtml", "mht", "mhtml",
}

var blockedExt = toSet(DefaultBlockedExtensions)

// SetBlockedExtensions replaces the extension blocklist. An empty list keeps
// the built-in default.
func SetBlockedExtensions(exts []string) {
	if len(exts) == 0 {
		blockedExt = toSet(DefaultBlockedExtensions)
		return
	}
	blockedExt = toSet(exts)
}

func toSet(exts []string) map[string]bool {
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
		if e != "" {
			m[e] = true
		}
	}
	return m
}

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

type headerGetter func(string) string

// CheckMail returns an empty string if the mail is acceptable, otherwise the
// reason for rejection. Anything the parser cannot interpret unambiguously is
// rejected (fail closed), because mail clients are more lenient than Go's
// MIME parser and would otherwise display content the filter never saw.
func CheckMail(rawMail string, allowed map[string]bool, headerInspectSize int) string {
	if strings.TrimSpace(rawMail) == "" {
		return "Empty mail"
	}

	msg, err := mail.ReadMessage(strings.NewReader(rawMail))
	if err != nil {
		logging.Debug("Failed to parse mail headers: %v", err)
		return "Malformed mail headers"
	}

	return checkEntity(msg.Header.Get, msg.Body, allowed, headerInspectSize, 0)
}

// checkEntity inspects a single MIME entity and recurses into nested
// multipart containers and attached rfc822 messages.
func checkEntity(get headerGetter, body io.Reader, allowed map[string]bool, headerInspectSize, depth int) string {
	mediaType := "text/plain"
	var params map[string]string
	if ct := strings.TrimSpace(get("Content-Type")); ct != "" {
		mt, p, err := mime.ParseMediaType(ct)
		if err != nil || mt == "" {
			logging.Debug("Unparsable Content-Type %q: %v", ct, err)
			return "Malformed Content-Type header"
		}
		mediaType, params = mt, p
	}

	decoded, reason := decodeTransfer(get("Content-Transfer-Encoding"), body)
	if reason != "" {
		return reason
	}

	switch {
	case mediaType == "message/rfc822":
		if depth >= maxMultipartDepth {
			return "Multipart nesting too deep"
		}
		inner, err := mail.ReadMessage(decoded)
		if err != nil {
			logging.Debug("Failed to parse attached message: %v", err)
			return "Malformed attached message"
		}
		return checkEntity(inner.Header.Get, inner.Body, allowed, headerInspectSize, depth+1)

	case strings.HasPrefix(mediaType, "multipart/"):
		if depth >= maxMultipartDepth {
			return "Multipart nesting too deep"
		}
		boundary := params["boundary"]
		if boundary == "" {
			return "Malformed multipart message: missing boundary"
		}
		mr := multipart.NewReader(decoded, boundary)
		for {
			// NextPart transparently decodes quoted-printable parts and
			// hides their Content-Transfer-Encoding header.
			part, err := mr.NextPart()
			if err == io.EOF {
				return ""
			}
			if err != nil {
				// Never retry (NextPart can return the same error forever)
				// and never skip: the rest of the message is uninspected.
				logging.Debug("Multipart parse error: %v", err)
				return "Malformed multipart message"
			}
			if reason := checkEntity(part.Header.Get, part, allowed, headerInspectSize, depth+1); reason != "" {
				return reason
			}
		}

	default:
		return checkLeaf(get, params, decoded, allowed, headerInspectSize)
	}
}

func decodeTransfer(cte string, r io.Reader) (io.Reader, string) {
	switch v := strings.ToLower(strings.TrimSpace(cte)); v {
	case "", "7bit", "8bit", "binary":
		return r, ""
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &whitespaceStripper{r: r}), ""
	case "quoted-printable":
		return quotedprintable.NewReader(r), ""
	default:
		return nil, "Unsupported Content-Transfer-Encoding: " + CleanString(v)
	}
}

func checkLeaf(get headerGetter, ctParams map[string]string, body io.Reader, allowed map[string]bool, headerInspectSize int) string {
	filename, reason := attachmentName(get, ctParams)
	if reason != "" {
		return reason
	}
	if ext := blockedExtension(filename); ext != "" {
		return "Forbidden file extension ." + CleanString(ext) + " (File: " + CleanString(filename) + ")"
	}

	head := make([]byte, headerInspectSize)
	n, _ := io.ReadFull(body, head)
	head = head[:n]
	realMime := sniff(head)

	// Inline text bodies (plain/html alternatives) are always acceptable.
	if filename == "" && strings.HasPrefix(realMime, "text/") {
		return ""
	}
	if !allowed[realMime] {
		if filename == "" {
			return "Forbidden MIME type: " + CleanString(realMime)
		}
		return "Forbidden MIME type: " + CleanString(realMime) + " (File: " + CleanString(filename) + ")"
	}
	if realMime == "application/zip" {
		data, err := io.ReadAll(io.MultiReader(bytes.NewReader(head), body))
		if err != nil {
			return "Unreadable attachment (File: " + CleanString(filename) + ")"
		}
		if reason := checkZip(data, 0); reason != "" {
			return reason + " (File: " + CleanString(filename) + ")"
		}
	}
	return ""
}

// attachmentName returns the decoded file name from Content-Disposition or,
// as clients do, from the Content-Type name parameter. A Content-Disposition
// header that cannot be parsed is rejected: clients may still extract a
// name from it that the filter would otherwise never see.
func attachmentName(get headerGetter, ctParams map[string]string) (string, string) {
	name := ""
	if cd := strings.TrimSpace(get("Content-Disposition")); cd != "" {
		_, p, err := mime.ParseMediaType(cd)
		if err != nil {
			logging.Debug("Unparsable Content-Disposition %q: %v", cd, err)
			return "", "Malformed Content-Disposition header"
		}
		name = p["filename"]
	}
	if name == "" {
		name = ctParams["name"]
	}
	if decoded, err := new(mime.WordDecoder).DecodeHeader(name); err == nil {
		name = decoded
	}
	return name, ""
}

// blockedExtension returns the blocked extension of filename, or "".
func blockedExtension(filename string) string {
	name := strings.ToLower(strings.TrimRight(strings.TrimSpace(filename), ". "))
	if name == "" {
		return ""
	}
	name = name[strings.LastIndexAny(name, `/\`)+1:]
	ext := strings.TrimPrefix(path.Ext(name), ".")
	if blockedExt[ext] {
		return ext
	}
	return ""
}

func sniff(head []byte) string {
	detected := http.DetectContentType(head)
	if mt, _, err := mime.ParseMediaType(detected); err == nil && mt != "" {
		return mt
	}
	return strings.ToLower(detected)
}

// checkZip inspects the entry names of a ZIP archive (including Office Open
// XML documents) and recurses into nested ZIP archives.
func checkZip(data []byte, depth int) string {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "Unreadable ZIP archive"
	}
	if len(zr.File) > maxArchiveEntries {
		return "Archive has too many entries"
	}
	for _, f := range zr.File {
		if ext := blockedExtension(f.Name); ext != "" {
			return "Forbidden file in archive: " + CleanString(f.Name)
		}
		base := strings.ToLower(path.Base(strings.ReplaceAll(f.Name, `\`, "/")))
		if base == "vbaproject.bin" || base == "vbadata.xml" {
			return "Office document with macros"
		}
		if strings.HasSuffix(base, ".zip") {
			if depth+1 >= maxArchiveDepth {
				return "Archive nesting too deep"
			}
			if f.Flags&0x1 != 0 {
				return "Encrypted nested archive: " + CleanString(f.Name)
			}
			rc, err := f.Open()
			if err != nil {
				return "Unreadable nested archive: " + CleanString(f.Name)
			}
			inner, err := io.ReadAll(io.LimitReader(rc, maxNestedArchiveBytes+1))
			rc.Close()
			if err != nil {
				return "Unreadable nested archive: " + CleanString(f.Name)
			}
			if len(inner) > maxNestedArchiveBytes {
				return "Nested archive too large to inspect: " + CleanString(f.Name)
			}
			if reason := checkZip(inner, depth+1); reason != "" {
				return reason
			}
		}
	}
	return ""
}
