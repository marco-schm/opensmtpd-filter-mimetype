package mail

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Allowlist close to the shipped example config (zip and pdf allowed).
var prodAllowed = map[string]bool{
	"application/pdf": true,
	"application/zip": true,
	"text/plain":      true,
	"image/png":       true,
}

// A minimal PE header: sniffs as application/octet-stream.
var exeBytes = append([]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"), bytes.Repeat([]byte{0}, 64)...)

func checkWith(t *testing.T, allowed map[string]bool, raw string) string {
	t.Helper()
	return CheckMail(raw, allowed, 512)
}

func b64(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	for len(s) > 76 {
		sb.WriteString(s[:76] + "\n")
		s = s[76:]
	}
	sb.WriteString(s + "\n")
	return sb.String()
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func attachmentMail(ctype, filename string, body []byte) string {
	return "From: a@example.com\n" +
		"Content-Type: multipart/mixed; boundary=\"B\"\n\n" +
		"--B\nContent-Type: text/plain\n\nHallo\n" +
		"--B\nContent-Type: " + ctype + "; name=\"" + filename + "\"\n" +
		"Content-Disposition: attachment; filename=\"" + filename + "\"\n" +
		"Content-Transfer-Encoding: base64\n\n" + b64(body) +
		"--B--\n"
}

// Bypass 1: a single-part mail whose body is a base64 encoded executable.
func TestSinglePartBase64ExecutableRejected(t *testing.T) {
	raw := "From: a@example.com\n" +
		"Content-Type: application/x-msdownload; name=\"evil.exe\"\n" +
		"Content-Disposition: attachment; filename=\"evil.exe\"\n" +
		"Content-Transfer-Encoding: base64\n\n" + b64(exeBytes)
	if r := checkWith(t, prodAllowed, raw); r == "" {
		t.Fatal("single-part base64 executable was accepted")
	}
}

// Bypass 2: Go's parser stops at a malformed part; lenient clients still show the rest.
func TestMalformedMultipartFailsClosed(t *testing.T) {
	raw := "From: a@example.com\n" +
		"Content-Type: multipart/mixed; boundary=\"B\"\n\n" +
		"--B\nContent-Type: text/plain\n\nHallo\n" +
		"--B\nthis line is not a header\n" +
		"Content-Type: application/octet-stream\n" +
		"Content-Disposition: attachment; filename=\"evil.exe\"\n" +
		"Content-Transfer-Encoding: base64\n\n" + b64(exeBytes) +
		"--B--\n"
	if r := checkWith(t, prodAllowed, raw); r == "" {
		t.Fatal("malformed multipart was accepted (fail-open)")
	}
}

// Bypass 3: script attachments sniff as text/plain.
func TestScriptAttachmentRejected(t *testing.T) {
	for _, name := range []string{"rechnung.js", "update.vbs", "run.bat", "x.ps1", "info.hta", "doc.pdf.exe", "Rechnung.JS. "} {
		raw := attachmentMail("application/octet-stream", name, []byte("var s = new ActiveXObject('WScript.Shell'); s.Run('calc');\n"))
		if r := checkWith(t, prodAllowed, raw); r == "" {
			t.Errorf("script attachment %q was accepted", name)
		}
	}
}

// Bypass 4: executables hidden inside an allowed ZIP archive.
func TestZipWithExecutableRejected(t *testing.T) {
	z := makeZip(t, map[string][]byte{"readme.txt": []byte("hi"), "invoice.exe": exeBytes})
	if r := checkWith(t, prodAllowed, attachmentMail("application/zip", "invoice.zip", z)); r == "" {
		t.Fatal("zip containing an .exe was accepted")
	}
}

func TestNestedZipWithExecutableRejected(t *testing.T) {
	inner := makeZip(t, map[string][]byte{"invoice.exe": exeBytes})
	outer := makeZip(t, map[string][]byte{"docs.zip": inner})
	if r := checkWith(t, prodAllowed, attachmentMail("application/zip", "docs.zip", outer)); r == "" {
		t.Fatal("zip-in-zip with an .exe was accepted")
	}
}

// Bypass 5: a macro document renamed to .docx sniffs as application/zip.
func TestMacroOfficeDocumentRejected(t *testing.T) {
	z := makeZip(t, map[string][]byte{
		"[Content_Types].xml": []byte("<Types/>"),
		"word/document.xml":   []byte("<w:document/>"),
		"word/vbaProject.bin": exeBytes,
	})
	if r := checkWith(t, prodAllowed, attachmentMail("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "report.docx", z)); r == "" {
		t.Fatal("office document with VBA macros was accepted")
	}
}

// RFC 2047 encoded filename must not hide the extension.
func TestEncodedFilenameRejected(t *testing.T) {
	enc := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("rechnung.js")) + "?="
	raw := attachmentMail("application/octet-stream", enc, []byte("WScript.Echo('x');\n"))
	if r := checkWith(t, prodAllowed, raw); r == "" {
		t.Fatal("RFC 2047 encoded .js filename was accepted")
	}
}

// Legitimate mails must still pass.
func TestCleanAttachmentsAllowed(t *testing.T) {
	docx := makeZip(t, map[string][]byte{"[Content_Types].xml": []byte("<Types/>"), "word/document.xml": []byte("<w:document/>")})
	cases := map[string]string{
		"pdf":                   attachmentMail("application/pdf", "Rechnung.pdf", []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n")),
		"docx":                  attachmentMail("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Bericht.docx", docx),
		"png":                   attachmentMail("image/png", "bild.png", append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 32)...)),
		"txt":                   attachmentMail("text/plain", "notiz.txt", []byte("hallo welt\n")),
		"quoted-printable body": "From: a@example.com\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nGr=C3=BC=C3=9Fe\n",
		"html alternative":      "From: a@example.com\nContent-Type: multipart/alternative; boundary=\"A\"\n\n--A\nContent-Type: text/plain\n\nhi\n--A\nContent-Type: text/html\n\n<html><body>hi</body></html>\n--A--\n",
	}
	for name, raw := range cases {
		if r := checkWith(t, prodAllowed, raw); r != "" {
			t.Errorf("%s: legitimate mail rejected: %q", name, r)
		}
	}
}
