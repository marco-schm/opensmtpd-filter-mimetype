package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// PNG magic header used in multiple tests
const pngMagic = "\x89PNG\r\n\x1a\n"

//
// 1) Email without attachments must pass
//
func TestNoAttachmentsPasses(t *testing.T) {
	email := []string{
		"From: test@example.com",
		"Content-Type: text/plain",
		"",
		"Hello world",
	}

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res != "" {
		t.Fatalf("Expected no attachments -> allowed, but rejected: %s", res)
	}
}

//
// 2) Single PNG attachment with real magic bytes must pass
//
func TestSingleAllowedAttachment(t *testing.T) {
	email := strings.Split(`From: sender@test
Content-Type: multipart/mixed; boundary=XYZ

--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="pic.png"

`+pngMagic+`DATA
--XYZ--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res != "" {
		t.Fatalf("Expected PNG to be allowed, got: %s", res)
	}
}

//
// 3) PDF-like content but PNG only allowed -> must reject
//
func TestForbiddenMimeAttachment(t *testing.T) {
	pdfMagic := "%PDF-1.7 DATA"

	email := strings.Split(`From: sender@test
Content-Type: multipart/mixed; boundary=XYZ

--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="file.pdf"

`+pdfMagic+`
--XYZ--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); !strings.Contains(res, "Forbidden MIME") {
		t.Fatalf("Expected PDF rejected, got: %s", res)
	}
}

//
// 4) Two valid PNG attachments -> all must pass
//
func TestMultipleAttachmentsMixed(t *testing.T) {
	email := strings.Split(`From: sender@test
Content-Type: multipart/mixed; boundary=XYZ

--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="one.png"

`+pngMagic+`
--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="two.png"

`+pngMagic+`
--XYZ--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res != "" {
		t.Fatalf("Expected 2× PNG allowed, got: %s", res)
	}
}

//
// 5) Fake MIME header says PDF, but magic is PNG -> must pass
//
func TestAttachmentWithFakeMimeHeaderButRealPNG(t *testing.T) {
	email := strings.Split(`From:a@test
Content-Type:multipart/mixed; boundary=A

--A
Content-Type: application/pdf
Content-Disposition: attachment; filename="fake.pdf"

`+pngMagic+`
--A--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res != "" {
		t.Fatalf("Should allow real PNG despite fake header -> got %s", res)
	}
}

//
// 6) PNG filename but no PNG magic -> must reject
//
func TestAttachmentWithPNGHeaderButWrongMagic(t *testing.T) {
	email := strings.Split(`From:a@test
Content-Type:multipart/mixed; boundary=A

--A
Content-Type: image/png
Content-Disposition: attachment; filename="bad.png"

FAKEPNGDATAWITHOUTMAGIC
--A--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); !strings.Contains(res, "Forbidden MIME") {
		t.Fatalf("Fake PNG without magic must be rejected")
	}
}

//
// 7) One attachment valid, second invalid -> whole mail blocked
//
func TestMultipleAttachmentsOneForbidden(t *testing.T) {
	email := strings.Split(`From:x@test
Content-Type:multipart/mixed; boundary=B

--B
Content-Type:application/octet-stream
Content-Disposition: attachment; filename="good.png"

`+pngMagic+`
--B
Content-Type:application/octet-stream
Content-Disposition: attachment; filename="evil.bin"

BINARYDATAWITHOUTMAGIC
--B--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res == "" {
		t.Fatalf("Expected rejection because second attachment is illegal")
	}
}

//
// 8) Empty attachments must be rejected
//
func TestEmptyAttachmentRejected(t *testing.T) {
	email := strings.Split(`From:z@test
Content-Type:multipart/mixed; boundary=B

--B
Content-Disposition: attachment; filename="empty.dat"

--B--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res == "" {
		t.Fatalf("Empty attachment must be rejected")
	}
}

//
// 9) Very large binary data not allowed -> must block
//
func TestVeryLargeAttachmentBlockedIfNotAllowed(t *testing.T) {
	large := strings.Repeat("A", 500000)

	email := strings.Split(`From:x@test
Content-Type:multipart/mixed; boundary=B

--B
Content-Disposition: attachment; filename="large.bin"

`+large+`
--B--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res == "" {
		t.Fatalf("Large unauthorized data must be blocked")
	}
}

//
// 10) Stops scanning after first forbidden attachment
//
func TestAllowedAndNotAllowedMimeScanStopsOnFirstBlock(t *testing.T) {
	email := []string{
		"From: x@test",
		"Content-Type: multipart/mixed; boundary=BOUNDARY",
		"",
		"--BOUNDARY",
		"Content-Disposition: attachment; filename=\"good1.png\"",
		"",
		pngMagic,
		"--BOUNDARY",
		"Content-Disposition: attachment; filename=\"evil.exe\"",
		"",
		"MZFAKEDATA",
		"--BOUNDARY--",
	}

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	res := checkMailContent(email)
	if res == "" {
		t.Fatalf("Mail must be blocked because it contains EXE")
	}
}


//
// 11) Base64 encoded PNG must pass
//
func TestBase64EncodedPNGPasses(t *testing.T) {
	raw := []byte{0x89,'P','N','G','\r','\n',0x1A,'\n','A','B'}
	encoded := base64.StdEncoding.EncodeToString(raw)

	email := strings.Split(`From: sender@test
Content-Type: multipart/mixed; boundary=XYZ

--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="pic.png"
Content-Transfer-Encoding: base64

`+encoded+`
--XYZ--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res != "" {
		t.Fatalf("Expected Base64 PNG allowed, got: %s", res)
	}
}

//
// 12) Base64 encoded fake PNG (wrong magic) must be rejected
//
func TestBase64FakePNGRejected(t *testing.T) {
	fake := []byte{0x01,'P','N','G','X','X'}
	encoded := base64.StdEncoding.EncodeToString(fake)

	email := strings.Split(`From: sender@test
Content-Type: multipart/mixed; boundary=XYZ

--XYZ
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="fake.png"
Content-Transfer-Encoding: base64

`+encoded+`
--XYZ--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res == "" {
		t.Fatalf("Fake Base64 PNG must be rejected")
	}
}

//
// 13) Huge Base64 PNG still must validate magic bytes
//
func TestBase64HugePNGStillMagicChecked(t *testing.T) {
	h := append([]byte{0x89,'P','N','G','\r','\n',0x1A,'\n'}, []byte(strings.Repeat("A", 400000))...)
	encoded := base64.StdEncoding.EncodeToString(h)

	email := strings.Split(`From: test
Content-Type: multipart/mixed; boundary=Z

--Z
Content-Disposition: attachment; filename="huge.png"
Content-Transfer-Encoding: base64

`+encoded+`
--Z--
`, "\n")

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}, MaxInspectBytes: 800000}
	allowedMimeMap = map[string]bool{"image/png": true}

	if res := checkMailContent(email); res != "" {
		t.Fatalf("Huge Base64-PNG should pass, got: %s", res)
	}
}
