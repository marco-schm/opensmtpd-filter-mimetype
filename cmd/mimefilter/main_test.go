package main

import (
	"strings"
	"testing"
)

const pngMagic = "\x89PNG\r\n\x1a\n"

//
// Tests that an email with no attachments is accepted.
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
		t.Fatalf("Expected no attachments → allowed, but rejected: %s", res)
	}
}

//
// Tests that one attachment containing valid PNG magic bytes is allowed.
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
		t.Fatalf("Expected PNG to be allowed, but got: %s", res)
	}
}

//
// Tests that an attachment without valid magic bytes (PDF) is rejected.
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
		t.Fatalf("Expected PDF to be rejected, but got: %s", res)
	}
}

//
// Tests that two valid PNG attachments are both allowed.
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
		t.Fatalf("Expected both PNG allowed but got: %s", res)
	}
}

//
// Tests a fake MIME header pretending to be PDF, but real PNG magic → must be allowed.
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
		t.Fatalf("Should allow real PNG despite fake header → got %s", res)
	}
}

//
// Tests a correct PNG filename + header, but missing real PNG magic bytes → must be blocked.
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
// Tests that if one of multiple attachments is invalid, the message is rejected.
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
// Tests that empty attachments (0 bytes) are rejected.
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
		t.Fatalf("Empty attachments must be rejected")
	}
}

//
// Tests rejection of large binary data when type is not allowed.
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

func TestAllowedAndNotAllowedMimeScanStopsOnFirstBlock(t *testing.T) {
	pngMagic := "\x89PNG\r\n\x1a\n"

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
		"MZFAKEDATA_THIS_IS_A_VIRUS",
		"--BOUNDARY",
		"Content-Disposition: attachment; filename=\"good2.png\"",
		"", 
		pngMagic,
		"--BOUNDARY--",
	}

	config = AppConfig{AllowedMimeTypes: []string{"image/png"}}
	allowedMimeMap = map[string]bool{"image/png": true}

	res := checkMailContent(email)

	if res == "" {
		t.Fatalf("Test failed: Mail was NOT blocked, but it contains .exe")
	}

	if !strings.Contains(res, "Forbidden MIME type") {
		t.Errorf("Wrong rejection reason: %s", res)
	}
}
