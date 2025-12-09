package mimecheck_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"opensmtpd-filter-mimetype/internal/mimecheck" 
)

func TestCheckMailPart_TextOnly(t *testing.T) {
	lines := []string{
		"From: test@example.com",
		"To: me@example.com",
		"Subject: Hello",
		"Content-Type: text/plain",
		"",
		"This is a plain text email body.",
	}

	allowed := map[string]bool{
		"application/pdf": true,
	}

	reason := mimecheck.CheckMailPart(lines, allowed, 512)
	assert.Equal(t, "", reason, "Plain text email should pass")
}

func TestCheckMailPart_AllowedAttachment(t *testing.T) {
	lines := []string{
		"From: test@example.com",
		"To: me@example.com",
		"Subject: PDF attachment",
		"Content-Type: multipart/mixed; boundary=boundary1",
		"",
		"--boundary1",
		"Content-Type: application/pdf",
		"Content-Disposition: attachment; filename=\"file.pdf\"",
		"Content-Transfer-Encoding: base64",
		"",
		"JVBERi0xLjQKJcfs...",
		"--boundary1--",
	}

	allowed := map[string]bool{
		"application/pdf": true,
	}

	reason := mimecheck.CheckMailPart(lines, allowed, 512)
	assert.Equal(t, "", reason, "Allowed PDF attachment should pass")
}

func TestCheckMailPart_DisallowedAttachment(t *testing.T) {
	lines := []string{
		"From: test@example.com",
		"To: me@example.com",
		"Subject: Executable",
		"Content-Type: multipart/mixed; boundary=boundary1",
		"",
		"--boundary1",
		"Content-Type: application/x-msdownload",
		"Content-Disposition: attachment; filename=\"evil.exe\"",
		"Content-Transfer-Encoding: base64",
		"",
		"TVqQAAMAAAAEAAAA//8AALg...",
		"--boundary1--",
	}

	allowed := map[string]bool{
		"application/pdf": true,
	}

	reason := mimecheck.CheckMailPart(lines, allowed, 512)
	assert.Contains(t, reason, "Forbidden MIME type", "Executable attachment should be rejected")
}

func TestCheckMailPart_MultipleAttachments(t *testing.T) {
	lines := []string{
		"From: test@example.com",
		"To: me@example.com",
		"Subject: Multiple attachments",
		"Content-Type: multipart/mixed; boundary=boundary1",
		"",
		"--boundary1",
		"Content-Type: application/pdf",
		"Content-Disposition: attachment; filename=\"file1.pdf\"",
		"Content-Transfer-Encoding: base64",
		"",
		"JVBERi0xLjQKJcfs...",
		"--boundary1",
		"Content-Type: application/x-msdownload",
		"Content-Disposition: attachment; filename=\"file2.exe\"",
		"Content-Transfer-Encoding: base64",
		"",
		"TVqQAAMAAAAEAAAA//8AALg...",
		"--boundary1--",
	}

	allowed := map[string]bool{
		"application/pdf": true,
	}

	reason := mimecheck.CheckMailPart(lines, allowed, 512)
	assert.Contains(t, reason, "Forbidden MIME type", "Only disallowed attachment should trigger rejection")
}

func TestCleanString(t *testing.T) {
	input := "test|string\nwith\rspecial\u0000chars"
	expected := "test?string?with?special?chars"
	assert.Equal(t, expected, mimecheck.CleanString(input))
}
