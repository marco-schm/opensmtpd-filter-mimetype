package mail

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var testAllowed = map[string]bool{
	"application/pdf": true,
	"text/plain":      true,
}

// binaryBody sniffs as application/octet-stream (not in the allowlist).
const binaryBody = "\x01\x02\x03\x04\xff\xfe\x00\x00"

func check(t *testing.T, rawMail string) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		done <- CheckMailPart(strings.Split(rawMail, "\n"), testAllowed, 512)
	}()
	select {
	case reason := <-done:
		return reason
	case <-time.After(5 * time.Second):
		t.Fatal("CheckMailPart did not return within 5s (infinite loop?)")
		return ""
	}
}

// Reproduces the busy-loop bug: a truncated multipart body makes NextPart
// return the same non-EOF error on every call.
func TestTruncatedMultipartTerminates(t *testing.T) {
	mail := "From: a@example.com\n" +
		"Content-Type: multipart/mixed; boundary=\"B\"\n" +
		"\n" +
		"--B\n" +
		"Content-Type: text/plain\n" +
		"\n" +
		"hello" // no closing boundary
	check(t, mail)
}

func TestMissingBoundaryRejected(t *testing.T) {
	mail := "From: a@example.com\n" +
		"Content-Type: multipart/mixed\n" +
		"\n" +
		"body without boundary"
	if reason := check(t, mail); !strings.Contains(reason, "boundary") {
		t.Fatalf("expected missing-boundary rejection, got %q", reason)
	}
}

// A forbidden attachment hidden one multipart level deeper must still be found.
func TestNestedMultipartAttachmentDetected(t *testing.T) {
	mail := "From: a@example.com\n" +
		"Content-Type: multipart/mixed; boundary=\"OUTER\"\n" +
		"\n" +
		"--OUTER\n" +
		"Content-Type: multipart/mixed; boundary=\"INNER\"\n" +
		"\n" +
		"--INNER\n" +
		"Content-Type: application/octet-stream\n" +
		"Content-Disposition: attachment; filename=\"evil.bin\"\n" +
		"\n" +
		binaryBody + "\n" +
		"--INNER--\n" +
		"--OUTER--\n"
	reason := check(t, mail)
	if !strings.Contains(reason, "Forbidden MIME type") {
		t.Fatalf("nested attachment not detected, got %q", reason)
	}
}

func TestAttachedRfc822MessageScanned(t *testing.T) {
	mail := "From: a@example.com\n" +
		"Content-Type: multipart/mixed; boundary=\"OUTER\"\n" +
		"\n" +
		"--OUTER\n" +
		"Content-Type: message/rfc822\n" +
		"\n" +
		"From: b@example.com\n" +
		"Content-Type: application/octet-stream\n" +
		"\n" +
		binaryBody + "\n" +
		"--OUTER--\n"
	reason := check(t, mail)
	if !strings.Contains(reason, "Forbidden MIME type") {
		t.Fatalf("attachment in forwarded message not detected, got %q", reason)
	}
}

func TestNestingDeeperThanLimitRejected(t *testing.T) {
	depth := maxMultipartDepth + 1
	var sb strings.Builder
	sb.WriteString("From: a@example.com\n")
	sb.WriteString("Content-Type: multipart/mixed; boundary=\"B0\"\n\n")
	for i := 1; i <= depth; i++ {
		sb.WriteString(fmt.Sprintf("--B%d\n", i-1))
		sb.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"B%d\"\n\n", i))
	}
	sb.WriteString(fmt.Sprintf("--B%d\n", depth))
	sb.WriteString("Content-Type: application/octet-stream\n\n")
	sb.WriteString(binaryBody + "\n")
	for i := depth; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("--B%d--\n", i))
	}
	reason := check(t, sb.String())
	if !strings.Contains(reason, "nesting too deep") {
		t.Fatalf("expected depth-limit rejection, got %q", reason)
	}
}

// A typical PGP/MIME encrypted mail (armored payload) must pass.
func TestPGPMimeMailAllowed(t *testing.T) {
	mail := "From: a@example.com\n" +
		"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"PGP\"\n" +
		"\n" +
		"--PGP\n" +
		"Content-Type: application/pgp-encrypted\n" +
		"\n" +
		"Version: 1\n" +
		"--PGP\n" +
		"Content-Type: application/octet-stream; name=\"encrypted.asc\"\n" +
		"\n" +
		"-----BEGIN PGP MESSAGE-----\n" +
		"hQGMA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV\n" +
		"-----END PGP MESSAGE-----\n" +
		"--PGP--\n"
	if reason := check(t, mail); reason != "" {
		t.Fatalf("PGP mail was rejected: %q", reason)
	}
}
