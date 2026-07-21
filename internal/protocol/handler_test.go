package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/session"
)

func newTestHandler(buf *bytes.Buffer) *ProtocolHandler {
	h := NewProtocolHandler(session.NewManager(), map[string]bool{}, 512, 0, bufio.NewWriter(buf))
	h.CheckFunc = func(string, map[string]bool, int) string { return "" }
	return h
}

// Reproduces the truncation bug: with the old channel-based output (capacity
// 200 with a non-blocking fallback), more than 200 data lines got reordered.
func TestDataLineOrderPreservedForLargeMail(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(&buf)

	const n = 5000
	for i := 0; i < n; i++ {
		h.HandleDataLine("s1", "tok", fmt.Sprintf("line-%d", i))
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d output lines, got %d", n, len(lines))
	}
	for i, l := range lines {
		want := fmt.Sprintf("filter-dataline|s1|tok|line-%d", i)
		if l != want {
			t.Fatalf("line %d out of order: got %q, want %q", i, l, want)
		}
	}
}

func TestDataLineDotEscaping(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(&buf)

	h.HandleDataLine("s1", "tok", "..starts with dot")
	h.HandleDataLine("s1", "tok", "normal line")
	h.HandleDataLine("s1", "tok", ".")

	got := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	want := []string{
		"filter-dataline|s1|tok|..starts with dot",
		"filter-dataline|s1|tok|normal line",
		"filter-dataline|s1|tok|.",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("echo %d: got %q, want %q", i, got[i], want[i])
		}
	}

	s := h.SessionManager.GetOrCreate("s1")
	if s.Data.String() != ".starts with dot\nnormal line\n" {
		t.Errorf("unexpected buffered data (must be unescaped, without terminating dot): %q", s.Data.String())
	}
}

// Lines beyond max_inspect_bytes are no longer buffered but must still be echoed.
func TestMaxInspectBytesCapsBufferButNotEcho(t *testing.T) {
	var buf bytes.Buffer
	h := NewProtocolHandler(session.NewManager(), map[string]bool{}, 512, 50, bufio.NewWriter(&buf))
	h.CheckFunc = func(string, map[string]bool, int) string { return "" }

	for i := 0; i < 20; i++ {
		h.HandleDataLine("s1", "tok", "0123456789") // 11 bytes buffered per line
	}

	s := h.SessionManager.GetOrCreate("s1")
	if s.Data.Len() > 50 {
		t.Errorf("buffer exceeds max_inspect_bytes: %d bytes", s.Data.Len())
	}
	if !s.Truncated {
		t.Error("Truncated flag not set")
	}
	if got := strings.Count(buf.String(), "\n"); got != 20 {
		t.Errorf("expected all 20 lines echoed, got %d", got)
	}
}

// After a tx-reset (RSET/rollback), a second mail in the same connection
// must not see leftover lines of the aborted transaction.
func TestTxResetClearsBufferedMessage(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(&buf)

	h.HandleDataLine("s1", "tok", "Subject: aborted mail")
	h.HandleTxReset("s1")

	h.HandleDataLine("s1", "tok2", "Subject: second mail")
	s := h.SessionManager.GetOrCreate("s1")
	if s.Data.String() != "Subject: second mail\n" {
		t.Fatalf("stale data survived tx-reset: %q", s.Data.String())
	}
}

func TestCommitProducesResultAfterAllDataLines(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(&buf)

	for i := 0; i < 300; i++ {
		h.HandleDataLine("s1", "tok", "Subject: test")
	}
	h.HandleDataLine("s1", "tok", ".")
	h.HandleCommit("s1", "tok")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	if last != "filter-result|s1|tok|proceed" {
		t.Fatalf("expected filter-result as last line, got %q", last)
	}
	for _, l := range lines[:len(lines)-1] {
		if strings.HasPrefix(l, "filter-result") {
			t.Fatalf("filter-result emitted before all data lines were flushed")
		}
	}
}
