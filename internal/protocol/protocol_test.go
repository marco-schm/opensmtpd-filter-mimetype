package protocol_test

import (
	"strings"
	"testing"

	"opensmtpd-filter-mimetype/internal/protocol"
	"opensmtpd-filter-mimetype/internal/session"

	"github.com/stretchr/testify/assert"
)

func TestHandleDataLine_And_Commit(t *testing.T) {
	output := make(chan string, 10)
	sessMgr := session.NewManager()

	allowed := map[string]bool{"text/plain": true}
	handler := protocol.NewProtocolHandler(sessMgr, allowed, 512, output)

	// Mock CheckFunc
	handler.CheckFunc = func(lines []string, allowed map[string]bool, headerSize int) string {
		for _, l := range lines {
			if strings.Contains(l, "BAD") {
				return "Forbidden content"
			}
		}
		return ""
	}

	sid := "sess1"
	token := "tok1"

	// Simulate sending data lines
	handler.HandleDataLine(sid, token, "Hello world")
	handler.HandleDataLine(sid, token, "This is a test")
	handler.HandleDataLine(sid, token, "..line with dot")
	handler.HandleDataLine(sid, token, ".")

	// Commit
	handler.HandleCommit(sid, token)

	// Close output channel for inspection
	close(output)

	var lines []string
	for l := range output {
		lines = append(lines, l)
	}

	// Expect filter-dataline lines + final proceed
	assert.Contains(t, lines[len(lines)-1], "proceed")
	assert.True(t, len(lines) >= 5)

	// Session should be deleted
	assert.Nil(t, sessMgr.GetExisting(sid))
}

func TestHandleCommit_Rejects(t *testing.T) {
	output := make(chan string, 10)
	sessMgr := session.NewManager()
	handler := protocol.NewProtocolHandler(sessMgr, nil, 512, output)

	handler.CheckFunc = func(lines []string, allowed map[string]bool, headerSize int) string {
		return "Forbidden content"
	}

	sid := "sess2"
	token := "tok2"
	handler.HandleDataLine(sid, token, "Some attachment BAD")
	handler.HandleCommit(sid, token)

	close(output)

	found := false
	for l := range output {
		if strings.Contains(l, "550 Policy violation") {
			found = true
		}
	}
	assert.True(t, found)
	assert.Nil(t, sessMgr.GetExisting(sid))
}

func TestHandleDisconnect(t *testing.T) {
	output := make(chan string, 5)
	sessMgr := session.NewManager()
	handler := protocol.NewProtocolHandler(sessMgr, nil, 512, output)

	sid := "sess3"
	handler.HandleDataLine(sid, "tok3", "Test")
	handler.HandleDisconnect(sid)

	assert.Nil(t, sessMgr.GetExisting(sid))
}
