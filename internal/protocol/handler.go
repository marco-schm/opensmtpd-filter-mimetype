package protocol

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/logging"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mail"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/session"
)


type ProtocolHandler struct {
	SessionManager *session.Manager
	AllowedMime    map[string]bool
	HeaderSize     int
	Writer         *bufio.Writer
	CheckFunc      func([]string, map[string]bool, int) string
}

func NewProtocolHandler(sessMgr *session.Manager, allowed map[string]bool, headerSize int, w *bufio.Writer) *ProtocolHandler {
	return &ProtocolHandler{
		SessionManager: sessMgr,
		AllowedMime:    allowed,
		HeaderSize:     headerSize,
		Writer:         w,
		CheckFunc:      mail.CheckMailPart,
	}
}

func (p *ProtocolHandler) HandleDataLine(sid, token, line string) {
	s := p.SessionManager.GetOrCreate(sid)
	// Store the unescaped form for analysis, but echo the line back
	// unchanged so the dot-escaping of the filter protocol is preserved.
	stored := line
	if line != "." && strings.HasPrefix(line, "..") {
		stored = line[1:]
	}
	s.Message = append(s.Message, stored)
	p.produceOutput("filter-dataline", sid, token, "%s", line)
}

func (p *ProtocolHandler) HandleCommit(sid, token string) {
	s := p.SessionManager.GetOrCreate(sid)
	hasHeader := false
	for _, l := range s.Message {
		if strings.Contains(l, ":") {
			hasHeader = true
			break
		}
	}

	if !hasHeader {
		p.produceOutput("filter-result", sid, token, "reject|550 Policy violation: No valid headers")
		p.SessionManager.Delete(sid)
		return
	}

	reason := p.CheckFunc(s.Message, p.AllowedMime, p.HeaderSize)
	if reason == "" {
		p.produceOutput("filter-result", sid, token, "proceed")
	} else {
		p.produceOutput("filter-result", sid, token, "reject|550 Policy violation: %s", reason)
	}

	p.SessionManager.Delete(sid)
}

// HandleTxReset drops any buffered message data when a transaction ends
// (RSET, rollback or after commit), so a follow-up mail in the same
// connection is not analyzed together with leftovers of the previous one.
func (p *ProtocolHandler) HandleTxReset(sid string) {
	p.SessionManager.Delete(sid)
	logging.Debug("[%s] Transaction reset, message buffer cleared.", sid)
}

func (p *ProtocolHandler) HandleDisconnect(sid string) {
	p.SessionManager.Delete(sid)
	logging.Debug("[%s] Session cleaned up.", sid)
}

func (p *ProtocolHandler) produceOutput(msgType, sid, token, format string, a ...interface{}) {
	payload := fmt.Sprintf(format, a...)
	fmt.Fprintf(p.Writer, "%s|%s|%s|%s\n", msgType, sid, token, payload)
	if err := p.Writer.Flush(); err != nil {
		logging.Warn("Failed to write to stdout: %v", err)
	}
}
