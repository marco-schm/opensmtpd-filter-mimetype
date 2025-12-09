package protocol

import (
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
	OutputChan     chan string
	CheckFunc      func([]string, map[string]bool, int) string
}

func NewProtocolHandler(sessMgr *session.Manager, allowed map[string]bool, headerSize int, out chan string) *ProtocolHandler {
	return &ProtocolHandler{
		SessionManager: sessMgr,
		AllowedMime:    allowed,
		HeaderSize:     headerSize,
		OutputChan:     out,
		CheckFunc:      mail.CheckMailPart,
	}
}

func (p *ProtocolHandler) HandleDataLine(sid, token, line string) {
	s := p.SessionManager.GetOrCreate(sid)
	if line == "." {
		s.Message = append(s.Message, line)
	} else {
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		s.Message = append(s.Message, line)
	}
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

func (p *ProtocolHandler) HandleDisconnect(sid string) {
	p.SessionManager.Delete(sid)
	logging.Debug("[%s] Session cleaned up.", sid)
}

func (p *ProtocolHandler) produceOutput(msgType, sid, token, format string, a ...interface{}) {
	payload := fmt.Sprintf(format, a...)
	out := fmt.Sprintf("%s|%s|%s|%s", msgType, sid, token, payload)
	select {
	case p.OutputChan <- out:
	default:
		fmt.Println(out)
	}
}
