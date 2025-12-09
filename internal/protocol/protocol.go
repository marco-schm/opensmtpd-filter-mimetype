package protocol

import (
	"fmt"
	"sync"

	"opensmtpd-filter-mimetype/internal/log"
	"opensmtpd-filter-mimetype/internal/mimecheck"
	"opensmtpd-filter-mimetype/internal/session"
)

// ProtocolHandler handles OpenSMTPD filter events and sessions.
type ProtocolHandler struct {
	SessionManager *session.Manager
	AllowedMime    map[string]bool
	HeaderSize     int
	outputChan     chan string
	lock           sync.Mutex
	CheckFunc      func(lines []string, allowedMime map[string]bool, headerSize int) string
}

// NewProtocolHandler creates a new ProtocolHandler.
func NewProtocolHandler(sessMgr *session.Manager, allowedMime map[string]bool, headerSize int, outputChan chan string) *ProtocolHandler {
	return &ProtocolHandler{
		SessionManager: sessMgr,
		AllowedMime:    allowedMime,
		HeaderSize:     headerSize,
		outputChan:     outputChan,
		CheckFunc:      mimecheck.CheckMailPart, // default function
	}
}

// HandleDataLine buffers the incoming email line and echoes it back.
func (p *ProtocolHandler) HandleDataLine(sid, token, line string) {
	s := p.SessionManager.GetOrCreate(sid)

	if line != "." {
		if len(line) > 1 && line[:2] == ".." {
			s.Message = append(s.Message, line[1:])
		} else {
			s.Message = append(s.Message, line)
		}
	}

	p.produceOutput("filter-dataline", sid, token, "%s", line)
}

// HandleCommit checks the email content and accepts or rejects the message.
func (p *ProtocolHandler) HandleCommit(sid, token string) {
	s := p.SessionManager.GetOrCreate(sid)

	rejectReason := p.CheckFunc(s.Message, p.AllowedMime, p.HeaderSize)

	if rejectReason == "" {
		log.Info("[%s] Mail accepted.", sid)
		for _, line := range s.Message {
			p.produceOutput("filter-dataline", sid, token, "%s", line)
		}
		p.produceOutput("filter-dataline", sid, token, ".")
		p.produceOutput("filter-result", sid, token, "proceed")
	} else {
		log.Warn("[%s] REJECTING: %s", sid, rejectReason)
		p.produceOutput("filter-result", sid, token, "reject|550 Policy violation: %s", rejectReason)
	}

	p.SessionManager.Delete(sid)
}

// HandleDisconnect cleans up the session when a client disconnects.
func (p *ProtocolHandler) HandleDisconnect(sid string) {
	p.SessionManager.Delete(sid)
	log.Debug("[%s] Session cleaned up.", sid)
}

// produceOutput sends a protocol message to stdout or channel.
func (p *ProtocolHandler) produceOutput(msgType, sid, token, format string, a ...interface{}) {
	payload := fmt.Sprintf(format, a...)
	out := fmt.Sprintf("%s|%s|%s|%s", msgType, sid, token, payload)
	log.Debug("Output: %s", out)

	select {
	case p.outputChan <- out:
	default:
		fmt.Println(out)
	}
}
