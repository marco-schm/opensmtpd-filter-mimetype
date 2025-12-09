package protocol

import (
	"fmt"
	"strings"

	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/log"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/mimecheck"
	"github.com/marco-schm/opensmtpd-filter-mimetype/internal/mimefilter/session"
)

type ProtocolHandler struct {
	SessionManager *session.Manager
	AllowedMime    map[string]bool
	HeaderSize     int
	outputChan     chan string
	CheckFunc      func([]string, map[string]bool, int, *log.Logger) string
	Logger         *log.Logger
}

func NewProtocolHandler(sessMgr *session.Manager, allowedMime map[string]bool, headerSize int, outputChan chan string, logger *log.Logger) *ProtocolHandler {
	return &ProtocolHandler{
		SessionManager: sessMgr,
		AllowedMime:    allowedMime,
		HeaderSize:     headerSize,
		outputChan:     outputChan,
		CheckFunc:      mimecheck.CheckMail,
		Logger:         logger,
	}
}
