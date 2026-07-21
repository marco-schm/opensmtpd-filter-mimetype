package session

import (
	"bytes"
	"sync"
)

type Session struct {
	ID   string
	Data bytes.Buffer
	// Truncated is set when the message exceeded max_inspect_bytes and
	// only a prefix of it is buffered for inspection.
	Truncated bool
}

type Manager struct {
	sessions map[string]*Session
	lock     sync.Mutex
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*Session)}
}

func (m *Manager) GetOrCreate(id string) *Session {
	m.lock.Lock()
	defer m.lock.Unlock()
	if s, ok := m.sessions[id]; ok {
		return s
	}
	s := &Session{ID: id}
	m.sessions[id] = s
	return s
}

func (m *Manager) Delete(id string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.sessions, id)
}
