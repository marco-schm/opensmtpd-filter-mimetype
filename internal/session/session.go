package session

import (
	"sync"
)

type Session struct {
	ID      string
	Message []string
}

type Manager struct {
	sessions map[string]*Session
	lock     sync.Mutex
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

// GetOrCreate returns an existing session or creates a new one if it does not exist.
func (m *Manager) GetOrCreate(id string) *Session {
	m.lock.Lock()
	defer m.lock.Unlock()

	s, exists := m.sessions[id]
	if !exists {
		s = &Session{ID: id, Message: []string{}}
		m.sessions[id] = s
	}
	return s
}

// GetExisting returns an existing session or nil if it does not exist.
func (m *Manager) GetExisting(id string) *Session {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.sessions[id]
}

// Delete removes a session by ID.
func (m *Manager) Delete(id string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.sessions, id)
}
