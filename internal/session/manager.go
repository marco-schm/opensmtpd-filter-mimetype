package session

import "sync"

type Session struct {
	ID      string
	Message []string
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
	s := &Session{ID: id, Message: []string{}}
	m.sessions[id] = s
	return s
}

func (m *Manager) Delete(id string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.sessions, id)
}
