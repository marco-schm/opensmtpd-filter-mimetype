package session_test

import (
	"fmt"
	"testing"

	"opensmtpd-filter-mimetype/internal/session"

	"github.com/stretchr/testify/assert"
)

func TestSessionManager_GetOrCreate_NewSession(t *testing.T) {
	mgr := session.NewManager()

	s := mgr.GetOrCreate("abc123")
	assert.NotNil(t, s)
	assert.Equal(t, "abc123", s.ID)
	assert.Empty(t, s.Message)
}

func TestSessionManager_GetOrCreate_ExistingSession(t *testing.T) {
	mgr := session.NewManager()

	s1 := mgr.GetOrCreate("abc123")
	s1.Message = append(s1.Message, "hello")

	s2 := mgr.GetOrCreate("abc123")
	assert.Equal(t, s1, s2)
	assert.Equal(t, []string{"hello"}, s2.Message)
}

func TestSessionManager_GetExisting(t *testing.T) {
	mgr := session.NewManager()

	s := mgr.GetExisting("abc123")
	assert.Nil(t, s)

	created := mgr.GetOrCreate("abc123")
	existing := mgr.GetExisting("abc123")
	assert.Equal(t, created, existing)
}

func TestSessionManager_Delete(t *testing.T) {
	mgr := session.NewManager()

	s := mgr.GetOrCreate("abc123")
	assert.NotNil(t, s)

	mgr.Delete("abc123")
	deleted := mgr.GetExisting("abc123")
	assert.Nil(t, deleted)
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	mgr := session.NewManager()
	numGoroutines := 100
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			id := fmt.Sprintf("session%d", idx)
		
			s := mgr.GetOrCreate(id)
			s.Message = append(s.Message, "line")
			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	s0 := mgr.GetExisting("session0")
	assert.NotNil(t, s0)
	assert.Equal(t, []string{"line"}, s0.Message)
}
