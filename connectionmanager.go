package pearl

import (
	"errors"
	"net"
	"sync"
)

// ConnectionHint specifies how to connect to a relay.
//
// TODO(mbm): bad name? perhaps Addr?
// TODO(mbm): should not return errors?
type ConnectionHint interface {
	Fingerprinted
	Addresses() ([]net.Addr, error)
}

// ConnectionManager manages a collection of Connections.
type ConnectionManager struct {
	connections map[Fingerprint]*Connection

	sync.RWMutex
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[Fingerprint]*Connection),
	}
}

func (m *ConnectionManager) AddConnection(c *Connection) error {
	m.Lock()
	defer m.Unlock()
	fp, err := c.Fingerprint()
	if err != nil {
		return errors.New("unknown connection fingerprint")
	}
	_, exists := m.connections[fp]
	if exists {
		return errors.New("cannot override existing fingerprint")
	}
	m.connections[fp] = c
	return nil
}

func (m *ConnectionManager) Connection(fp Fingerprint) (*Connection, bool) {
	m.RLock()
	defer m.RUnlock()
	c, ok := m.connections[fp]
	return c, ok
}
