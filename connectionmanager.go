package pearl

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// ConnectionHint specifies how to connect to a relay.
//
// TODO(mbm): bad name? perhaps Addr?
// TODO(mbm): should not return errors?
type ConnectionHint interface {
	Fingerprinted
	Addresses() ([]net.Addr, error)
}

type ConnID uint64

var globalConnID uint64

func NewConnID() ConnID {
	return ConnID(atomic.AddUint64(&globalConnID, 1))
}

// ConnectionManager manages a collection of Connections.
type ConnectionManager struct {
	connections map[Fingerprint]map[ConnID]*Connection

	sync.RWMutex
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[Fingerprint]map[ConnID]*Connection),
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
	if !exists {
		m.connections[fp] = make(map[ConnID]*Connection)
	}
	m.connections[fp][c.ConnID()] = c
	return nil
}

func (m *ConnectionManager) Connection(fp Fingerprint) (*Connection, bool) {
	m.RLock()
	defer m.RUnlock()
	conns, ok := m.connections[fp]
	if !ok {
		return nil, false
	}
	// REVIEW(mbm): return random connection when we have more than one?
	for _, conn := range conns {
		return conn, true
	}
	panic("unreachable")
}
