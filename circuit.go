package pearl

import (
	"errors"
	"sync"
)

type Circuit struct {
	ID             CircID
	ForwardDigest  []byte
	BackwardDigest []byte
	ForwardKey     []byte
	BackwardKey    []byte
}

// CircuitManager manages a collection of circuits.
type CircuitManager struct {
	circuits map[CircID]*Circuit

	sync.RWMutex
}

func NewCircuitManager() *CircuitManager {
	return &CircuitManager{
		circuits: make(map[CircID]*Circuit),
	}
}

func (m *CircuitManager) AddCircuit(c *Circuit) error {
	m.Lock()
	defer m.Unlock()
	_, exists := m.circuits[c.ID]
	if exists {
		return errors.New("cannot override existing circuit id")
	}
	m.circuits[c.ID] = c
	return nil
}
