package pearl

import (
	"crypto/cipher"
	"errors"
	"sync"

	"github.com/mmcloughlin/pearl/torkeys"
)

type CircuitDirectionState struct {
	digest []byte
	cipher.Stream
}

func NewCircuitDirectionState(d, k []byte) CircuitDirectionState {
	return CircuitDirectionState{
		digest: d,
		Stream: torkeys.NewStream(k),
	}
}

type Circuit struct {
	ID       CircID
	Forward  CircuitDirectionState
	Backward CircuitDirectionState
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

func (m *CircuitManager) Circuit(id CircID) (*Circuit, bool) {
	m.RLock()
	defer m.RUnlock()
	c, ok := m.circuits[id]
	return c, ok
}
