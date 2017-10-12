package pearl

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/mmcloughlin/pearl/torcrypto"
)

// GenerateCircID generates a circuit ID with the given most significant bit.
func GenerateCircID(f CellFormat, msb uint32) CircID {
	b := torcrypto.Rand(4)
	x := binary.BigEndian.Uint32(b)
	x = (x >> 1) | (msb << 31)
	if f.CircIDLen() == 2 {
		x >>= 16
	}
	return CircID(x)
}

type CircuitCryptoState struct {
	digest []byte
	cipher.Stream
}

func NewCircuitCryptoState(d, k []byte) CircuitCryptoState {
	return CircuitCryptoState{
		digest: d,
		Stream: torcrypto.NewStream(k),
	}
}

type Circuit struct {
	ID       CircID
	Previous *Connection
	Next     *Connection
	Forward  CircuitCryptoState
	Backward CircuitCryptoState
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

func (m *CircuitManager) NewCircuit(f CellFormat, outbound bool) *Circuit {
	m.Lock()
	defer m.Unlock()

	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L931-L933
	//
	//	   In link protocol version 4 or higher, whichever node initiated the
	//	   connection sets its MSB to 1, and whichever node didn't initiate the
	//	   connection sets its MSB to 0.
	//
	msb := uint32(0)
	if outbound {
		msb = uint32(1)
	}

	// BUG(mbm): potential infinite (or at least long) loop to find a new circuit id
	for {
		id := GenerateCircID(f, msb)
		_, exists := m.circuits[id]
		if exists {
			continue
		}
		circ := &Circuit{
			ID: id,
		}
		m.circuits[id] = circ
		return circ
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
