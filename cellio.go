package pearl

import (
	"errors"
	"io"
	"sync"

	"go.uber.org/multierr"
)

// CellSender can send a Cell.
type CellSender interface {
	SendCell(Cell) error
}

// CellReceiver can receive Cells.
type CellReceiver interface {
	ReceiveCell() (Cell, error)
}

type CellReceiverSender interface {
	CellSender
	CellReceiver
}

type CellSenderCloser interface {
	CellSender
	io.Closer
}

// CellReceiver can receive legacy Cells (circ ID length 2).
type LegacyCellReceiver interface {
	CellReceiver
	ReceiveLegacyCell() (Cell, error)
}

// Link is a Cell communication layer.
type Link interface {
	CellSender
	CellReceiver
	io.Closer
}

type link struct {
	CellSender
	CellReceiver
	io.Closer
}

func NewLink(s CellSender, r CellReceiver, c io.Closer) Link {
	return link{
		CellSender:   s,
		CellReceiver: r,
		Closer:       c,
	}
}

type CellChan struct {
	C    chan Cell
	done <-chan struct{}
}

func NewCellChan(c chan Cell, done chan struct{}) *CellChan {
	return &CellChan{
		C:    c,
		done: done,
	}
}

func (ch *CellChan) SendCell(cell Cell) error {
	select {
	case <-ch.done:
		return io.EOF
	case ch.C <- cell:
		return nil
	}
}

func (ch *CellChan) ReceiveCell() (Cell, error) {
	select {
	case <-ch.done:
		return nil, io.EOF
	case cell := <-ch.C:
		return cell, nil
	}
}

type CircuitLink interface {
	CircID() CircID
	CellReceiverSender
	Destroy(CircuitErrorCode) error
}

type circLink struct {
	conn *Connection
	id   CircID
	CellReceiver
	CellSender
}

func NewCircuitLink(conn *Connection, id CircID, r CellReceiver) CircuitLink {
	return circLink{
		conn:         conn,
		id:           id,
		CellReceiver: r,
		CellSender:   conn,
	}
}

func (c circLink) Destroy(reason CircuitErrorCode) error {
	// XXX sync.Once ?
	d := NewDestroyCell(c.CircID(), reason)
	return multierr.Combine(
		c.conn.circuits.Remove(c.CircID()),
		c.SendCell(d.Cell()),
	)
}

func (c circLink) CircID() CircID { return c.id }

// SenderManager manages a collection of cell senders.
type SenderManager struct {
	senders  map[CircID]CellSenderCloser
	outbound bool
	sync.RWMutex
}

func NewSenderManager(outbound bool) *SenderManager {
	return &SenderManager{
		senders:  make(map[CircID]CellSenderCloser),
		outbound: outbound,
	}
}

func (m *SenderManager) Add(sc CellSenderCloser) CircID {
	m.Lock()
	defer m.Unlock()

	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L931-L933
	//
	//	   In link protocol version 4 or higher, whichever node initiated the
	//	   connection sets its MSB to 1, and whichever node didn't initiate the
	//	   connection sets its MSB to 0.
	//
	msb := uint32(0)
	if m.outbound {
		msb = uint32(1)
	}

	// BUG(mbm): potential infinite (or at least long) loop to find a new id
	for {
		id := GenerateCircID(msb)
		// 0 is reserved
		if id == 0 {
			continue
		}
		_, exists := m.senders[id]
		if exists {
			continue
		}
		m.senders[id] = sc
		return id
	}
}

func (m *SenderManager) AddWithID(id CircID, sc CellSenderCloser) error {
	m.Lock()
	defer m.Unlock()

	if m.senders == nil {
		return errors.New("sender manager closed")
	}

	_, exists := m.senders[id]
	if exists {
		return errors.New("cannot override existing sender id")
	}
	m.senders[id] = sc

	return nil
}

func (m *SenderManager) Sender(id CircID) (CellSender, bool) {
	m.RLock()
	defer m.RUnlock()
	sc, ok := m.senders[id]
	return sc, ok
}

func (m *SenderManager) Remove(id CircID) error {
	m.Lock()
	defer m.Unlock()

	_, ok := m.senders[id]
	if !ok {
		return errors.New("unknown circuit")
	}

	delete(m.senders, id)

	return nil
}

func (m *SenderManager) Empty() []CellSenderCloser {
	m.Lock()
	defer m.Unlock()

	scs := make([]CellSenderCloser, 0, len(m.senders))
	for _, sc := range m.senders {
		scs = append(scs, sc)
	}

	m.senders = nil

	return scs
}
