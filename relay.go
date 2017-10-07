package pearl

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mmcloughlin/pearl/log"
)

type RelayCell interface {
	RelayCommand() byte
	StreamID() uint16
	Digest() []byte
	RelayData() []byte
}

type relayCell []byte

func (r relayCell) RelayCommand() byte {
	return r[0]
}

func (r relayCell) StreamID() uint16 {
	return binary.BigEndian.Uint16(r[1:])
}

func (r relayCell) Digest() []byte {
	return r[5:9]
}

func (r relayCell) RelayData() []byte {
	n := binary.BigEndian.Uint16(r[9:])
	return r[11 : 11+int(n)]
}

func NewRelayCellFromBytes(b []byte) RelayCell {
	return relayCell(b)
}

func LogRelayCell(l log.Logger, r RelayCell) {
	l = l.With("relaycmd", r.RelayCommand()).With("streamid", r.StreamID())
	l = log.WithBytes(l, "digest", r.Digest())
	l = log.WithBytes(l, "relaydata", r.RelayData())
	l.Debug("received relay cell")
}

func RelayHandler(conn *Connection, c Cell) error {
	// Fetch the corresponding circuit.
	circ, ok := conn.circuits.Circuit(c.CircID())
	if !ok {
		// BUG(mbm): should close curcuit.
		return errors.New("unknown circuit")
	}

	// Decrypt.
	p := c.Payload()
	circ.Forward.XORKeyStream(p, p)

	fmt.Println(hex.Dump(p))

	// Parse as relay cell.
	r := NewRelayCellFromBytes(p)
	LogRelayCell(conn.logger, r)

	return nil
}
