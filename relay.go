package pearl

import (
	"encoding/binary"
	"errors"

	"github.com/mmcloughlin/pearl/log"
)

type RelayCell interface {
	RelayCommand() RelayCommand
	Recognized() []byte
	StreamID() uint16
	Digest() []byte
	RelayData() []byte
}

// relayCell interprets a byte slice as a relay cell.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1414-L1420
//
//	   The payload of each unencrypted RELAY cell consists of:
//	         Relay command           [1 byte]
//	         'Recognized'            [2 bytes]
//	         StreamID                [2 bytes]
//	         Digest                  [4 bytes]
//	         Length                  [2 bytes]
//	         Data                    [PAYLOAD_LEN-11 bytes]
//
type relayCell []byte

func (r relayCell) RelayCommand() RelayCommand {
	return RelayCommand(r[0])
}

func (r relayCell) Recognized() []byte {
	return r[1:3]
}

func (r relayCell) StreamID() uint16 {
	return binary.BigEndian.Uint16(r[3:])
}

func (r relayCell) Digest() []byte {
	return r[5:9]
}

func (r relayCell) RelayData() []byte {
	n := binary.BigEndian.Uint16(r[9:])
	return r[11 : 11+int(n)]
}

func RelayCellIsRecogized(r RelayCell) bool {
	rec := r.Recognized()
	return rec[0] == 0 && rec[1] == 0
}

func NewRelayCellFromBytes(b []byte) RelayCell {
	return relayCell(b)
}

func RelayCellLogger(l log.Logger, r RelayCell) log.Logger {
	l = l.With("relaycmd", r.RelayCommand()).With("streamid", r.StreamID())
	l = log.WithBytes(l, "digest", r.Digest())
	l = log.WithBytes(l, "relaydata", r.RelayData())
	return l
}

func RelayHandler(conn *Connection, c Cell) error {
	// Fetch the corresponding circuit.
	circ, ok := conn.circuits.Circuit(c.CircID())
	if !ok {
		// TODO(mbm): should close curcuit.
		return errors.New("unknown circuit")
	}

	// Decrypt.
	p := c.Payload()
	circ.Forward.XORKeyStream(p, p)

	// Parse as relay cell.
	r := NewRelayCellFromBytes(p)
	logger := RelayCellLogger(conn.logger, r)
	logger.Debug("received relay cell")

	// TODO(mbm): relay cell recognized and digest handling
	logger.Error("digest handling not implemented")

	// TODO(mbm): Director pattern for relay cells?
	switch r.RelayCommand() {
	default:
		logger.Warn("no handler registered")
	}

	return nil
}
