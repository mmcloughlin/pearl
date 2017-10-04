package pearl

import (
	"encoding/binary"
	"errors"
)

// HandshakeType is an identifier for a circuit handshake type.
type HandshakeType uint16

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L877-L880
//
//	   Recognized handshake types are:
//	       0x0000  TAP  -- the original Tor handshake; see 5.1.3
//	       0x0001  reserved
//	       0x0002  ntor -- the ntor+curve25519+sha256 handshake; see 5.1.4
//
var (
	HandshakeTypeTAP  HandshakeType
	HandshakeTypeNTOR HandshakeType = 2
)

// Create2Cell represents a CREATE2 cell.
type Create2Cell struct {
	CircID        CircID
	HandshakeType HandshakeType
	HandshakeData []byte
}

// ParseCreate2Cell parses a CREATE2 cell.
func ParseCreate2Cell(c Cell) (*Create2Cell, error) {
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L868-L871
	//
	//	   A CREATE2 cell contains:
	//	       HTYPE     (Client Handshake Type)     [2 bytes]
	//	       HLEN      (Client Handshake Data Len) [2 bytes]
	//	       HDATA     (Client Handshake Data)     [HLEN bytes]
	//
	if c.Command() != Create2 {
		return nil, ErrUnexpectedCommand
	}

	payload := c.Payload()
	n := len(payload)

	if n < 4 {
		return nil, errors.New("create2 cell too short")
	}

	htype := binary.BigEndian.Uint16(payload)
	hlen := binary.BigEndian.Uint16(payload[2:])

	if n < int(4+hlen) {
		return nil, errors.New("inconsistent create2 cell length")
	}

	return &Create2Cell{
		CircID:        c.CircID(),
		HandshakeType: HandshakeType(htype),
		HandshakeData: payload[4 : 4+hlen],
	}, nil
}

// Cell builds a cell from the CREATE2 payload.
func (c Create2Cell) Cell(f CellFormat) (Cell, error) {
	hlen := len(c.HandshakeData)
	cell := NewFixedCell(f, c.CircID, Create2)
	payload := cell.Payload()

	binary.BigEndian.PutUint16(payload, uint16(c.HandshakeType))
	binary.BigEndian.PutUint16(payload[2:], uint16(hlen))
	copy(payload[4:], c.HandshakeData)

	return cell, nil
}
