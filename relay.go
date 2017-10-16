package pearl

import (
	"encoding/binary"
	"errors"

	"github.com/mmcloughlin/pearl/log"
)

type RelayCell interface {
	RelayCommand() RelayCommand
	Recognized() uint16
	StreamID() uint16
	Digest() uint32
	RelayData() ([]byte, error)
	Bytes() []byte
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

func (r relayCell) Bytes() []byte {
	return r
}

func (r relayCell) RelayCommand() RelayCommand {
	return RelayCommand(r[0])
}

func (r relayCell) SetRelayCommand(cmd RelayCommand) {
	r[0] = byte(cmd)
}

func (r relayCell) Recognized() uint16 {
	return binary.BigEndian.Uint16(r[1:])
}

func (r relayCell) ClearRecognized() {
	r[1] = 0
	r[2] = 0
}

func (r relayCell) StreamID() uint16 {
	return binary.BigEndian.Uint16(r[3:])
}

func (r relayCell) SetStreamID(id uint16) {
	binary.BigEndian.PutUint16(r[3:], id)
}

func (r relayCell) Digest() uint32 {
	return binary.BigEndian.Uint32(r[5:9])
}

func (r relayCell) SetDigest(d uint32) {
	binary.BigEndian.PutUint32(r[5:9], d)
}

func (r relayCell) ClearDigest() {
	r.SetDigest(0)
}

func (r relayCell) DataLength() int {
	return int(binary.BigEndian.Uint16(r[9:]))
}

func (r relayCell) SetDataLength(n uint16) {
	binary.BigEndian.PutUint16(r[9:], n)
}

func (r relayCell) RelayData() ([]byte, error) {
	if r.DataLength() > len(r)-11 {
		return nil, errors.New("relay cell data length is too large")
	}
	return r[11 : 11+r.DataLength()], nil
}

func (r relayCell) SetData(data []byte) error {
	n := len(data)
	r.SetDataLength(uint16(n))
	d, err := r.RelayData()
	if err != nil {
		return err
	}
	copy(d, data)
	return nil
}

func NewRelayCellFromBytes(b []byte) RelayCell {
	if len(b) != MaxPayloadLength {
		panic("relay cell payload expected to be max payload length")
	}
	return relayCell(b)
}

func NewRelayCell(cmd RelayCommand, streamID uint16, data []byte) RelayCell {
	r := relayCell(make([]byte, MaxPayloadLength))
	r.SetRelayCommand(cmd)
	r.ClearRecognized()
	r.SetStreamID(streamID)
	r.ClearDigest()
	err := r.SetData(data)
	if err != nil {
		panic(err)
	}
	return r
}

func RelayCellLogger(l log.Logger, r RelayCell) log.Logger {
	return l.With("relaycmd", r.RelayCommand()).
		With("streamid", r.StreamID()).
		With("digest", r.Digest()).
		With("recognized", r.Recognized())
}
