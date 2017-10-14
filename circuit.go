package pearl

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/pkg/errors"
)

// GenerateCircID generates a 4-byte circuit ID with the given most significant bit.
func GenerateCircID(msb uint32) CircID {
	b := torcrypto.Rand(4)
	x := binary.BigEndian.Uint32(b)
	x = (x >> 1) | (msb << 31)
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

// TransverseCircuit is a circuit transiting through the relay.
type TransverseCircuit struct {
	Router   *Router
	Prev     CircuitLink
	Next     CircuitLink
	Forward  CircuitCryptoState
	Backward CircuitCryptoState
	logger   log.Logger
}

// ProcessForward executes a runloop processing cells intended for this circuit.
func (t TransverseCircuit) ProcessForward() error {
	for {
		cell, err := t.Prev.ReceiveCell()
		if err != nil {
			return err
		}

		switch cell.Command() {
		case Relay:
		case RelayEarly:
			t.handleForwardRelay(cell) // XXX error return
		default:
			t.logger.Error("unrecognized cell")
		}
	}
}

func (t TransverseCircuit) handleForwardRelay(c Cell) error {
	// Decrypt.
	p := c.Payload()
	t.Forward.XORKeyStream(p, p)

	// Parse as relay cell.
	r := NewRelayCellFromBytes(p)
	logger := RelayCellLogger(t.logger, r)
	logger.Debug("received relay cell")

	// TODO(mbm): relay cell recognized and digest handling
	logger.Error("digest handling not implemented")

	switch r.RelayCommand() {
	case RelayExtend2:
		return t.handleRelayExtend2(r)
	default:
		logger.Error("no handler registered")
	}

	return nil
}

func (t TransverseCircuit) handleRelayExtend2(r RelayCell) error {
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1253-L1260
	//
	//	   When an onion router receives an EXTEND relay cell, it sends a CREATE
	//	   cell to the next onion router, with the enclosed onion skin as its
	//	   payload.  As special cases, if the extend cell includes a digest of
	//	   all zeroes, or asks to extend back to the relay that sent the extend
	//	   cell, the circuit will fail and be torn down. The initiating onion
	//	   router chooses some circID not yet used on the connection between the
	//	   two onion routers.  (But see section 5.1.1 above, concerning choosing
	//	   circIDs based on lexicographic order of nicknames.)
	//

	if t.Next != nil {
		return errors.New("circuit already has a next hop established")
	}

	// Parse payload
	ext := &Extend2Payload{}
	err := ext.UnmarshalBinary(r.RelayData())
	if err != nil {
		return errors.Wrap(err, "bad EXTEND2 payload")
	}

	// Obtain connection to referenced node.
	nextConn, err := t.Router.Connection(ext)
	if err != nil {
		return errors.Wrap(err, "could not obtain connection to extend node")
	}

	// Initialize circuit on the next connection
	t.Next = nextConn.GenerateCircuitLink()

	// Send CREATE2 cell
	cell := NewFixedCell(t.Next.CircID(), Create2)
	copy(cell.Payload(), ext.HandshakeData) // BUG(mbm): overflow risk

	return t.Next.SendCell(cell)
}
