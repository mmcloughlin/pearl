package pearl

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/sha1"
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
	stream cipher.Stream
	prev   *sha1.Digest
	digest *sha1.Digest
}

func NewCircuitCryptoState(d, k []byte) *CircuitCryptoState {
	h := sha1.New()
	h.Write(d)
	return &CircuitCryptoState{
		prev:   h,
		digest: h,
		stream: torcrypto.NewStream(k),
	}
}

func (c *CircuitCryptoState) Sum() []byte {
	return c.digest.Sum(nil)
}

func (c *CircuitCryptoState) Digest() uint32 {
	s := c.Sum()
	return binary.BigEndian.Uint32(s)
}

func (c *CircuitCryptoState) RewindDigest() {
	c.digest = c.prev
}

func (c *CircuitCryptoState) Decrypt(b []byte) {
	c.stream.XORKeyStream(b, b)

	// Backup digest
	c.prev = c.digest.Clone()

	// Update digest by hashing the relay cell with digest cleared.
	r := relayCell(b)
	d := r.Digest()
	r.ClearDigest()
	c.digest.Write(b)
	r.SetDigest(d)
}

func (c *CircuitCryptoState) Encrypt(b []byte) {
	// Backup digest
	c.prev = c.digest.Clone()

	// Update digest by hashing the relay cell with digest cleared.
	r := relayCell(b)
	r.ClearDigest()
	c.digest.Write(b)

	// Set correct value of the digest field
	r.SetDigest(c.Digest())

	c.stream.XORKeyStream(b, b)
}

// TransverseCircuit is a circuit transiting through the relay.
type TransverseCircuit struct {
	Router   *Router
	Prev     CircuitLink
	Next     CircuitLink
	Forward  *CircuitCryptoState
	Backward *CircuitCryptoState
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
			// TODO(mbm): count relay early cells
			// XXX error handling
			err = t.handleForwardRelay(cell)
			if err != nil {
				log.Err(t.logger, err, "forward relay failed")
			}
		default:
			t.logger.Error("unrecognized cell")
		}
	}
}

func (t TransverseCircuit) handleForwardRelay(c Cell) error {
	// Decrypt payload.
	p := c.Payload()
	t.Forward.Decrypt(p)

	// Parse as relay cell.
	r := NewRelayCellFromBytes(p)
	logger := RelayCellLogger(t.logger, r)
	logger.Debug("received relay cell")

	// Should the cell be forwarded?
	if !relayCellIsRecogized(r, t.Forward) {
		// TODO(mbm): forward cell
		logger.Error("cell not recognized")
		return nil
	}

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
	d, err := r.RelayData()
	if err != nil {
		return errors.Wrap(err, "error extracting relay data")
	}
	err = ext.UnmarshalBinary(d)
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

	err = t.Next.SendCell(cell)
	if err != nil {
		return errors.Wrap(err, "failed to send create cell")
	}

	// Wait for CREATED2 cell
	t.logger.Info("waiting for CREATED2")
	cell, err = t.Next.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "failed to receive cell")
	}

	if cell.Command() != Created2 {
		return ErrUnexpectedCommand
	}

	created2, err := ParseCreated2Cell(cell)
	if err != nil {
		return errors.Wrap(err, "failed to parse created2 cell")
	}

	// Reply with EXTENDED2
	cell = NewFixedCell(t.Prev.CircID(), Relay)
	ext2 := NewRelayCell(RelayExtended2, 0, created2.Payload())
	copy(cell.Payload(), ext2.Bytes())
	t.Backward.Encrypt(cell.Payload())

	err = t.Prev.SendCell(cell)
	if err != nil {
		return errors.Wrap(err, "failed to send relay extend cell")
	}

	return nil
}

func relayCellIsRecogized(r RelayCell, cs *CircuitCryptoState) bool {
	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L1446-L1452
	//
	//	   The 'recognized' field in any unencrypted relay payload is always set
	//	   to zero; the 'digest' field is computed as the first four bytes of
	//	   the running digest of all the bytes that have been destined for
	//	   this hop of the circuit or originated from this hop of the circuit,
	//	   seeded from Df or Db respectively (obtained in section 5.2 above),
	//	   and including this RELAY cell's entire payload (taken with the digest
	//	   field set to zero).
	//

	if !RelayCellHasRecognizedZero(r) {
		return false
	}

	digest := cs.Digest()
	if digest != r.Digest() {
		cs.RewindDigest()
		return false
	}

	return true
}
