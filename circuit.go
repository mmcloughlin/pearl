package pearl

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"go.uber.org/multierr"

	"github.com/mmcloughlin/pearl/check"
	"github.com/mmcloughlin/pearl/fork/sha1"
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torcrypto"
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
	torcrypto.HashWrite(h, d)
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
	torcrypto.HashWrite(c.digest, b)
	r.SetDigest(d)
}

func (c *CircuitCryptoState) EncryptOrigin(b []byte) {
	// Backup digest
	c.prev = c.digest.Clone()

	// Update digest by hashing the relay cell with digest cleared.
	r := relayCell(b)
	r.ClearDigest()
	torcrypto.HashWrite(c.digest, b)

	// Set correct value of the digest field
	r.SetDigest(c.Digest())

	c.Encrypt(b)
}

func (c *CircuitCryptoState) Encrypt(b []byte) {
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

func NewTransverseCircuit(r *Router, prev CircuitLink, fwd, back *CircuitCryptoState, l log.Logger) *TransverseCircuit {
	circ := &TransverseCircuit{
		Router:   r,
		Prev:     prev,
		Forward:  fwd,
		Backward: back,
		logger:   log.ForComponent(l, "transverse_circuit").With("circid", prev.CircID()),
	}
	r.metrics.Circuits.Alloc()
	return circ
}

// ProcessForward executes a runloop processing cells intended for this circuit.
func (t *TransverseCircuit) ProcessForward() {
	t.receiveLoop(t.Prev, t.Next, t.handleForwardRelay)
}

func (t *TransverseCircuit) receiveLoop(src, dst CircuitLink, handler func(Cell) error) {
	var err error

	for {
		var cell Cell
		cell, err = src.ReceiveCell()
		if err != nil {
			break
		}

		switch cell.Command() {
		case Relay, RelayEarly:
			// TODO(mbm): count relay early cells
			err = handler(cell)
		case Destroy:
			err = t.handleDestroy(cell, dst)
		default:
			t.logger.Error("unrecognized cell")
			err = t.destroy(CircuitErrorProtocol)
		}

		if err != nil {
			break
		}
	}

	if err != nil && !check.EOF(err) {
		log.Err(t.logger, err, "error in circuit handling")
	}

	t.logger.Debug("receive loop exit")
}

func (t *TransverseCircuit) handleForwardRelay(c Cell) error {
	// Decrypt payload.
	p := c.Payload()
	t.Forward.Decrypt(p)

	// Parse as relay cell.
	r := NewRelayCellFromBytes(p)
	logger := RelayCellLogger(t.logger, r)
	logger.Debug("received relay cell")

	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L1369-L1375
	//
	//	   The OR then decides whether it recognizes the relay cell, by
	//	   inspecting the payload as described in section 6.1 below.  If the OR
	//	   recognizes the cell, it processes the contents of the relay cell.
	//	   Otherwise, it passes the decrypted relay cell along the circuit if
	//	   the circuit continues.  If the OR at the end of the circuit
	//	   encounters an unrecognized relay cell, an error has occurred: the OR
	//	   sends a DESTROY cell to tear down the circuit.
	//
	if !relayCellIsRecogized(r, t.Forward) {
		logger.Debug("forwarding unrecognized cell")
		return t.handleUnrecognizedCell(c)
	}

	switch r.RelayCommand() {
	case RelayExtend2:
		return t.handleRelayExtend2(r)
	default:
		logger.Error("no handler registered")
	}

	return nil
}

// handleUnrecognizedCell passes an unrecognized cell onto the next hop.
func (t *TransverseCircuit) handleUnrecognizedCell(c Cell) error {
	if t.Next == nil {
		t.logger.Warn("no next hop")
		return t.destroyWithHops(CircuitErrorProtocol, t.Prev)
	}

	// Clone the cell but swap out the circuit ID.
	// TODO(mbm): forwarding relay cell should not require a copy, rather just
	// a modification of the incoming cell
	f := NewFixedCell(t.Next.CircID(), c.Command())
	copy(f.Payload(), c.Payload())

	err := t.Next.SendCell(f)
	if err != nil {
		t.logger.Warn("could not forward cell")
		return t.destroy(CircuitErrorConnectfailed)
	}

	return nil
}

func (t *TransverseCircuit) handleRelayExtend2(r RelayCell) error {
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
		t.logger.Warn("extend cell on circuit that already has next hop")
		return t.destroy(CircuitErrorProtocol)
	}

	// Parse payload
	ext := &Extend2Payload{}
	d, err := r.RelayData()
	if err != nil {
		log.Err(t.logger, err, "could not extract relay data")
		return t.destroy(CircuitErrorProtocol)
	}
	err = ext.UnmarshalBinary(d)
	if err != nil {
		log.Err(t.logger, err, "bad extend2 playload")
		return t.destroy(CircuitErrorProtocol)
	}

	// Obtain connection to referenced node.
	nextConn, err := t.Router.Connection(ext)
	if err != nil {
		log.Err(t.logger, err, "could not obtain connection to extend node")
		return t.destroy(CircuitErrorConnectfailed)
	}

	// Initialize circuit on the next connection
	t.Next = nextConn.GenerateCircuitLink()

	// Send CREATE2 cell
	cell := NewFixedCell(t.Next.CircID(), Create2)
	copy(cell.Payload(), ext.HandshakeData) // BUG(mbm): overflow risk

	err = t.Next.SendCell(cell)
	if err != nil {
		log.Err(t.logger, err, "failed to send create cell")
		return t.destroy(CircuitErrorConnectfailed)
	}

	// Wait for CREATED2 cell
	t.logger.Debug("waiting for CREATED2")
	cell, err = t.Next.ReceiveCell()
	if err != nil {
		log.Err(t.logger, err, "failed to receive cell")
		return t.destroy(CircuitErrorConnectfailed)
	}

	if cell.Command() != Created2 {
		t.logger.Error("expected create2 cell")
		return t.destroy(CircuitErrorProtocol)
	}

	created2, err := ParseCreated2Cell(cell)
	if err != nil {
		log.Err(t.logger, err, "failed to parse created2 cell")
		return t.destroy(CircuitErrorProtocol)
	}

	// Reply with EXTENDED2
	cell = NewFixedCell(t.Prev.CircID(), Relay)
	ext2 := NewRelayCell(RelayExtended2, 0, created2.Payload())
	copy(cell.Payload(), ext2.Bytes())
	t.Backward.EncryptOrigin(cell.Payload())

	err = t.Prev.SendCell(cell)
	if err != nil {
		log.Err(t.logger, err, "failed to send relay extend cell")
		return t.destroy(CircuitErrorConnectfailed)
	}

	// TODO(mbm): better goroutine management
	// Process cells received from the next hop
	go t.ProcessBackward()

	t.logger.Info("circuit extended")

	return nil
}

func (t *TransverseCircuit) handleDestroy(c Cell, other CircuitLink) error {
	var reason CircuitErrorCode
	d, err := ParseDestroyCell(c)
	if err != nil {
		log.Err(t.logger, err, "failed to parse destroy cell")
		reason = CircuitErrorNone
	} else if d != nil {
		reason = d.Reason
	}

	return t.destroyWithHops(reason, other)
}

func (t *TransverseCircuit) destroyWithHops(reason CircuitErrorCode, hops ...CircuitLink) error {
	t.logger.With("reason", reason).Info("destroying circuit")
	return multierr.Combine(
		t.free(),
		announceDestroy(reason, hops...),
	)
}

func (t *TransverseCircuit) destroy(reason CircuitErrorCode) error {
	return t.destroyWithHops(reason, t.Prev, t.Next)
}

func (t *TransverseCircuit) free() error {
	var result error

	t.Router.metrics.Circuits.Free()

	for _, c := range []io.Closer{t.Prev, t.Next} {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			result = multierr.Append(result, err)
		}
	}

	return result
}

// ProcessBackward executes a runloop processing cells to be sent back in the
// direction of the originator of the circuit.
func (t *TransverseCircuit) ProcessBackward() {
	t.receiveLoop(t.Next, t.Prev, t.handleBackwardRelay)
}

func (t *TransverseCircuit) handleBackwardRelay(c Cell) error {
	// Encrypt payload.
	p := c.Payload()
	t.Backward.Encrypt(p)

	// Clone the cell but swap out the circuit ID.
	// TODO(mbm): forwarding relay cell should not require a copy, rather just
	// a modification of the incoming cell
	f := NewFixedCell(t.Prev.CircID(), c.Command())
	copy(f.Payload(), c.Payload())

	err := t.Prev.SendCell(f)
	if err != nil {
		t.logger.Warn("could not forward cell")
		return t.destroy(CircuitErrorConnectfailed)
	}

	return nil
}

func announceDestroy(reason CircuitErrorCode, hops ...CircuitLink) error {
	var result error
	for _, hop := range hops {
		if hop == nil {
			continue
		}
		d := NewDestroyCell(hop.CircID(), reason)
		if err := hop.SendCell(d.Cell()); err != nil {
			result = multierr.Append(result, err)
		}
	}
	return result
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

	if r.Recognized() != 0 {
		return false
	}

	digest := cs.Digest()
	if digest != r.Digest() {
		cs.RewindDigest()
		return false
	}

	return true
}
