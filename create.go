package pearl

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/ntor"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/pkg/errors"
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
func (c Create2Cell) Cell() (Cell, error) {
	hlen := len(c.HandshakeData)
	cell := NewFixedCell(c.CircID, Create2)
	payload := cell.Payload()

	binary.BigEndian.PutUint16(payload, uint16(c.HandshakeType))
	binary.BigEndian.PutUint16(payload[2:], uint16(hlen))
	copy(payload[4:], c.HandshakeData)

	return cell, nil
}

// Created2Cell represents a CREATED2 cell.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L873-L875
//
//	   A CREATED2 cell contains:
//	       HLEN      (Server Handshake Data Len) [2 bytes]
//	       HDATA     (Server Handshake Data)     [HLEN bytes]
//
type Created2Cell struct {
	CircID        CircID
	HandshakeData []byte
}

func ParseCreated2Cell(c Cell) (*Created2Cell, error) {
	if c.Command() != Created2 {
		return nil, ErrUnexpectedCommand
	}

	p := c.Payload()
	n := len(p)

	if n < 2 {
		return nil, errors.New("created2 cell too short")
	}

	hlen := binary.BigEndian.Uint16(p)

	if n < int(2+hlen) {
		return nil, errors.New("inconsistent created2 cell length")
	}

	return &Created2Cell{
		CircID:        c.CircID(),
		HandshakeData: p[2 : 2+hlen],
	}, nil
}

// Payload returns just the payload part of the CREATED2 cell.
func (c Created2Cell) Payload() []byte {
	n := len(c.HandshakeData)
	p := make([]byte, 2+n)
	binary.BigEndian.PutUint16(p, uint16(n))
	copy(p[2:], c.HandshakeData)
	return p
}

// Cell builds a cell from the CREATED2 payload.
func (c Created2Cell) Cell() (Cell, error) {
	cell := NewFixedCell(c.CircID, Created2)
	payload := cell.Payload()

	hlen := len(c.HandshakeData)
	binary.BigEndian.PutUint16(payload, uint16(hlen))
	copy(payload[2:], c.HandshakeData)

	return cell, nil
}

// Create2Handler handles a received CREATE2 cell.
func Create2Handler(conn *Connection, c Cell) error {
	cr, err := ParseCreate2Cell(c)
	if err != nil {
		return errors.Wrap(err, "failed to parse create2 cell")
	}

	if cr.HandshakeType != HandshakeTypeNTOR {
		return errors.New("only support NTOR handshake")
	}

	return ProcessHandshakeNTOR(conn, cr)
}

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1075-L1077
//
//	      H_LENGTH  = 32.
//	      ID_LENGTH = 20.
//	      G_LENGTH  = 32
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1095-L1098
//
//	   and generates a client-side handshake with contents:
//	       NODEID      Server identity digest  [ID_LENGTH bytes]
//	       KEYID       KEYID(B)                [H_LENGTH bytes]
//	       CLIENT_PK   X                       [G_LENGTH bytes]
//
type ClientHandshakeDataNTOR []byte

func (h ClientHandshakeDataNTOR) ServerFingerprint() []byte { return h[:20] }
func (h ClientHandshakeDataNTOR) KeyID() []byte             { return h[20:52] }

func (h ClientHandshakeDataNTOR) ClientPK() [32]byte {
	var X [32]byte
	copy(X[:], h[52:84])
	return X
}

func ProcessHandshakeNTOR(conn *Connection, c *Create2Cell) error {
	clientData := ClientHandshakeDataNTOR(c.HandshakeData)

	// Verify the fingerprint matches.
	got := clientData.ServerFingerprint()
	expect := conn.router.Fingerprint()
	ctx := log.WithBytes(conn.logger, "client_handshake_fingerprint", got)
	ctx = log.WithBytes(ctx, "server_fingerprint", expect)
	if !bytes.Equal(got, expect) {
		ctx.Notice("fingerprints do not match")
		return errors.New("incorrect server fingerprint")
	}
	ctx.Debug("verified server fingerprint")

	// Verify the NTOR key ID matches.
	got = clientData.KeyID()
	expect = conn.router.ntorKey.Public[:]
	ctx = conn.logger
	ctx = log.WithBytes(ctx, "client_handshake_keyid", got)
	ctx = log.WithBytes(ctx, "server_keyid", expect)
	if !bytes.Equal(got, expect) {
		ctx.Notice("ntor key ids do not match")
		return errors.New("incorrect ntor key id")
	}
	ctx.Debug("verified ntor key id")

	serverKeyPair, err := torcrypto.GenerateCurve25519KeyPair()
	if err != nil {
		return errors.Wrap(err, "failed to generate server key pair")
	}

	h := ntor.ServerHandshake{
		Public: ntor.Public{
			ID: conn.router.Fingerprint(),
			KX: clientData.ClientPK(),
			KY: serverKeyPair.Public,
			KB: conn.router.ntorKey.Public,
		},
		Ky: serverKeyPair.Private,
		Kb: conn.router.ntorKey.Private,
	}

	// Record results
	lk, err := conn.NewCircuitLink(c.CircID)
	if err != nil {
		return errors.Wrap(err, "failed to open circuit link")
	}

	fwd, back, err := BuildCircuitKeysNTOR(ntor.KDF(h))
	if err != nil {
		return errors.Wrap(err, "failed to build circuit")
	}

	circ := &TransverseCircuit{
		Router:   conn.router,
		Prev:     lk,
		Forward:  fwd,
		Backward: back,
		logger:   conn.logger.With("circid", c.CircID),
	}
	// TODO(mbm): goroutine management
	go circ.ProcessForward()

	// Send reply
	//
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1108-L1110
	//
	//	   The server's handshake reply is:
	//	       SERVER_PK   Y                       [G_LENGTH bytes]
	//	       AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
	//
	hd := NewServerHandshakeDataNTOR(serverKeyPair.Public, ntor.Auth(h))
	reply := &Created2Cell{
		CircID:        c.CircID,
		HandshakeData: hd,
	}

	err = BuildAndSend(conn, reply)
	if err != nil {
		return errors.Wrap(err, "could not send created2 cell")
	}

	conn.logger.Info("sent created2 cell")

	return nil
}

// BuildCircuitKeysNTOR generates Circuit key material from r.
func BuildCircuitKeysNTOR(r io.Reader) (*CircuitCryptoState, *CircuitCryptoState, error) {
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1210-L1214
	//
	//	   When used in the ntor handshake, the first HASH_LEN bytes form the
	//	   forward digest Df; the next HASH_LEN form the backward digest Db; the
	//	   next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
	//	   DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
	//	   hidden service protocol.  Excess bytes from K are discarded.
	//
	var k [72]byte
	_, err := io.ReadFull(r, k[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "short read for circuit key material")
	}

	forward := NewCircuitCryptoState(k[:20], k[40:56])
	backward := NewCircuitCryptoState(k[20:40], k[56:72])

	return forward, backward, nil
}

// ServerHandshakeDataNTOR represents server handshake data for the NTOR handshake.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1108-L1110
//
//	   The server's handshake reply is:
//	       SERVER_PK   Y                       [G_LENGTH bytes]
//	       AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
//
type ServerHandshakeDataNTOR []byte

func NewServerHandshakeDataNTOR(Y [32]byte, auth []byte) ServerHandshakeDataNTOR {
	var b []byte
	b = append(b, Y[:]...)
	b = append(b, auth...)
	return b
}
