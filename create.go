package pearl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/curve25519"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torkeys"
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
func (c Create2Cell) Cell(f CellFormat) (Cell, error) {
	hlen := len(c.HandshakeData)
	cell := NewFixedCell(f, c.CircID, Create2)
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

// Cell builds a cell from the CREATED2 payload.
func (c Created2Cell) Cell(f CellFormat) (Cell, error) {
	cell := NewFixedCell(f, c.CircID, Created2)
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
func (h ClientHandshakeDataNTOR) ClientPK() []byte          { return h[52:84] }

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

	serverKeyPair, err := torkeys.GenerateCurve25519KeyPair()
	if err != nil {
		return errors.Wrap(err, "failed to generate server key pair")
	}

	h := serverHandshakeNTOR{
		ClientPK:          clientData.ClientPK(),
		ServerKeyPair:     serverKeyPair,
		ServerNTORKey:     conn.router.ntorKey,
		ServerFingerprint: conn.router.Fingerprint(),
	}

	// Record results

	// Send reply
	reply := &Created2Cell{
		CircID:        c.CircID,
		HandshakeData: h.Reply(),
	}

	cell, err := reply.Cell(conn.proto.CellFormat())
	if err != nil {
		return errors.Wrap(err, "error building created2 cell")
	}

	_, err = conn.tlsConn.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send created2 cell")
	}

	conn.logger.Info("sent created2 cell")

	return nil
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

// serverHandshakeNTOR assists with computing values in the server-side of
// circuit creation.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1073-L1088
//
//	   In this section, define:
//	      H(x,t) as HMAC_SHA256 with message x and key t.
//	      H_LENGTH  = 32.
//	      ID_LENGTH = 20.
//	      G_LENGTH  = 32
//	      PROTOID   = "ntor-curve25519-sha256-1"
//	      t_mac     = PROTOID | ":mac"
//	      t_key     = PROTOID | ":key_extract"
//	      t_verify  = PROTOID | ":verify"
//	      MULT(a,b) = the multiplication of the curve25519 point 'a' by the
//	                  scalar 'b'.
//	      G         = The preferred base point for curve25519 ([9])
//	      KEYGEN()  = The curve25519 key generation algorithm, returning
//	                  a private/public keypair.
//	      m_expand  = PROTOID | ":key_expand"
//	      KEYID(A)  = A
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1100-L1106
//
//	   The server generates a keypair of y,Y = KEYGEN(), and uses its ntor
//	   private key 'b' to compute:
//
//	     secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
//	     KEY_SEED = H(secret_input, t_key)
//	     verify = H(secret_input, t_verify)
//	     auth_input = verify | ID | B | Y | X | PROTOID | "Server"
//
// TODO(mbm): poorly named
type serverHandshakeNTOR struct {
	ClientPK          []byte
	ServerKeyPair     *torkeys.Curve25519KeyPair
	ServerNTORKey     *torkeys.Curve25519KeyPair
	ServerFingerprint []byte
}

const ntorProtoID = "ntor-curve25519-sha256-1"

// BUG(mbm): SecretInput may be computed multiple times
func (s serverHandshakeNTOR) SecretInput() []byte {
	// Reference: https://github.com/torproject/tor/blob/7505f452c865ef9ca5be35647032f93bfb392762/src/or/onion_ntor.c#L193-L205
	//
	//	  /* build secret_input */
	//	  curve25519_handshake(si, &s.seckey_y, &s.pubkey_X);
	//	  bad = safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
	//	  si += CURVE25519_OUTPUT_LEN;
	//	  curve25519_handshake(si, &keypair_bB->seckey, &s.pubkey_X);
	//	  bad |= safe_mem_is_zero(si, CURVE25519_OUTPUT_LEN);
	//	  si += CURVE25519_OUTPUT_LEN;
	//
	//	  APPEND(si, my_node_id, DIGEST_LEN);
	//	  APPEND(si, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(si, PROTOID, PROTOID_LEN);
	//
	var buf bytes.Buffer
	var t [32]byte
	var X [32]byte
	copy(X[:], s.ClientPK)

	// EXP(X,y)
	curve25519.ScalarMult(&t, &s.ServerKeyPair.Private, &X)
	buf.Write(t[:])

	// EXP(X,b)
	curve25519.ScalarMult(&t, &s.ServerNTORKey.Private, &X)
	buf.Write(t[:])

	// ID
	buf.Write(s.ServerFingerprint)

	// B
	buf.Write(s.ServerNTORKey.Public[:])

	// X
	buf.Write(X[:])

	// Y
	buf.Write(s.ServerKeyPair.Public[:])

	// PROTOID
	buf.Write([]byte(ntorProtoID))

	return buf.Bytes()
}

func (s serverHandshakeNTOR) KeySeed() []byte {
	return ntorHMAC(s.SecretInput(), "key_extract")
}

func (s serverHandshakeNTOR) Verify() []byte {
	return ntorHMAC(s.SecretInput(), "verify")
}

func (s serverHandshakeNTOR) AuthInput() []byte {
	// Reference: https://github.com/torproject/tor/blob/7505f452c865ef9ca5be35647032f93bfb392762/src/or/onion_ntor.c#L211-L218
	//
	//	  /* Compute auth_input */
	//	  APPEND(ai, s.verify, DIGEST256_LEN);
	//	  APPEND(ai, my_node_id, DIGEST_LEN);
	//	  APPEND(ai, keypair_bB->pubkey.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(ai, s.pubkey_Y.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(ai, s.pubkey_X.public_key, CURVE25519_PUBKEY_LEN);
	//	  APPEND(ai, PROTOID, PROTOID_LEN);
	//	  APPEND(ai, SERVER_STR, SERVER_STR_LEN);
	//
	var buf bytes.Buffer

	// verify
	buf.Write(s.Verify())

	// ID
	buf.Write(s.ServerFingerprint)

	// B
	buf.Write(s.ServerNTORKey.Public[:])

	// Y
	buf.Write(s.ServerKeyPair.Public[:])

	// X
	buf.Write(s.ClientPK)

	// PROTOID | "Server"
	buf.Write([]byte(ntorProtoID + "Server"))

	return buf.Bytes()
}

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L1108-L1110
//
//	   The server's handshake reply is:
//	       SERVER_PK   Y                       [G_LENGTH bytes]
//	       AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
//
func (s serverHandshakeNTOR) Auth() []byte {
	return ntorHMAC(s.AuthInput(), "mac")
}

func (s serverHandshakeNTOR) Reply() ServerHandshakeDataNTOR {
	return NewServerHandshakeDataNTOR(s.ServerKeyPair.Public, s.Auth())
}

func ntorHMAC(x []byte, k string) []byte {
	h := hmac.New(sha256.New, []byte(ntorProtoID+":"+k))
	h.Write(x)
	return h.Sum(nil)
}
