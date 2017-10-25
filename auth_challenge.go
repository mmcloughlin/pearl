package pearl

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/mmcloughlin/pearl/debug"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/pkg/errors"
)

// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L601-L617
//
//	4.3. AUTH_CHALLENGE cells
//
//	   An AUTH_CHALLENGE cell is a variable-length cell with the following
//	   fields:
//	       Challenge [32 octets]
//	       N_Methods [2 octets]
//	       Methods   [2 * N_Methods octets]
//
//	   It is sent from the responder to the initiator. Initiators MUST
//	   ignore unexpected bytes at the end of the cell.  Responders MUST
//	   generate every challenge independently using a strong RNG or PRNG.
//
//	   The Challenge field is a randomly generated string that the
//	   initiator must sign (a hash of) as part of authenticating.  The
//	   methods are the authentication methods that the responder will
//	   accept.  Only one authentication method is defined right now:
//	   see 4.4 below.
//

// AuthMethod represents an authentication method ID.
type AuthMethod uint16

// Defined AuthMethod values.
var (
	AuthMethodRSASHA256TLSSecret   AuthMethod = 1
	AuthMethodEd25519SHA256RFC5705 AuthMethod = 3
)

// String represents the AuthMethod as a string. This is also the TYPE value
// expected in AUTHENTICATE cells.
func (m AuthMethod) String() string {
	return fmt.Sprintf("AUTH%04d", int(m))
}

// AuthChallengeCell represents an AUTH_CHALLENGE cell.
type AuthChallengeCell struct {
	Challenge [32]byte
	Methods   []AuthMethod
}

var _ CellBuilder = new(AuthChallengeCell)

// NewAuthChallengeCell builds an AUTH_CHALLENGE cell with the given method IDs.
// The challenge is generated at random.
func NewAuthChallengeCell(methods []AuthMethod) (*AuthChallengeCell, error) {
	var challenge [32]byte
	_, err := cryptorand.Read(challenge[:])
	if err != nil {
		return nil, errors.Wrap(err, "could not read enough random bytes")
	}
	return &AuthChallengeCell{
		Challenge: challenge,
		Methods:   methods,
	}, nil
}

// NewAuthChallengeCellStandard builds an AUTH_CHALLENGE cell for method 1.
func NewAuthChallengeCellStandard() (*AuthChallengeCell, error) {
	return NewAuthChallengeCell([]AuthMethod{AuthMethodRSASHA256TLSSecret})
}

// ParseAuthChallengeCell parses c as an AUTH_CHALLENGE cell.
func ParseAuthChallengeCell(c Cell) (*AuthChallengeCell, error) {
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L700-L702
	//
	//	       Challenge [32 octets]
	//	       N_Methods [2 octets]
	//	       Methods   [2 * N_Methods octets]
	//
	if c.Command() != CommandAuthChallenge {
		return nil, ErrUnexpectedCommand
	}

	p := c.Payload()
	ac := &AuthChallengeCell{}

	if len(p) < 32+2 {
		return nil, ErrShortCellPayload
	}

	copy(ac.Challenge[:], p)
	N := int(binary.BigEndian.Uint16(p[32:]))
	p = p[34:]

	if len(p) < 2*N {
		return nil, ErrShortCellPayload
	}

	ac.Methods = make([]AuthMethod, N)
	for i := 0; i < N; i++ {
		ac.Methods[i] = AuthMethod(binary.BigEndian.Uint16(p))
		p = p[2:]
	}

	return ac, nil
}

func (a AuthChallengeCell) SupportsMethod(m AuthMethod) bool {
	for _, method := range a.Methods {
		if method == m {
			return true
		}
	}
	return false
}

// Cell constructs the cell bytes.
func (a AuthChallengeCell) Cell() (Cell, error) {
	m := len(a.Methods)
	n := 32 + 2 + 2*m
	c := NewCellEmptyPayload(0, CommandAuthChallenge, uint16(n))
	payload := c.Payload()

	copy(payload, a.Challenge[:])
	binary.BigEndian.PutUint16(payload[32:], uint16(m))
	ptr := 34
	for _, method := range a.Methods {
		binary.BigEndian.PutUint16(payload[ptr:], uint16(method))
		ptr += 2
	}

	return c, nil
}

// AuthenticateCell represents an AUTHENTICATE cell.
type AuthenticateCell struct {
	Method         AuthMethod
	Authentication []byte
}

// ParseAuthenticateCell parses Cell c as an AUTHENTICATE cell.
func ParseAuthenticateCell(c Cell) (*AuthenticateCell, error) {
	if c.Command() != CommandAuthenticate {
		return nil, ErrUnexpectedCommand
	}

	payload := c.Payload()
	n := len(payload)

	if n < 4 {
		return nil, errors.New("authenticate cell too short")
	}

	method := binary.BigEndian.Uint16(payload)
	authLen := binary.BigEndian.Uint16(payload[2:])

	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L733-L735
	//
	//	   Responders MUST ignore extra bytes at the end of an AUTHENTICATE
	//	   cell.  Recognized AuthTypes are 1 and 3, described in the next
	//	   two sections.
	//
	if n < int(4+authLen) {
		return nil, errors.New("inconsistent authenticate cell length")
	}

	return &AuthenticateCell{
		Method:         AuthMethod(method),
		Authentication: payload[4 : 4+authLen],
	}, nil
}

// Cell builds a cell from the AuthenticateCell payload.
func (a AuthenticateCell) Cell() (Cell, error) {
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L727-L731
	//
	//	   An AUTHENTICATE cell contains the following:
	//
	//	        AuthType                              [2 octets]
	//	        AuthLen                               [2 octets]
	//	        Authentication                        [AuthLen octets]
	//
	authLen := len(a.Authentication)
	c := NewCellEmptyPayload(0, CommandAuthenticate, uint16(4+authLen))
	payload := c.Payload()

	binary.BigEndian.PutUint16(payload, uint16(a.Method))
	binary.BigEndian.PutUint16(payload[2:], uint16(authLen))
	copy(payload[4:], a.Authentication)

	return c, nil
}

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L741-L774
//
//	4.4.1. Link authentication type 1: RSA-SHA256-TLSSecret
//
//	   If AuthType is 1 (meaning "RSA-SHA256-TLSSecret"), then the
//	   Authentication field of the AUTHENTICATE cell contains the following:
//
//	       TYPE: The characters "AUTH0001" [8 octets]
//	       CID: A SHA256 hash of the initiator's RSA1024 identity key [32 octets]
//	       SID: A SHA256 hash of the responder's RSA1024 identity key [32 octets]
//	       SLOG: A SHA256 hash of all bytes sent from the responder to the
//	         initiator as part of the negotiation up to and including the
//	         AUTH_CHALLENGE cell; that is, the VERSIONS cell, the CERTS cell,
//	         the AUTH_CHALLENGE cell, and any padding cells.  [32 octets]
//	       CLOG: A SHA256 hash of all bytes sent from the initiator to the
//	         responder as part of the negotiation so far; that is, the
//	         VERSIONS cell and the CERTS cell and any padding cells. [32
//	         octets]
//	       SCERT: A SHA256 hash of the responder's TLS link certificate. [32
//	         octets]
//	       TLSSECRETS: A SHA256 HMAC, using the TLS master secret as the
//	         secret key, of the following:
//	           - client_random, as sent in the TLS Client Hello
//	           - server_random, as sent in the TLS Server Hello
//	           - the NUL terminated ASCII string:
//	             "Tor V3 handshake TLS cross-certification"
//	          [32 octets]
//	       RAND: A 24 byte value, randomly chosen by the initiator.  (In an
//	         imitation of SSL3's gmt_unix_time field, older versions of Tor
//	         sent an 8-byte timestamp as the first 8 bytes of this field;
//	         new implementations should not do that.) [24 octets]
//	       SIG: A signature of a SHA256 hash of all the previous fields
//	         using the initiator's "Authenticate" key as presented.  (As
//	         always in Tor, we use OAEP-MGF1 padding; see tor-spec.txt
//	         section 0.3.)
//	          [variable length]
//

type AuthRSASHA256TLSSecretPayload []byte

func NewAuthRSASHA256TLSSecretPayload(b []byte) (AuthRSASHA256TLSSecretPayload, error) {
	p := AuthRSASHA256TLSSecretPayload(b)
	if len(b) <= 224 {
		return p, errors.New("payload too short")
	}
	return p, nil
}

func (p AuthRSASHA256TLSSecretPayload) Body() []byte {
	return p[:200]
}

func (p AuthRSASHA256TLSSecretPayload) Random() []byte {
	return p[200:224]
}

func (p AuthRSASHA256TLSSecretPayload) ToBeSigned() []byte {
	return p[:224]
}

func (p AuthRSASHA256TLSSecretPayload) Signature() []byte {
	return p[224:]
}

type AuthRSASHA256TLSSecret struct {
	AuthKey           *rsa.PrivateKey
	ClientIdentityKey *rsa.PublicKey
	ServerIdentityKey *rsa.PublicKey
	ServerLogHash     []byte
	ClientLogHash     []byte
	ServerLinkCert    []byte
	TLSMasterSecret   []byte
	TLSClientRandom   []byte
	TLSServerRandom   []byte
}

func (a AuthRSASHA256TLSSecret) CID() ([]byte, error) {
	return torcrypto.Fingerprint256(a.ClientIdentityKey)
}

func (a AuthRSASHA256TLSSecret) SID() ([]byte, error) {
	return torcrypto.Fingerprint256(a.ServerIdentityKey)
}

func (a AuthRSASHA256TLSSecret) SCERT() [32]byte {
	return sha256.Sum256(a.ServerLinkCert)
}

func (a AuthRSASHA256TLSSecret) TLSSecrets() []byte {
	h := hmac.New(sha256.New, a.TLSMasterSecret)
	torcrypto.HashWrite(h, a.TLSClientRandom)
	torcrypto.HashWrite(h, a.TLSServerRandom)
	torcrypto.HashWrite(h, []byte("Tor V3 handshake TLS cross-certification\x00"))
	return h.Sum(nil)
}

func (a AuthRSASHA256TLSSecret) Body() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte("AUTH0001"))

	cid, err := a.CID()
	if err != nil {
		return nil, err
	}
	buf.Write(cid)

	sid, err := a.SID()
	if err != nil {
		return nil, err
	}
	buf.Write(sid)

	buf.Write(a.ServerLogHash)

	buf.Write(a.ClientLogHash)

	scert := a.SCERT()
	buf.Write(scert[:])

	buf.Write(a.TLSSecrets())

	return buf.Bytes(), nil
}

func (a AuthRSASHA256TLSSecret) SignedBody() ([]byte, error) {
	var buf bytes.Buffer

	body, err := a.Body()
	if err != nil {
		return nil, err
	}
	buf.Write(body)

	_, err = io.CopyN(&buf, cryptorand.Reader, 24)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read enough random bytes")
	}

	if a.AuthKey == nil {
		return nil, errors.New("cannot sign without auth key")
	}

	sig, err := torcrypto.SignRSASHA256(buf.Bytes(), a.AuthKey)
	if err != nil {
		return nil, err
	}
	buf.Write(sig)

	return buf.Bytes(), nil
}

func (a AuthRSASHA256TLSSecret) Cell() (Cell, error) {
	body, err := a.SignedBody()
	if err != nil {
		return nil, err
	}

	c := &AuthenticateCell{
		Method:         AuthMethodRSASHA256TLSSecret,
		Authentication: body,
	}
	return c.Cell()
}

func (a AuthRSASHA256TLSSecret) GoString() string {
	s := "AuthRSASHA256TLSSecret{\n"
	s += "\tAuthKey: " + debug.GoStringRSAPrivateKey(a.AuthKey) + ",\n"
	s += "\tClientIdentityKey: " + debug.GoStringRSAPublicKey(a.ClientIdentityKey) + ",\n"
	s += "\tServerIdentityKey: " + debug.GoStringRSAPublicKey(a.ServerIdentityKey) + ",\n"
	s += "\tServerLogHash: " + debug.GoStringByteArray(a.ServerLogHash) + ",\n"
	s += "\tClientLogHash: " + debug.GoStringByteArray(a.ClientLogHash) + ",\n"
	s += "\tServerLinkCert: " + debug.GoStringByteArray(a.ServerLinkCert) + ",\n"
	s += "\tTLSMasterSecret: " + debug.GoStringByteArray(a.TLSMasterSecret) + ",\n"
	s += "\tTLSClientRandom: " + debug.GoStringByteArray(a.TLSClientRandom) + ",\n"
	s += "\tTLSServerRandom: " + debug.GoStringByteArray(a.TLSServerRandom) + ",\n"
	s += "}"
	return s
}
