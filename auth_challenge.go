package pearl

import (
	"crypto/rand"
	"encoding/binary"

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
	_, err := rand.Read(challenge[:])
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
	return NewAuthChallengeCell([]AuthMethod{1})
}

// Cell constructs the cell bytes.
func (a AuthChallengeCell) Cell(f CellFormat) (Cell, error) {
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L605-L607
	//
	//	       Challenge [32 octets]
	//	       N_Methods [2 octets]
	//	       Methods   [2 * N_Methods octets]
	//
	m := len(a.Methods)
	n := 32 + 2 + 2*m
	c := NewCellEmptyPayload(f, 0, AuthChallenge, uint16(n))
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
