package torcrypto

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Curve25519KeyPair represents a public/private curve25519 keys.
//
// curve25519 keys are used in the ntor handshake.
//
// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L82
//
//	   For the "ntor" handshake, we also use the Curve25519 elliptic curve group.
//
// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L157-L163
//
//	   This is Curve25519 key:
//
//	    - A medium-term ntor "Onion key" used to handle onion key handshakes when
//	      accepting incoming circuit extend requests.  As with TAP onion keys,
//	      old ntor keys MUST be accepted for at least one week after they are no
//	      longer advertised.  Because of this, relays MUST retain old keys for a
//	      while after they're rotated.
//
type Curve25519KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateCurve25519KeyPair generates a Curve25519KeyPair using crypto/rand as
// the random source.
func GenerateCurve25519KeyPair() (*Curve25519KeyPair, error) {
	return generateCurve25519KeyPairFromRandom(rand.Reader)
}

// generateCurve25519KeyPairFromRandom generates a Curve25519KeyPair using the
// provided reader to generate the private key.
func generateCurve25519KeyPairFromRandom(r io.Reader) (*Curve25519KeyPair, error) {
	kp := &Curve25519KeyPair{}

	_, err := io.ReadFull(r, kp.Private[:])
	if err != nil {
		return nil, err
	}

	// Note that the curve25519 library ensures required bits are clamped in
	// the private key.
	//
	// Reference: https://github.com/golang/crypto/blob/master/curve25519/curve25519.go#L792-L798
	//
	//	func scalarMult(out, in, base *[32]byte) {
	//		var e [32]byte
	//
	//		copy(e[:], in[:])
	//		e[0] &= 248
	//		e[31] &= 127
	//		e[31] |= 64
	//

	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)

	return kp, nil
}
