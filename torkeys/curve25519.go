package torkeys

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

var ErrRandomShortRead = errors.New("torkeys: could not read enough random bytes")

type Curve25519KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

func GenerateCurve25519() (*Curve25519KeyPair, error) {
	return generateCurve25519KeyPairFromRandom(rand.Reader)
}

func generateCurve25519KeyPairFromRandom(r io.Reader) (*Curve25519KeyPair, error) {
	kp := &Curve25519KeyPair{}

	n, err := r.Read(kp.Private[:])
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, ErrRandomShortRead
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
