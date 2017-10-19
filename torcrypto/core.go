// Package torcrypto provides cryptographic functions useful in tor.
package torcrypto

import (
	"crypto/rand"
	"hash"
)

// Rand generates n bytes of cryptographic random. Panics if the read fails.
func Rand(n int) []byte {
	x := make([]byte, n)
	_, err := rand.Read(x)
	if err != nil {
		panic(err)
	}
	return x
}

// HashWrite provides a convenience for writing to a hash without tripping error
// checking linters. The hash.Hash interface satisfies io.Writer but promises to
// never return an error.
func HashWrite(h hash.Hash, b []byte) {
	// Reference: https://github.com/golang/go/blob/12c9d753f83ab4755151c8a72c212358dd85bc83/src/hash/hash.go#L11-L14
	//
	//	type Hash interface {
	//		// Write (via the embedded io.Writer interface) adds more data to the running hash.
	//		// It never returns an error.
	//		io.Writer
	//
	_, err := h.Write(b)
	if err != nil {
		panic(err)
	}
}
