// Package torcrypto provides cryptographic functions useful in tor.
package torcrypto

import "crypto/rand"

// Rand generates n bytes of cryptographic random. Panics if the read fails.
func Rand(n int) []byte {
	x := make([]byte, n)
	_, err := rand.Read(x)
	if err != nil {
		panic(err)
	}
	return x
}
