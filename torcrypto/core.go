// Package torcrypto provides cryptographic functions useful in tor.
package torcrypto

import (
	"crypto/rand"
	"hash"
)

// Reference: https://github.com/torproject/torspec/blob/f9eeae509344dcfd1f185d0130a0055b00131cea/tor-spec.txt#L52-L70
//
//	   KEY_LEN -- the length of the stream cipher's key, in bytes.
//
//	   PK_ENC_LEN -- the length of a public-key encrypted message, in bytes.
//	   PK_PAD_LEN -- the number of bytes added in padding for public-key
//	     encryption, in bytes. (The largest number of bytes that can be encrypted
//	     in a single public-key operation is therefore PK_ENC_LEN-PK_PAD_LEN.)
//
//	   DH_LEN -- the number of bytes used to represent a member of the
//	     Diffie-Hellman group.
//	   DH_SEC_LEN -- the number of bytes used in a Diffie-Hellman private key (x).
//
//	   HASH_LEN -- the length of the hash function's output, in bytes.
//
//	   PAYLOAD_LEN -- The longest allowable cell payload, in bytes. (509)
//
//	   CELL_LEN(v) -- The length of a Tor cell, in bytes, for link protocol
//	      version v.
//	       CELL_LEN(v) = 512    if v is less than 4;
//	                   = 514    otherwise.
//

// Security parameters.
//
// Reference: https://github.com/torproject/torspec/blob/f9eeae509344dcfd1f185d0130a0055b00131cea/tor-spec.txt#L109-L112
//
//	   KEY_LEN=16.
//	   DH_LEN=128; DH_SEC_LEN=40.
//	   PK_ENC_LEN=128; PK_PAD_LEN=42.
//	   HASH_LEN=20.
//
const (
	StreamCipherKeySize  = 16
	DiffieHellmanSize    = 128
	PublicKeyMessageSize = 128
	PublicKeyPaddingSize = 42
	HashSize             = 20
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
