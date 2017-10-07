package torkeys

import (
	"crypto/aes"
	"crypto/cipher"
)

// NewStream constructs a new stream cipher.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L77-L78
//
//	   For a stream cipher, unless otherwise specified, we use 128-bit AES in
//	   counter mode, with an IV of all 0 bytes.  (We also require AES256.)
//
func NewStream(key []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	return cipher.NewCTR(block, iv)
}
