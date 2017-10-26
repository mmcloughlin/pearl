package torcrypto

import (
	"crypto/sha1"
	"errors"
)

// KDFTOR generates n bytes of key using the KDF-TOR algorithm.
func KDFTOR(k []byte, n int) ([]byte, error) {
	// TODO(mbm): implement KDFTOR as an io.Reader

	// Reference: https://github.com/torproject/torspec/blob/f9eeae509344dcfd1f185d0130a0055b00131cea/tor-spec.txt#L1177-L1179
	//
	//	   From the base key material K0, they compute KEY_LEN*2+HASH_LEN*3 bytes of
	//	   derivative key data as
	//	       K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...
	//

	blocks := (n + sha1.Size - 1) / sha1.Size
	if blocks > 256 {
		return nil, errors.New("cannot generate that much key")
	}
	out := make([]byte, blocks*sha1.BlockSize)

	msg := make([]byte, len(k)+1)
	copy(msg, k)

	cur := out
	for i := 0; i < blocks; i++ {
		d := sha1.Sum(msg)
		copy(cur, d[:])
		cur = cur[len(d):]
		msg[len(k)]++
	}

	return out[:n], nil
}
