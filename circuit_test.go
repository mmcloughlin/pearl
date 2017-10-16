package pearl

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCircID4(t *testing.T) {
	assert.Equal(t, CircID(0), GenerateCircID(0)>>31)
	assert.Equal(t, CircID(1), GenerateCircID(1)>>31)
}

func TestGenerateCircID4Rand(t *testing.T) {
	assert.NotEqual(t, GenerateCircID(0), GenerateCircID(0))
}

func TestCircuitCryptoStateRewind(t *testing.T) {
	d := []byte("He thought he saw an Elephant")
	s := NewCircuitCryptoState(d, make([]byte, 16))
	s.EncryptOrigin([]byte("That practised on a fife:"))
	expect := s.Sum()
	s.EncryptOrigin([]byte("He looked again, and found it was"))
	assert.NotEqual(t, expect, s.Sum())
	s.RewindDigest()
	assert.Equal(t, expect, s.Sum())
}

func TestCircuitCryptoStateDigestUint32Extraction(t *testing.T) {
	d := make([]byte, 32)
	s := NewCircuitCryptoState(d, make([]byte, 16))
	s.EncryptOrigin(d)
	// $ head -c 64 /dev/zero | sha1sum
	// c8d7d0ef0eedfa82d2ea1aa592845b9a6d4b02b7  -
	assert.Equal(t, "c8d7d0ef0eedfa82d2ea1aa592845b9a6d4b02b7", hex.EncodeToString(s.Sum()))
	assert.Equal(t, uint32(0xc8d7d0ef), s.Digest())
}

func TestCircuitCryptoStateDigestRoundTrip(t *testing.T) {
	// Form two CircuitCryptoStates with the same secrets.
	d := make([]byte, 32)
	k := make([]byte, 16)
	s1 := NewCircuitCryptoState(d, k)
	s2 := NewCircuitCryptoState(d, k)

	// RoundTrip some random data.
	n := 128
	plain := make([]byte, n)
	_, err := rand.Read(plain)
	require.NoError(t, err)
	b := make([]byte, n)
	copy(b, plain)

	s1.EncryptOrigin(b)
	s2.Decrypt(b)

	// Ensure the digests are the same on both states, and it was correctly
	// inserted into the encrypted data.
	r := relayCell(b)
	assert.Equal(t, r.Digest(), s1.Digest())
	assert.Equal(t, s1.Digest(), s2.Digest())
}
