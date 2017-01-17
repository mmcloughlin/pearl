package torkeys

import (
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mmcloughlin/openssl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRSA(t *testing.T) {
	_, err := GenerateRSA()
	require.NoError(t, err)
}

func TestPublicKeyHash(t *testing.T) {
	// test data taken from a server descriptor
	keyPEM := `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAL3AM6+zg8ICgl0E27D/nGzJEI8AaoCjkiAH03/ltQa/+1sFs3O+M3Js
GfIunes0FpU804Fy2gNZg7d08bquSHuDL/V2U3tjNHQKo3b0FMVYvd8I6nF4djCq
qr9jcmN5zD7BBUua+kHYSEx40uId2T8e4ztpQSeNB32i6p4pWlcbAgMBAAE=
-----END RSA PUBLIC KEY-----
`
	expectedFingerprint := "086E685F66C963A7D50C4A5ABD32BAA1FF2930F8"

	key, err := openssl.LoadPublicKeyFromPKCS1PEM([]byte(keyPEM))
	require.NoError(t, err)

	h, err := PublicKeyHash(key)
	require.NoError(t, err)

	fingerprint := strings.ToUpper(hex.EncodeToString(h))
	assert.Equal(t, expectedFingerprint, fingerprint)
}

// TestExpectedBehaviorDERAndPEM really just confirms my understanding that
// the data in the PEM block is just the DER encoded public key.
func TestExpectedBehaviorDERAndPEM(t *testing.T) {
	k, err := GenerateRSA()
	require.NoError(t, err)

	der, err := k.MarshalPKCS1PublicKeyDER()
	require.NoError(t, err)

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}
	data := pem.EncodeToMemory(block)

	expect, err := k.MarshalPKCS1PublicKeyPEM()
	require.NoError(t, err)

	assert.Equal(t, expect, data)
}
