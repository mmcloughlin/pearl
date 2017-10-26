package torcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffieHellmanShared(t *testing.T) {
	a, err := GenerateDiffieHellmanKey()
	require.NoError(t, err)

	b, err := GenerateDiffieHellmanKey()
	require.NoError(t, err)

	ak, err := a.ComputeSharedSecret(b.Public[:])
	require.NoError(t, err)

	bk, err := b.ComputeSharedSecret(a.Public[:])
	require.NoError(t, err)

	assert.Equal(t, ak, bk)
}
