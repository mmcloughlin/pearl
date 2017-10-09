package torcrypto

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivatePKCS1DERRoundTrip(t *testing.T) {
	b, err := ioutil.ReadFile("testdata/pkcs1_private_der")
	require.NoError(t, err)
	k, err := ParseRSAPrivateKeyPKCS1DER(b)
	require.NoError(t, err)
	b2 := MarshalRSAPrivateKeyPKCS1DER(k)
	assert.Equal(t, b, b2)
}

func TestPrivatePKCS1PEMRoundTrip(t *testing.T) {
	b, err := ioutil.ReadFile("testdata/pkcs1_private_pem")
	require.NoError(t, err)
	k, err := ParseRSAPrivateKeyPKCS1PEM(b)
	require.NoError(t, err)
	b2 := MarshalRSAPrivateKeyPKCS1PEM(k)
	assert.Equal(t, b, b2)
}

func TestPublicPKCS1DERRoundTrip(t *testing.T) {
	b, err := ioutil.ReadFile("testdata/pkcs1_public_der")
	require.NoError(t, err)
	k, err := ParseRSAPublicKeyPKCS1DER(b)
	require.NoError(t, err)
	b2, err := MarshalRSAPublicKeyPKCS1DER(k)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestPublicPKCS1PEMRoundTrip(t *testing.T) {
	b, err := ioutil.ReadFile("testdata/pkcs1_public_pem")
	require.NoError(t, err)
	k, err := ParseRSAPublicKeyPKCS1PEM(b)
	require.NoError(t, err)
	b2, err := MarshalRSAPublicKeyPKCS1PEM(k)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}
