package torkeys

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateExpectedOutput(t *testing.T) {
	t.Skip()

	k, err := GenerateRSA()
	require.NoError(t, err)

	cases := []struct {
		Name    string
		Encoder func() ([]byte, error)
	}{
		{"pkcs1_private_der", k.MarshalPKCS1PrivateKeyDER},
		{"pkcs1_private_pem", k.MarshalPKCS1PrivateKeyPEM},
		{"pkcs1_public_der", k.MarshalPKCS1PublicKeyDER},
		{"pkcs1_public_pem", k.MarshalPKCS1PublicKeyPEM},
		{"pkix_public_der", k.MarshalPKIXPublicKeyDER},
		{"pkix_public_pem", k.MarshalPKIXPublicKeyDER},
	}

	for _, c := range cases {
		b, err := c.Encoder()
		require.NoError(t, err)
		err = ioutil.WriteFile("testdata/"+c.Name, b, 0640)
		require.NoError(t, err)
	}
}

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
