package tordir

import (
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/mmcloughlin/openssl"
	"github.com/mmcloughlin/pearl/torkeys/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var keyPEM = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMX8r0RFoXr7etUrzJqOAQx1hAeqLwMyMU3xbkBBlLXn+8wTcOvyOAKP
3+MP3pQZyI/+oK2D0N3PLQk4CyrigF8AjR91QVAHcVxC1DOouA54seki5JoTWbZ2
z45XOAsoekZM1K0Mb2LF6Z+7gjdtdl5D5Cdp5THpcekJDqhjuBo3AgMBAAE=
-----END RSA PUBLIC KEY-----
`)

func TestServerDescriptor(t *testing.T) {
	s := NewServerDescriptor()

	k, err := openssl.LoadPublicKeyFromPKCS1PEM(keyPEM)
	require.NoError(t, err)

	// router (required)
	assert.Error(t, s.Validate())
	s.SetRouter("nickname", net.IPv4(1, 2, 3, 4), 9001, 0)

	// bandwidth (required)
	assert.Error(t, s.Validate())
	s.SetBandwidth(1000, 2000, 500)

	// published time (required)
	assert.Error(t, s.Validate())
	loc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	s.SetPublishedTime(time.Date(2016, 12, 25, 10, 33, 17, 3534, loc))

	// onion-key (required)
	assert.Error(t, s.Validate())
	s.SetOnionKey(k)

	// signing-key (required)
	assert.Error(t, s.Validate())
	s.SetSigningKey(k)

	// should have all required fields
	assert.NoError(t, s.Validate())

	doc, err := s.Document()
	require.NoError(t, err)

	expect, err := ioutil.ReadFile("./testdata/descriptors/example")
	require.NoError(t, err)
	assert.Equal(t, expect, doc.Encode())
}

func TestServerDescriptorCreateInvalid(t *testing.T) {
	s := NewServerDescriptor()
	_, err := s.Document()
	assert.Error(t, err)
}

func TestServerDescriptorSetRouterErrors(t *testing.T) {
	s := NewServerDescriptor()

	err := s.SetRouter("^%*^%*^%*", net.IPv4(1, 2, 3, 4), 9001, 0)
	assert.Error(t, err)

	addr := net.ParseIP("2001:4860:0:2001::68")
	err = s.SetRouter("nickname", addr, 9001, 0)
	assert.Error(t, err)
}

func TestServerDescriptorSetKeysError(t *testing.T) {
	m := &mocks.PublicKey{}
	m.On("MarshalPKCS1PublicKeyDER").Return(nil, assert.AnError).Times(3)

	s := NewServerDescriptor()

	err := s.SetOnionKey(m)
	assert.Error(t, err)

	err = s.SetSigningKey(m)
	assert.Error(t, err)

	err = s.setFingerprint(m)
	assert.Error(t, err)

	m.AssertExpectations(t)
}

func TestServerDescriptorMissingFieldError(t *testing.T) {
	err := ServerDescriptorMissingFieldError("foo")
	assert.EqualError(t, err, "missing field 'foo'")
}
