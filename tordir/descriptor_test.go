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
MIGJAoGBAMe1RFNxr3yHhLigZr4oNlvqgyldE6fdHQgWwV/w9E0RGTiatSD4+Mu6
RO3OJhVg8MNooPcPO4wS/zPbjfCZ3sJIk+rKKKCKnlyk1KWpXGgbat4ZloyGXs1c
ZexdoiqI6TFP1kSHrKK5hDvsdWQllSW4Y4WdRcCIzcEdRDTCDMo5AgMBAAE=
-----END RSA PUBLIC KEY-----
`)

func TestServerDescriptor(t *testing.T) {
	s := NewServerDescriptor()

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
	k, err := openssl.LoadPublicKeyFromPKCS1PEM(keyPEM)
	require.NoError(t, err)
	s.SetOnionKey(k)

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

func TestServerDescriptorSetOnionKeyError(t *testing.T) {
	m := &mocks.PublicKey{}
	m.On("MarshalPKCS1PublicKeyDER").Return(nil, assert.AnError).Once()
	s := NewServerDescriptor()
	err := s.SetOnionKey(m)
	assert.Error(t, err)
	m.AssertExpectations(t)
}

func TestServerDescriptorMissingFieldError(t *testing.T) {
	err := ServerDescriptorMissingFieldError("foo")
	assert.EqualError(t, err, "missing field 'foo'")
}
