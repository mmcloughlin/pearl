package tordir

import (
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	// should have all required fields
	assert.NoError(t, s.Validate())

	doc, err := s.Document()
	require.NoError(t, err)

	expect, err := ioutil.ReadFile("./testdata/descriptors/example")
	assert.Equal(t, expect, doc.Encode())
}

func TestServerDescriptorSetRouterErrors(t *testing.T) {
	s := NewServerDescriptor()

	err := s.SetRouter("^%*^%*^%*", net.IPv4(1, 2, 3, 4), 9001, 0)
	assert.Error(t, err)

	addr := net.ParseIP("2001:4860:0:2001::68")
	err = s.SetRouter("nickname", addr, 9001, 0)
	assert.Error(t, err)
}
