package tordir

import (
	"io/ioutil"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerDescriptor(t *testing.T) {
	s := NewServerDescriptor()

	err := s.Validate()
	assert.Error(t, err)

	s.SetRouter("nickname", net.IPv4(1, 2, 3, 4), 9001, 0)

	err = s.Validate()
	assert.NoError(t, err)

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
