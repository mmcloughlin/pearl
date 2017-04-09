package pearl

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeAddressIPv4(t *testing.T) {
	ip := net.IPv4(1, 2, 3, 4)
	b := EncodeAddress(ip)
	assert.Equal(t, []byte{4, 4, 1, 2, 3, 4}, b)
}

func TestEncodeAddressIPv6(t *testing.T) {
	ip := net.IP{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}
	b := EncodeAddress(ip)
	assert.Equal(t, []byte{
		6, 16,
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	}, b)
}

func TestEncodeAddressError(t *testing.T) {
	ip := net.IP{1, 2, 3, 4, 5}
	b := EncodeAddress(ip)
	assert.Nil(t, b)
}
