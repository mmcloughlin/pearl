package pearl

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetInfoCell(t *testing.T) {
	n := NetInfoCell{
		Timestamp:       time.Unix(0xbeefcafe, 0),
		ReceiverAddress: net.IPv4(0x11, 0x22, 0x33, 0x44),
		SenderAddresses: []net.IP{
			net.IPv4(16, 32, 64, 128),
			net.IP{
				0xbb, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0xee,
			},
		},
	}

	c, err := n.Cell(CircID2Format{})
	require.NoError(t, err)

	payload := []byte{
		0, 0, // circid
		8,                      // command
		0xbe, 0xef, 0xca, 0xfe, // timestamp
		4, 4, 0x11, 0x22, 0x33, 0x44, // receiver addr
		2,                     // number of addresses
		4, 4, 16, 32, 64, 128, // first sender addr
		6, 16, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee, // second sender addr
	}
	expect := make([]byte, 512)
	copy(expect, payload)

	assert.Equal(t, expect, c.Bytes())
}

func TestNetInfoCellUnencodableAddress(t *testing.T) {
	good := net.IPv4(127, 0, 0, 1)
	bad := net.IP{1, 2, 3, 4, 5, 6, 7}

	netInfoCells := []*NetInfoCell{
		NewNetInfoCell(bad, nil),
		NewNetInfoCell(good, []net.IP{good, bad, good}),
	}

	for _, n := range netInfoCells {
		_, err := n.Cell(CircID2Format{})
		assert.Equal(t, ErrUnencodableAddress, err)
	}
}

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
