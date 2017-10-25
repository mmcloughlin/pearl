package torconfig

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTorrcFile(t *testing.T) {
	cfg, err := ParseTorrcFile("testdata/torrc")
	require.NoError(t, err)

	expect := &Config{
		Nickname:         "JetpacksPlease",
		IP:               net.IPv4(12, 34, 56, 78),
		ORPort:           9001,
		Contact:          "Harm Aarts <XXXX ET XXXX>",
		BandwidthAverage: 102400,
		BandwidthBurst:   26843545600,
	}

	assert.Equal(t, expect, cfg)
}

func TestParseTorrcFileMissing(t *testing.T) {
	_, err := ParseTorrcFile("doesnotexist")
	assert.Error(t, err)
}

func TestParseTorrcErrors(t *testing.T) {
	cases := []struct {
		Name  string
		Input string
	}{
		{"MissingArgs", "Keyword\n"},
		{"ORPortBad", "ORPort bad\n"},
		{"ORPortOverflow", "ORPort 65536\n"},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			b := strings.NewReader(c.Input)
			_, err := ParseTorrc(b)
			assert.Error(t, err)
		})
	}
}

type errorReader struct {
	err error
}

func (e errorReader) Read(_ []byte) (int, error) {
	return 0, e.err
}

func TestParseTorrcReaderError(t *testing.T) {
	r := errorReader{err: assert.AnError}
	_, err := ParseTorrc(r)
	assert.Error(t, err)
}
