package pearl

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/mmcloughlin/pearl/torkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSA1024(t *testing.T) {
	id, err := torkeys.GenerateRSA()
	require.NoError(t, err)
	ctx, err := NewTLSContext(id)
	require.NoError(t, err)
	assert.Equal(t, 1024, torkeys.RSAKeySize(ctx.AuthKey))
	assert.Equal(t, 1024, torkeys.RSAKeySize(ctx.LinkKey))
}

func TestRandomHostname(t *testing.T) {
	rand.Seed(1)
	hostname := randomHostname(8, 20, "www.", ".net")
	assert.Equal(t, "www.ph3bgzmiegpcry2lvf.net", hostname)
}

func TestRandomHostnameProperties(t *testing.T) {
	trials := 100
	min := 8
	max := 20
	prefix := "www."
	suffix := ".com"
	extraLen := len(prefix) + len(suffix)
	for i := 0; i < trials; i++ {
		hostname := randomHostname(min, max, prefix, suffix)
		require.True(t, len(hostname) >= min+extraLen)
		require.True(t, len(hostname) <= max+extraLen)
		assert.True(t, strings.HasPrefix(hostname, prefix))
		assert.True(t, strings.HasSuffix(hostname, suffix))
		// Reference: https://github.com/torproject/tor/blob/master/src/common/util_format.h#L23-L25
		//
		//	/** Characters that can appear (case-insensitively) in a base32 encoding. */
		//	#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"
		//	void base32_encode(char *dest, size_t destlen, const char *src, size_t srclen);
		//
		alpha := []byte("abcdefghijklmnopqrstuvwxyz234567")
		for j := len(prefix); j < len(hostname)-len(suffix); j++ {
			assert.Contains(t, alpha, hostname[j])
		}
	}
}

func TestGenerateCertificateLifetime(t *testing.T) {
	trials := 100
	dayNs := 24 * int64(time.Hour)
	secNs := int64(time.Second)
	for i := 0; i < trials; i++ {
		d := generateCertificateLifetime()
		assert.True(t, d >= time.Duration(5*24)*time.Hour)
		assert.True(t, d < time.Duration(365*24)*time.Hour)
		dNs := int64(d)
		assert.True(t, ((dNs%dayNs) == 0) || (((dNs+secNs)%dayNs) == 0))
	}
}

func TestGenerateCertificateSerial(t *testing.T) {
	trials := 100
	for i := 0; i < trials; i++ {
		serial, err := generateCertificateSerial()
		require.NoError(t, err)
		bytes := serial.Bytes()
		assert.True(t, len(bytes) <= 8)
	}
}

func TestGenerateCertificateSerialKnownValue(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	r := bytes.NewReader(b)
	serial, err := generateCertificateSerialFromRandom(r)
	require.NoError(t, err)
	hx := fmt.Sprintf("%016x", serial)
	assert.Equal(t, "0102030405060708", hx)
}

func TestGenerateCertificateSerialShortRead(t *testing.T) {
	// should fail if it cannot read 8 bytes
	r := strings.NewReader("1234567")
	_, err := generateCertificateSerialFromRandom(r)
	assert.Error(t, err)
}
