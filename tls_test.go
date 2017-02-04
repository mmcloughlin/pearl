package pearl

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
