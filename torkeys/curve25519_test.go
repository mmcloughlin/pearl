package torkeys

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reference: https://tools.ietf.org/id/draft-josefsson-tls-curve25519-04.txt (508-538)
//
//	Appendix A.  Test vectors
//
//	   This section provides some test vectors for example Diffie-Hellman
//	   key exchanges using Curve25519.  The following notations are used:
//
//	   d_A  the secret key of party A
//
//	   x_A  the public key of party A
//
//	   d_B  the secret key of party B
//
//	   x_B  the public key of party B
//
//	   x_S  the shared secret that results from completion of the Diffie-
//	      Hellman computation, i.e., the hex representation of the pre-
//	      master secret.
//
//	   The field elements x_A, x_B, and x_S are represented as hexadecimal
//	   values using the FieldElement-to-OctetString conversion method
//	   specified in [SEC1].
//
//	          d_A = 5AC99F33632E5A768DE7E81BF854C27C46E3FBF2ABBACD29EC4AFF51
//	                7369C660
//	          d_B = 47DC3D214174820E1154B49BC6CDB2ABD45EE95817055D255AA35831
//	                B70D3260
//	          x_A = 057E23EA9F1CBE8A27168F6E696A791DE61DD3AF7ACD4EEACC6E7BA5
//	                14FDA863
//	          x_B = 6EB89DA91989AE37C7EAC7618D9E5C4951DBA1D73C285AE1CD26A855
//	                020EEF04
//	          x_S = 61450CD98E36016B58776A897A9F0AEF738B99F09468B8D6B8511184
//	                D53494AB
//
func TestGenerateCurve25519KeyPairFromRandom(t *testing.T) {
	dABigEndianHex := "5AC99F33632E5A768DE7E81BF854C27C46E3FBF2ABBACD29EC4AFF517369C660"
	dABigEndian, err := hex.DecodeString(dABigEndianHex)
	require.NoError(t, err)
	dALittleEndian := ReverseBytes(dABigEndian)

	xABigEndianHex := "057E23EA9F1CBE8A27168F6E696A791DE61DD3AF7ACD4EEACC6E7BA514FDA863"
	xABigEndian, err := hex.DecodeString(xABigEndianHex)
	require.NoError(t, err)
	xALittleEndian := ReverseBytes(xABigEndian)

	r := bytes.NewBuffer(dALittleEndian)
	kp, err := generateCurve25519KeyPairFromRandom(r)
	require.NoError(t, err)

	assert.Equal(t, dALittleEndian, kp.Private[:])
	assert.Equal(t, xALittleEndian, kp.Public[:])
}

func ReverseBytes(x []byte) []byte {
	n := len(x)
	rev := make([]byte, n)
	for i := 0; i < n; i++ {
		rev[i] = x[n-1-i]
	}
	return rev
}
