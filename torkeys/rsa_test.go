package torkeys

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRSA(t *testing.T) {
	k, err := GenerateRSA()
	require.NoError(t, err)
	// spec requires that exponent is 65537
	assert.Equal(t, 65537, k.E)
}

func TestPublicKeyHash(t *testing.T) {
	// test data taken from a server descriptor
	keyPEM := `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAL3AM6+zg8ICgl0E27D/nGzJEI8AaoCjkiAH03/ltQa/+1sFs3O+M3Js
GfIunes0FpU804Fy2gNZg7d08bquSHuDL/V2U3tjNHQKo3b0FMVYvd8I6nF4djCq
qr9jcmN5zD7BBUua+kHYSEx40uId2T8e4ztpQSeNB32i6p4pWlcbAgMBAAE=
-----END RSA PUBLIC KEY-----
`
	expectedFingerprint := "086E685F66C963A7D50C4A5ABD32BAA1FF2930F8"

	key, err := ParseRSAPublicKeyPKCS1PEM([]byte(keyPEM))
	require.NoError(t, err)

	h, err := PublicKeyHash(key)
	require.NoError(t, err)

	fingerprint := strings.ToUpper(hex.EncodeToString(h))
	assert.Equal(t, expectedFingerprint, fingerprint)
}

func TestSignRSASHA1(t *testing.T) {
	keyPEM := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDjvNig/RTIGeGrlHuKgcvkwvKzpcVAo/UlRdSFed+2WH1QxntX
ffHHYPyO2Gtndtx+Zm+W3/xtixJxmK6mXNjpAOWPtVJ1Colb6djQFSPDJQxoPgT9
LPA3lUMnzndoJxaK6lYd136G7BBolvnvciso/BdyF5mReZ2jfNlLlwWalwIBAwKB
gQCX0zsV/g3au+vHuFJcVoft10x3w9jVwqNuLo2uUT/O5ajghFI6U/aE61MJ5Zzv
pJL+7vUPP/2eXLb2ZcnEPeXvaUXlOTIWWotEbGfPScPRPW63c+4KLjaaaU2/zJhD
ZB5Rq5yYrtyqpDLQW95uWQOCcBau7UmiRZQisjXsqN/9awJBAPXFuiV/qXMbH3b2
rzRlXEpv5/jXsQmIZRcQb/vDV/NmFX+hE+Y8fy3drkX8bsNtGmd+9ZqeUYDTda/2
baBthrECQQDtNv26B6oPnVXQRmnyGKz+dm0XSDzeFergPhgfz6sdgvrpSiTq9wfH
5oHHL9spOMrsdnYZDMyQa/nBkfr5SBfHAkEAo9kmw6pw92dqT08feEOS3EqapeUg
sQWYugr1UoI6okQOVRYNRChUyT50LqhJ154RmlSjvGmLqzejyqRJFZ5ZywJBAJ4k
qSavxrUTjorZm/a7Hf75ng+Ffelj8erUEBU1HL5XUfDcGJykr9qZq9of53DQh0hO
+WYIiGBH+9ZhUfuFZS8CQQDapZNEFGNvWzsTCCArt9SL8J5ON3yewhtexRppmq7+
Wf3oMS8BAJD0D+tSgvm+KQsXL0eIDb/rH9k6ligAhfz1
-----END RSA PRIVATE KEY-----`)
	data := []byte(`Hello World!`)
	priv, err := ParseRSAPrivateKeyPKCS1PEM(keyPEM)
	require.NoError(t, err)
	got, err := SignRSASHA1(data, priv)
	require.NoError(t, err)

	expect := "da22aadbeae958c39b1dcc780bbdf630749932ad725f5c3b9a998f49005c35ce88a5eb9d1bcd59a4effffed0e015c03ad951a17b2a882eb6a617593faa478fab21e45b47cf60f30abf2f20845ca3765c4311806776c6a88e3cee6e47b136a8fbc3facb23cfecd5cd082eb0cf7ade03c180c88e1370925eda29fdf39cbcb9b83f"
	assert.Equal(t, expect, hex.EncodeToString(got))
}
