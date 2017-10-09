package torcrypto

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
	assert.Equal(t, 1024, RSAKeySize(k))
	// spec requires that exponent is 65537
	assert.Equal(t, 65537, k.E)
}

func TestFingerprint(t *testing.T) {
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

	h, err := Fingerprint(key)
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

	expect := []byte{
		0xda, 0x22, 0xaa, 0xdb, 0xea, 0xe9, 0x58, 0xc3, 0x9b, 0x1d, 0xcc, 0x78,
		0x0b, 0xbd, 0xf6, 0x30, 0x74, 0x99, 0x32, 0xad, 0x72, 0x5f, 0x5c, 0x3b,
		0x9a, 0x99, 0x8f, 0x49, 0x00, 0x5c, 0x35, 0xce, 0x88, 0xa5, 0xeb, 0x9d,
		0x1b, 0xcd, 0x59, 0xa4, 0xef, 0xff, 0xfe, 0xd0, 0xe0, 0x15, 0xc0, 0x3a,
		0xd9, 0x51, 0xa1, 0x7b, 0x2a, 0x88, 0x2e, 0xb6, 0xa6, 0x17, 0x59, 0x3f,
		0xaa, 0x47, 0x8f, 0xab, 0x21, 0xe4, 0x5b, 0x47, 0xcf, 0x60, 0xf3, 0x0a,
		0xbf, 0x2f, 0x20, 0x84, 0x5c, 0xa3, 0x76, 0x5c, 0x43, 0x11, 0x80, 0x67,
		0x76, 0xc6, 0xa8, 0x8e, 0x3c, 0xee, 0x6e, 0x47, 0xb1, 0x36, 0xa8, 0xfb,
		0xc3, 0xfa, 0xcb, 0x23, 0xcf, 0xec, 0xd5, 0xcd, 0x08, 0x2e, 0xb0, 0xcf,
		0x7a, 0xde, 0x03, 0xc1, 0x80, 0xc8, 0x8e, 0x13, 0x70, 0x92, 0x5e, 0xda,
		0x29, 0xfd, 0xf3, 0x9c, 0xbc, 0xb9, 0xb8, 0x3f,
	}

	assert.Equal(t, expect, got)
}
