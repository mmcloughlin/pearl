package torcrypto

import (
	"crypto/rsa"
	"crypto/sha1"

	"github.com/pkg/errors"
)

// Reference: https://github.com/torproject/torspec/blob/f9eeae509344dcfd1f185d0130a0055b00131cea/tor-spec.txt#L124-L142
//
//	0.4. A bad hybrid encryption algorithm, for legacy purposes.
//
//	   Some specifications will refer to the "legacy hybrid encryption" of a
//	   byte sequence M with a public key PK.  It is computed as follows:
//
//	      1. If the length of M is no more than PK_ENC_LEN-PK_PAD_LEN,
//	         pad and encrypt M with PK.
//	      2. Otherwise, generate a KEY_LEN byte random key K.
//	         Let M1 = the first PK_ENC_LEN-PK_PAD_LEN-KEY_LEN bytes of M,
//	         and let M2 = the rest of M.
//	         Pad and encrypt K|M1 with PK.  Encrypt M2 with our stream cipher,
//	         using the key K.  Concatenate these encrypted values.
//
//	   Note that this "hybrid encryption" approach does not prevent
//	   an attacker from adding or removing bytes to the end of M. It also
//	   allows attackers to modify the bytes not covered by the OAEP --
//	   see Goldberg's PET2006 paper for details.  Do not use it as the basis
//	   for new protocols! Also note that as used in Tor's protocols, case 1
//	   never occurs.
//

// HybridDecrypt decrypts ciphertext z with private key pk accoriding to "legacy
// hybrid encryption".
func HybridDecrypt(pk *rsa.PrivateKey, z []byte) ([]byte, error) {
	if len(z) < PublicKeyMessageSize {
		return nil, errors.New("cipher too short")
	}

	z1, z2 := z[:PublicKeyMessageSize], z[PublicKeyMessageSize:]

	// Based on the C tor code we need to use RSA_PKCS1_OAEP_PADDING.
	//
	// Reference: https://github.com/openssl/openssl/blob/1e3f62a3823f7e3db9d403f724fd9d66f5b04cf8/doc/man3/RSA_public_encrypt.pod#L31-L35
	//
	//	=item RSA_PKCS1_OAEP_PADDING
	//
	//	EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty
	//	encoding parameter. This mode is recommended for all new applications.
	//
	//
	p, err := rsa.DecryptOAEP(sha1.New(), nil, pk, z1, nil)
	if err != nil {
		return nil, errors.Wrap(err, "private key decryption failure")
	}

	n := PublicKeyMessageSize - PublicKeyPaddingSize
	if len(p) < n {
		return p, nil
	}

	k := p[:StreamCipherKeySize]
	m1 := p[StreamCipherKeySize:]

	m2 := make([]byte, len(z2))
	s := NewStream(k)
	s.XORKeyStream(m2, z2)

	return append(m1, m2...), nil
}
