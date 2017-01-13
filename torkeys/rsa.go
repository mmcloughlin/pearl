package torkeys

import (
	"crypto/sha1"

	"github.com/mmcloughlin/openssl"
)

// GenerateRSA generates an RSA key pair according to the Tor requirements.
//
// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L77-L80
//
//	   For a public-key cipher, we use RSA with 1024-bit keys and a fixed
//	   exponent of 65537.  We use OAEP-MGF1 padding, with SHA-1 as its digest
//	   function.  We leave the optional "Label" parameter unset. (For OAEP
//	   padding, see ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf)
//
func GenerateRSA() (openssl.PrivateKey, error) {
	return openssl.GenerateRSAKeyWithExponent(1024, 65537)
}

// PublicKeyHash computes the hash of a public key as defined in the spec
// below.
//
// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L109-L110
//
//	   When we refer to "the hash of a public key", we mean the SHA-1 hash of the
//	   DER encoding of an ASN.1 RSA public key (as specified in PKCS.1).
//
func PublicKeyHash(k openssl.PublicKey) ([]byte, error) {
	der, err := k.MarshalPKCS1PublicKeyDER()
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(der)

	return h[:], nil
}
