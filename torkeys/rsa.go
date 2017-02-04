package torkeys

import (
	"crypto/sha1"

	"github.com/mmcloughlin/openssl"
)

// PublicKey is an RSA public key.
type PublicKey interface {
	// MarshalPKCS1PublicKeyDER converts the public key to DER-encoded PKCS#1
	// format
	MarshalPKCS1PublicKeyDER() ([]byte, error)

	// MarshalPKCS1PublicKeyPEM converts the public key to PEM-encoded PKCS#1
	// format
	MarshalPKCS1PublicKeyPEM() ([]byte, error)

	// PublicDecrypt decrypts the given data with the public key (for signature
	// verification).
	PublicDecrypt([]byte) ([]byte, error)
}

// Confirm compatibility with openssl type.
var _ PublicKey = (openssl.PublicKey)(nil)

//go:generate mockery -name=PublicKey -case=underscore

// PrivateKey is an RSA private key.
type PrivateKey interface {
	PublicKey

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyPEM() ([]byte, error)

	// PrivateEncrypt encrypts the given data with the private key (for signing).
	PrivateEncrypt([]byte) ([]byte, error)
}

// Confirm compatibility with openssl type.
var _ PrivateKey = (openssl.PrivateKey)(nil)

//go:generate mockery -name=PrivateKey -case=underscore

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
func PublicKeyHash(k PublicKey) ([]byte, error) {
	der, err := k.MarshalPKCS1PublicKeyDER()
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(der)

	return h[:], nil
}
