package torkeys

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
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
func GenerateRSA() (*rsa.PrivateKey, error) {
	return GenerateRSAWithBits(1024)
}

// GenerateRSAWithBits generates an RSA private key of the given size.
func GenerateRSAWithBits(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(cryptorand.Reader, bits)
}

// Fingerprint computes the SHA-1 hash of a public key referred to as a
// fingerprint.
func Fingerprint(k *rsa.PublicKey) ([]byte, error) {
	return publicKeyHash(k, sha1.New())
}

// Fingerprint256 computes the SHA-256 hash of a public key.
func Fingerprint256(k *rsa.PublicKey) ([]byte, error) {
	return publicKeyHash(k, sha256.New())
}

// publicKeyHash computes the hash of a public key as defined in the spec
// below.
//
// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L116-L118
//
//	   When we refer to "the hash of a public key", unless otherwise
//	   specified, we mean the SHA-1 hash of the DER encoding of an ASN.1 RSA
//	   public key (as specified in PKCS.1).
//
func publicKeyHash(k *rsa.PublicKey, h hash.Hash) ([]byte, error) {
	der, err := MarshalRSAPublicKeyPKCS1DER(k)
	if err != nil {
		return nil, err
	}

	_, err = h.Write(der)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// SignRSASHA1 signs data with k. This is the RSA encryption of the SHA-1 hash
// of data, with PKCS#1 v1.5 padding.
func SignRSASHA1(data []byte, k *rsa.PrivateKey) ([]byte, error) {
	digest := sha1.Sum(data)
	return rsa.SignPKCS1v15(nil, k, 0, digest[:])
}
