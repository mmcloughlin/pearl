package torcrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"

	"github.com/pkg/errors"
)

func MustRSAPrivateKey(k *rsa.PrivateKey, err error) *rsa.PrivateKey {
	if err != nil {
		panic(err)
	}
	return k
}

func MustRSAPublicKey(k *rsa.PublicKey, err error) *rsa.PublicKey {
	if err != nil {
		panic(err)
	}
	return k
}

// MarshalRSAPrivateKeyPKCS1DER encodes k as PKCS#1 DER.
func MarshalRSAPrivateKeyPKCS1DER(k *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(k)
}

// ParseRSAPrivateKeyPKCS1DER decodes PKCS#1 DER encoded private key.
func ParseRSAPrivateKeyPKCS1DER(b []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(b)
}

// MarshalRSAPrivateKeyPKCS1PEM encodes k as PKCS#1 PEM.
func MarshalRSAPrivateKeyPKCS1PEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: MarshalRSAPrivateKeyPKCS1DER(k),
		},
	)
}

// ParseRSAPrivateKeyPKCS1PEM decodes PKCS#1 PEM encoded private key.
func ParseRSAPrivateKeyPKCS1PEM(b []byte) (*rsa.PrivateKey, error) {
	d, _ := pem.Decode(b)
	if d == nil {
		return nil, errors.New("could not decode PEM block")
	}
	return ParseRSAPrivateKeyPKCS1DER(d.Bytes)
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS#1 public key.
//
// https://github.com/golang/go/blob/d8ff3d592088ef175222dbf69991887f0dd458d6/src/crypto/x509/pkcs1.go#L38
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// MarshalRSAPublicKeyPKCS1DER encodes k as PKCS#1 DER.
func MarshalRSAPublicKeyPKCS1DER(k *rsa.PublicKey) ([]byte, error) {
	return asn1.Marshal(pkcs1PublicKey{
		N: k.N,
		E: k.E,
	})
}

// ParseRSAPublicKeyPKCS1DER decodes PKCS#1 DER encoded public key.
func ParseRSAPublicKeyPKCS1DER(b []byte) (*rsa.PublicKey, error) {
	p := new(pkcs1PublicKey)
	rest, err := asn1.Unmarshal(b, p)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding ASN.1")
	}
	if len(rest) != 0 {
		return nil, errors.New("unexpected extra data")
	}
	return &rsa.PublicKey{
		N: p.N,
		E: p.E,
	}, nil
}

// MarshalRSAPublicKeyPKCS1PEM encodes k as PKCS#1 PEM.
func MarshalRSAPublicKeyPKCS1PEM(k *rsa.PublicKey) ([]byte, error) {
	b, err := MarshalRSAPublicKeyPKCS1DER(k)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode as DER")
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: b,
		},
	), nil
}

// ParseRSAPublicKeyPKCS1PEM decodes PKCS#1 PEM encoded public key.
func ParseRSAPublicKeyPKCS1PEM(b []byte) (*rsa.PublicKey, error) {
	d, _ := pem.Decode(b)
	if d == nil {
		return nil, errors.New("could not decode PEM block")
	}
	return ParseRSAPublicKeyPKCS1DER(d.Bytes)
}

func ParseRSAPublicKeyFromCertificateDER(der []byte) (*rsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse DER-encoded certificate")
	}

	k, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("non-RSA public key")
	}

	return k, nil
}
