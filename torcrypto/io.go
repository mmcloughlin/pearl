package torcrypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
)

func LoadRSAPrivateKeyFromPEMFile(filename string) (*rsa.PrivateKey, error) {
	pem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file")
	}

	k, err := ParseRSAPrivateKeyPKCS1PEM(pem)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse private key")
	}

	return k, nil
}

func SaveRSAPrivateKeyToPEMFile(k *rsa.PrivateKey, filename string) error {
	data := MarshalRSAPrivateKeyPKCS1PEM(k)
	return ioutil.WriteFile(filename, data, 0600)
}

func LoadCurve25519KeyPairPrivateKeyFromFile(filename, label string) (*Curve25519KeyPair, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file")
	}

	if len(b) != 96 {
		return nil, errors.New("curve25519 key file should be 96 bytes")
	}

	magic, err := curve25519FileMagic(label)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(b[:32], magic) {
		return nil, errors.New("incorrect magic bytes in curve25519 key file")
	}

	k := &Curve25519KeyPair{}
	copy(k.Private[:], b[32:64])
	copy(k.Public[:], b[64:96])

	return k, nil
}

func SaveCurve25519KeyPairPrivateKeyToFile(k *Curve25519KeyPair, filename, label string) error {
	var buf bytes.Buffer

	magic, err := curve25519FileMagic(label)
	if err != nil {
		return err
	}

	buf.Write(magic)
	buf.Write(k.Private[:])
	buf.Write(k.Public[:])

	return ioutil.WriteFile(filename, buf.Bytes(), 0600)
}

func curve25519FileMagic(label string) ([]byte, error) {
	leader := fmt.Sprintf("== c25519v1: %s ==", label)
	if len(leader) > 32 {
		return nil, errors.New("label too long")
	}

	magic := make([]byte, 32)
	copy(magic, []byte(leader))

	return magic, nil
}
