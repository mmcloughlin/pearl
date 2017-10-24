package torcrypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

const (
	privateKeyPermissions os.FileMode = 0600
	publicKeyPermissions  os.FileMode = 0644
)

// CheckPrivateKeyPermissions checks whether the given file has appropriate
// permissions for a private key.
func CheckPrivateKeyPermissions(filename string) error {
	return checkPermissionsAtMost(filename, privateKeyPermissions)
}

// SetPrivateKeyPermissions sets permissions on a private key file.
func SetPrivateKeyPermissions(filename string) error {
	return os.Chmod(filename, privateKeyPermissions)
}

func checkPermissionsAtMost(filename string, allow os.FileMode) error {
	s, err := os.Stat(filename)
	if err != nil {
		return err
	}

	perm := s.Mode().Perm()
	if (perm & ^allow) != 0 {
		return errors.Errorf("permissions must be at most 0%03o", allow)
	}

	return nil
}

func LoadRSAPrivateKeyFromPEMFile(filename string) (*rsa.PrivateKey, error) {
	if err := CheckPrivateKeyPermissions(filename); err != nil {
		return nil, err
	}

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
	return ioutil.WriteFile(filename, data, privateKeyPermissions)
}

func LoadRSAPublicKeyFromPEMFile(filename string) (*rsa.PublicKey, error) {
	if err := checkPermissionsAtMost(filename, publicKeyPermissions); err != nil {
		return nil, err
	}

	pem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file")
	}

	k, err := ParseRSAPublicKeyPKCS1PEM(pem)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}

	return k, nil
}

func SaveRSAPublicKeyToPEMFile(k *rsa.PublicKey, filename string) error {
	data, err := MarshalRSAPublicKeyPKCS1PEM(k)
	if err != nil {
		return errors.Wrap(err, "failed to encode public key")
	}
	return ioutil.WriteFile(filename, data, publicKeyPermissions)
}

func LoadCurve25519KeyPairPrivateKeyFromFile(filename, label string) (*Curve25519KeyPair, error) {
	if err := CheckPrivateKeyPermissions(filename); err != nil {
		return nil, err
	}

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

	return ioutil.WriteFile(filename, buf.Bytes(), privateKeyPermissions)
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
