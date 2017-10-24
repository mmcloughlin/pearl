package torconfig

import (
	"crypto/rsa"
	"os"
	"path/filepath"

	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/pkg/errors"
)

// Standard filenames for key files.
const (
	identityKeyFilename = "secret_id_key"
	onionKeyFilename    = "secret_onion_key"
	ntorKeyFilename     = "secret_onion_key_ntor"
)

type Keys struct {
	Identity *rsa.PrivateKey
	Onion    *rsa.PrivateKey
	Ntor     *torcrypto.Curve25519KeyPair
}

func GenerateKeys() (*Keys, error) {
	idKey, err := torcrypto.GenerateRSA()
	if err != nil {
		return nil, err
	}

	onionKey, err := torcrypto.GenerateRSA()
	if err != nil {
		return nil, err
	}

	ntorKey, err := torcrypto.GenerateCurve25519KeyPair()
	if err != nil {
		return nil, err
	}

	return &Keys{
		Identity: idKey,
		Onion:    onionKey,
		Ntor:     ntorKey,
	}, nil
}

func LoadKeysFromDirectory(path string) (*Keys, error) {
	k := &Keys{}
	var err error

	k.Identity, err = torcrypto.LoadRSAPrivateKeyFromPEMFile(filepath.Join(path, identityKeyFilename))
	if err != nil {
		return nil, errors.Wrap(err, "failed to load identity key")
	}

	k.Onion, err = torcrypto.LoadRSAPrivateKeyFromPEMFile(filepath.Join(path, onionKeyFilename))
	if err != nil {
		return nil, errors.Wrap(err, "failed to load onion key")
	}

	k.Ntor, err = torcrypto.LoadCurve25519KeyPairPrivateKeyFromFile(filepath.Join(path, ntorKeyFilename), "onion")
	if err != nil {
		return nil, errors.Wrap(err, "failed to load onion ntor key")
	}

	return k, nil
}

func (k *Keys) SaveToDirectory(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.ErrExist
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := torcrypto.SaveRSAPrivateKeyToPEMFile(k.Identity, filepath.Join(path, identityKeyFilename)); err != nil {
		return err
	}
	if err := torcrypto.SaveRSAPrivateKeyToPEMFile(k.Onion, filepath.Join(path, onionKeyFilename)); err != nil {
		return err
	}
	if err := torcrypto.SaveCurve25519KeyPairPrivateKeyToFile(k.Ntor, filepath.Join(path, ntorKeyFilename), "onion"); err != nil {
		return err
	}
	return nil
}
