package torconfig

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadKeysFromDirectory(t *testing.T) {
	dir := "testdata/keys"
	keyfiles := []string{"secret_id_key", "secret_onion_key", "secret_onion_key_ntor"}
	for _, name := range keyfiles {
		err := os.Chmod(filepath.Join(dir, name), 0600)
		require.NoError(t, err)
	}
	_, err := LoadKeysFromDirectory(dir)
	require.NoError(t, err)
}

func TestKeysRoundTrip(t *testing.T) {
	start, err := GenerateKeys()
	require.NoError(t, err)

	dir, err := ioutil.TempDir("", "pearltorkeystest")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	err = start.SaveToDirectory(dir)
	require.NoError(t, err)

	k, err := LoadKeysFromDirectory(dir)
	require.NoError(t, err)

	assert.Equal(t, start, k)
}
