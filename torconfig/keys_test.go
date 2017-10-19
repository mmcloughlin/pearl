package torconfig

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadKeysFromDirectory(t *testing.T) {
	_, err := LoadKeysFromDirectory("./testdata/keys")
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
