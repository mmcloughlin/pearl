package torcrypto

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPermissionsAtMost(t *testing.T) {
	dir, err := ioutil.TempDir("", "permstest")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	createPermFile := func(perm os.FileMode) string {
		octal := fmt.Sprintf("0%03o", perm)
		filename := filepath.Join(dir, octal)
		err := ioutil.WriteFile(filename, []byte(octal), perm)
		require.NoError(t, err)
		return filename
	}

	cases := []struct {
		Filename     string
		Allow        os.FileMode
		ErrorMessage string
	}{
		{"doesnotexist", 0777, "stat doesnotexist: no such file or directory"},
		{createPermFile(0600), 0600, ""},
		{createPermFile(0644), 0600, "permissions must be at most 0600"},
		{createPermFile(0777), 0644, "permissions must be at most 0644"},
		{createPermFile(0640), 0644, ""},
	}
	for _, c := range cases {
		err := checkPermissionsAtMost(c.Filename, c.Allow)
		if c.ErrorMessage != "" {
			assert.EqualError(t, err, c.ErrorMessage)
		} else {
			assert.NoError(t, err)
		}
	}
}
