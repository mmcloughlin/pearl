package torcrypto

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPermissionsAtMost(t *testing.T) {
	cases := []struct {
		Filename     string
		Allow        os.FileMode
		ErrorMessage string
	}{
		{"doesnotexist", 0777, "stat doesnotexist: no such file or directory"},
		{"testdata/perm0600", 0600, ""},
		{"testdata/perm0640", 0600, "permissions must be at most 0600"},
		{"testdata/perm0777", 0644, "permissions must be at most 0644"},
		{"testdata/perm0640", 0644, ""},
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
