package tordir

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	filenames, err := filepath.Glob("./testdata/descriptors/*")
	require.NoError(t, err)
	for _, filename := range filenames {
		t.Run(filename, func(t *testing.T) {
			b, err := ioutil.ReadFile(filename)
			require.NoError(t, err)

			doc, err := Parse(b)
			require.NoError(t, err)
			assert.Equal(t, b, doc.Encode())
		})
	}
}

func TestParseErrors(t *testing.T) {
	documents := map[string]string{
		"badpem": `keyword
-----BEGIN SOMETHING-----
===============
-----END SOMETHING-----
`,
		"garbage": "keyword\n*$%$*^%$%\nkeyword2\n",
	}

	for name, body := range documents {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(body))
			assert.Error(t, err)
		})
	}
}
