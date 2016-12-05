package tordir

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func SearchWithResponder(responder httpmock.Responder) ([]string, error) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		http.MethodGet,
		"https://onionoo.torproject.org/details?flag=authority&",
		responder,
	)

	return SearchAuthorityDirectoryAddresses()
}

func TestSearchAuthorityDirectoryAddresses(t *testing.T) {
	fixture, err := ioutil.ReadFile("./testdata/onionoo_details.json")
	require.NoError(t, err)

	responder := httpmock.NewBytesResponder(200, fixture)

	addresses, err := SearchWithResponder(responder)
	require.NoError(t, err)
	assert.Equal(t, Authorities, addresses)
}

func TestSearchAuthorityDirectoryAddressesError(t *testing.T) {
	responder := httpmock.NewStringResponder(200, "bad json")
	_, err := SearchWithResponder(responder)
	assert.Error(t, err)
}
