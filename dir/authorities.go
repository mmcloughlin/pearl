package dir

import "github.com/erans/gonionoo"

// Authorities is a list of the directory addresses for the Tor directory
// authorities. This is unlikely to change often, but can be queried with the
// SearchAuthorityDirectoryAddresses() function. Listed at
// https://atlas.torproject.org/#search/flag:authority.
var Authorities = []string{
	"86.59.21.38:80",
	"154.35.175.225:80",
	"193.23.244.244:80",
	"37.218.247.217:80",
	"128.31.0.34:9131",
	"171.25.193.9:443",
	"131.188.40.189:80",
	"194.109.206.212:80",
	"199.254.238.53:80",
}

// SearchAuthorityDirectoryAddresses queries the onionoo API for the directory
// addresses of the Tor authorities.
func SearchAuthorityDirectoryAddresses() ([]string, error) {
	query := map[string]string{
		"flag": "authority",
	}

	details, err := gonionoo.GetDetails(query)
	if err != nil {
		return nil, err
	}

	addresses := make([]string, len(details.Relays))
	for i, relay := range details.Relays {
		addresses[i] = relay.DirAddress
	}

	return addresses, nil
}
