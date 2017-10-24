package torconfig

import "path/filepath"

// Data is an interface to router data storage.
type Data interface {
	Keys() (*Keys, error)
	SetKeys(*Keys) error
}

// dataDirectory manages the data directory structure for a relay.
type dataDirectory string

// NewDataDirectory constructs a new data directory at dir.
func NewDataDirectory(dir string) Data {
	return dataDirectory(dir)
}

// Keys loads keys from the data directory.
func (d dataDirectory) Keys() (*Keys, error) {
	return LoadKeysFromDirectory(d.keysDir())
}

// SetKeys writes keys to the data directory.
func (d dataDirectory) SetKeys(k *Keys) error {
	return k.SaveToDirectory(d.keysDir())
}

func (d dataDirectory) keysDir() string {
	return d.path("keys")
}

// path constructs a path to sub inside the data directory.
func (d dataDirectory) path(sub string) string {
	return filepath.Join(string(d), sub)
}
