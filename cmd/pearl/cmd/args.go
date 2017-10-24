package cmd

import (
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/mmcloughlin/pearl/tordir"
	"github.com/spf13/pflag"
)

// Defined argument sets.
var (
	relayData   = new(RelayData)
	authorities = new(DirectoryAuthorities)
)

// Module is something that can be configured with command line arguments.
type Module interface {
	Attach(*pflag.FlagSet)
}

// Register adds a list of modules to the given flag set.
func Register(f *pflag.FlagSet, modules ...Module) {
	for _, m := range modules {
		m.Attach(f)
	}
}

// RelayData configures relay data directory.
type RelayData struct {
	dir string
}

func (d *RelayData) Attach(f *pflag.FlagSet) {
	f.StringVarP(&d.dir, "data-dir", "d", "", "data directory")
}

func (d *RelayData) Data() torconfig.Data {
	return torconfig.NewDataDirectory(d.dir)
}

// DirectoryAuthorities configures which directory authorities to publish to.
type DirectoryAuthorities struct {
	public bool
	addrs  []string
}

// Attach configures command line flags.
func (a *DirectoryAuthorities) Attach(f *pflag.FlagSet) {
	f.BoolVar(&a.public, "public", false, "publish to public directory authorities")
	f.StringSliceVar(&a.addrs, "authorities", []string{"127.0.0.1:7000"}, "directory authorities to publish to")
}

// Addresses returns configured directory authority addresses.
func (a *DirectoryAuthorities) Addresses() []string {
	if a.public {
		return tordir.Authorities
	}
	return a.addrs
}
