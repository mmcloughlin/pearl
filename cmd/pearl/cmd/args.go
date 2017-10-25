package cmd

import (
	"net"

	"github.com/mmcloughlin/pearl/meta"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/mmcloughlin/pearl/tordir"
	"github.com/spf13/pflag"
)

// Defined argument sets.
var (
	cfg         = new(Config)
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

type Config struct {
	nickname string
	ip       net.IP
	port     int
	contact  string
	bwAvg    int
	bwBurst  int
	data     RelayData
}

func (c *Config) Attach(f *pflag.FlagSet) {
	f.StringVarP(&c.nickname, "nickname", "n", "pearl", "nickname")
	f.IPVar(&c.ip, "ip", net.IPv4(127, 0, 0, 1), "relay ip")
	f.IntVarP(&c.port, "port", "p", 9111, "relay port")
	f.StringVar(&c.contact, "contact", "https://github.com/mmcloughlin/pearl", "contact information")
	f.IntVar(&c.bwAvg, "bandwidth-average", 75<<10, "bandwidth average (bytes per second)")
	f.IntVar(&c.bwBurst, "bandwidth-burst", 150<<10, "bandwidth burst (bytes per second)")
	Register(f, &c.data)
}

func (c *Config) Config() (*torconfig.Config, error) {
	d := c.data.Data()
	k, err := d.Keys()
	if err != nil {
		return nil, err
	}
	return &torconfig.Config{
		Nickname:         c.nickname,
		IP:               c.ip,
		ORPort:           uint16(c.port),
		Platform:         meta.Platform.String(),
		Contact:          c.contact,
		BandwidthAverage: c.bwAvg,
		BandwidthBurst:   c.bwBurst,
		Keys:             k,
		Data:             d,
	}, nil
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
