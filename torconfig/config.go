package torconfig

import (
	"net"
	"strconv"
)

// Config encapsulates configuration options for a Tor relay.
type Config struct {
	Nickname string
	Host     string
	ORPort   uint16
	Platform string
	Contact  string
	Keys     *Keys
}

// ORAddr returns the address of the relay.
func (c Config) ORAddr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(int(c.ORPort)))
}
