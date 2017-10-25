package torconfig

import "net"

// Config encapsulates configuration options for a Tor relay.
type Config struct {
	Nickname         string
	IP               net.IP
	ORPort           uint16
	Platform         string
	Contact          string
	BandwidthAverage int
	BandwidthBurst   int
	Keys             *Keys
	Data             Data
}

// ORAddr returns the address of the relay.
func (c Config) ORAddr() string {
	addr := net.TCPAddr{
		IP:   c.IP,
		Port: int(c.ORPort),
	}
	return addr.String()
}
