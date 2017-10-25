package torconfig

import "net"

// Config encapsulates configuration options for a Tor relay.
type Config struct {
	Nickname         string
	IP               net.IP // Relay public IP
	ORBindIP         net.IP // OR bind address
	ORPort           uint16
	Platform         string
	Contact          string
	BandwidthAverage int
	BandwidthBurst   int
	Keys             *Keys
	Data             Data
}

// ORBindAddr returns the address the relay should bind to.
func (c Config) ORBindAddr() string {
	addr := net.TCPAddr{
		IP:   c.ORBindIP,
		Port: int(c.ORPort),
	}
	return addr.String()
}
