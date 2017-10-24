package torconfig

// Config encapsulates configuration options for a Tor relay.
type Config struct {
	Nickname string
	Address  string
	ORPort   uint16
	Platform string
	Contact  string
	Keys     *Keys
}
