package torconfig

import (
	"fmt"
	"net"
)

func ExampleConfig_ORAddr() {
	c := Config{
		ORBindIP: net.IPv4(13, 37, 0, 1),
		ORPort:   9001,
	}
	addr := c.ORBindAddr()
	fmt.Println(addr)
	// Output:
	// 13.37.0.1:9001
}
