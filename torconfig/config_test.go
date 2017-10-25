package torconfig

import (
	"fmt"
	"net"
)

func ExampleConfig_ORAddr() {
	c := Config{
		IP:     net.IPv4(13, 37, 0, 1),
		ORPort: 9001,
	}
	addr := c.ORAddr()
	fmt.Println(addr)
	// Output:
	// 13.37.0.1:9001
}
