package torconfig

import "fmt"

func ExampleConfig_ORAddr() {
	c := Config{
		Host:   "example.com",
		ORPort: 9001,
	}
	addr := c.ORAddr()
	fmt.Println(addr)
	// Output:
	// example.com:9001
}
