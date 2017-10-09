// Package debug contains debugging helpers.
package debug

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
)

func DumpBytes(name string, data []byte) {
	fmt.Print(hex.Dump(data))
	ioutil.WriteFile(name, data, 0640)
}
