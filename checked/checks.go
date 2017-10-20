// Package checked provides utility functions for checking error returns.
package checked

import (
	"io"

	"github.com/mmcloughlin/pearl/log"
)

// MustClose closes c and panics on error.
func MustClose(c io.Closer) {
	if err := c.Close(); err != nil {
		panic(err)
	}
}

// Close closes c and logs an error, if it occurs.
func Close(logger log.Logger, c io.Closer) {
	if err := c.Close(); err != nil {
		log.Err(logger, err, "close failed")
	}
}
