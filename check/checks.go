// Package check provides error checking helpers.
package check

import (
	"io"

	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

// EOF checks if err was caused by io.EOF.
func EOF(err error) bool {
	return errors.Cause(err) == io.EOF
}

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
