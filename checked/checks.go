package checked

import (
	"io"

	"github.com/mmcloughlin/pearl/log"
)

func MustClose(c io.Closer) {
	if err := c.Close(); err != nil {
		panic(err)
	}
}

func Close(logger log.Logger, c io.Closer) {
	if err := c.Close(); err != nil {
		log.Err(logger, err, "close failed")
	}
}
